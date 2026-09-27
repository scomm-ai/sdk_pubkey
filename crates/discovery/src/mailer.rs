//! App-facing OTP / ID-token mailer client.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical::encode_base64url;
use crate::errors::{ErrorCodes, PubkeyError};
use crate::http::{join_url, pubkey_request, HttpClient};
use crate::identity::{email_sha256_hex, normalize_email, require_canonical_email};

/// Mailer OTP purposes.
pub struct MailerOtpPurpose;

impl MailerOtpPurpose {
    /// Directory enroll.
    pub const ENROLL: &'static str = "enroll";
    /// Replace MSK.
    pub const REPLACE_MSK: &'static str = "replace_msk";
    /// Vault open.
    pub const VAULT_OPEN: &'static str = "vault_open";
    /// Recovery envelope.
    pub const RECOVERY_ENVELOPE: &'static str = "recovery_envelope";
    /// Recovery generation.
    pub const RECOVERY_GENERATION: &'static str = "recovery_generation";
    /// Vault backup.
    pub const VAULT_BACKUP: &'static str = "vault_backup";
}

/// OIDC providers the mailer accepts.
pub struct MailerIdTokenProvider;

impl MailerIdTokenProvider {
    /// Google.
    pub const GOOGLE: &'static str = "google";
    /// Microsoft.
    pub const MICROSOFT: &'static str = "microsoft";
}

/// ID-token challenge returned by the mailer.
#[derive(Debug, Clone)]
pub struct MailerIdTokenChallenge {
    /// Challenge id.
    pub challenge_id: String,
    /// Nonce for the ID token.
    pub nonce: String,
    /// Seconds until expiry.
    pub expires_in: i64,
}

/// Per-provider ID-token config.
#[derive(Debug, Clone)]
pub struct MailerIdTokenProviderConfig {
    /// Supported purposes.
    pub purposes: Vec<String>,
}

/// Cached mailer ID-token configuration.
#[derive(Debug, Clone)]
pub struct MailerIdTokenConfig {
    /// Whether ID-token challenges are enabled.
    pub enabled: bool,
    /// Provider map.
    pub providers: HashMap<String, MailerIdTokenProviderConfig>,
    /// Challenge TTL seconds.
    pub challenge_ttl_seconds: i64,
}

impl MailerIdTokenConfig {
    /// Whether provider+purpose is supported.
    pub fn supports(&self, provider: &str, purpose: &str) -> bool {
        if !self.enabled {
            return false;
        }
        self.providers
            .get(provider)
            .map(|e| e.purposes.iter().any(|p| p == purpose))
            .unwrap_or(false)
    }
}

/// `base64url(sha256(raw MSK public key))` without padding.
pub fn mailer_msk_jkt(msk_public_key: &[u8]) -> String {
    let digest = Sha256::digest(msk_public_key);
    encode_base64url(&digest)
}

/// Same object the OTP and ID-token verify calls return.
#[derive(Debug, Clone)]
pub struct MailerOtpGrant {
    /// Present for vault-consumed purposes. Absent for directory enroll.
    pub identity_id: Option<String>,
    /// Opaque or v1 grant token.
    pub otp_grant: String,
    /// `replace_msk` only: signed vault grant.
    pub vault_grant: Option<String>,
}

impl MailerOtpGrant {
    /// Require a 64-hex identity_id.
    pub fn require_identity_id(&self) -> Result<&str, PubkeyError> {
        match &self.identity_id {
            Some(id) if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) => {
                Ok(id)
            }
            _ => Err(PubkeyError::new(
                ErrorCodes::OTP_GRANT_INVALID,
                "Mailer verify did not return identity_id",
            )),
        }
    }
}

const EMAIL_OTP_TYPE: &str = "https://discovery.scomm.ai/challenges/email-otp/v1";
const OIDC_TYPE: &str = "https://discovery.scomm.ai/challenges/oidc-id-token/v1";

fn purpose_uri(purpose: &str) -> Result<&'static str, PubkeyError> {
    match purpose {
        MailerOtpPurpose::ENROLL => {
            Ok("https://discovery.scomm.ai/operations/msk/enroll/v1")
        }
        MailerOtpPurpose::REPLACE_MSK => {
            Ok("https://discovery.scomm.ai/operations/msk/replace/v1")
        }
        MailerOtpPurpose::VAULT_OPEN => {
            Ok("https://discovery.scomm.ai/operations/vault/open/v1")
        }
        MailerOtpPurpose::VAULT_BACKUP => {
            Ok("https://discovery.scomm.ai/operations/vault/backup-fetch/v1")
        }
        MailerOtpPurpose::RECOVERY_ENVELOPE => {
            Ok("https://discovery.scomm.ai/operations/recovery/envelope-fetch/v1")
        }
        MailerOtpPurpose::RECOVERY_GENERATION => {
            Ok("https://discovery.scomm.ai/operations/recovery/generation/v1")
        }
        other => Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            format!("Unknown mailer purpose {other}"),
        )),
    }
}

fn is_vault_purpose(purpose: &str) -> bool {
    matches!(
        purpose,
        MailerOtpPurpose::VAULT_OPEN
            | MailerOtpPurpose::RECOVERY_ENVELOPE
            | MailerOtpPurpose::RECOVERY_GENERATION
            | MailerOtpPurpose::VAULT_BACKUP
    )
}

/// App-facing OTP mailer. Request bodies contain the canonical mailbox.
pub struct MailerClient {
    /// Mailer base URL.
    pub base_url: String,
    http: HttpClient,
    id_token_config: Option<MailerIdTokenConfig>,
    id_token_config_until: Option<Instant>,
    otp_challenge_ids: HashMap<String, String>,
    challenge_mailboxes: HashMap<String, String>,
}

impl MailerClient {
    /// Construct with a base URL.
    pub fn new(base_url: impl Into<String>) -> Result<Self, PubkeyError> {
        Ok(Self {
            base_url: base_url.into().trim().to_string(),
            http: HttpClient::new()?,
            id_token_config: None,
            id_token_config_until: None,
            otp_challenge_ids: HashMap::new(),
            challenge_mailboxes: HashMap::new(),
        })
    }

    /// Construct with a shared HTTP client.
    pub fn with_http(base_url: impl Into<String>, http: HttpClient) -> Self {
        Self {
            base_url: base_url.into().trim().to_string(),
            http,
            id_token_config: None,
            id_token_config_until: None,
            otp_challenge_ids: HashMap::new(),
            challenge_mailboxes: HashMap::new(),
        }
    }

    fn require_base_url(&self) -> Result<(), PubkeyError> {
        if self.base_url.is_empty() {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "PUBKEY_MAILER_BASE_URL is required and must not be empty",
            ));
        }
        Ok(())
    }

    fn require_arming_key(purpose: &str, msk_public_key: Option<&[u8]>) -> Result<(), PubkeyError> {
        let arming =
            purpose == MailerOtpPurpose::ENROLL || purpose == MailerOtpPurpose::REPLACE_MSK;
        if arming && msk_public_key.map(|k| k.len()) != Some(32) {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                format!("mskPublicKey is required for {purpose}"),
            ));
        }
        Ok(())
    }

    /// Request a mailbox OTP. Uniform success does not distinguish unknown vs enrolled.
    pub async fn request_otp(
        &mut self,
        email: &str,
        purpose: &str,
        msk_public_key: Option<&[u8]>,
    ) -> Result<(), PubkeyError> {
        self.require_base_url()?;
        let canonical = require_canonical_email(Some(&normalize_email(Some(email))))?;
        Self::require_arming_key(purpose, msk_public_key)?;
        let sha = email_sha256_hex(&canonical)?;
        let mut body = json!({
            "type": EMAIL_OTP_TYPE,
            "email": canonical,
            "purpose": purpose_uri(purpose)?,
        });
        if let Some(key) = msk_public_key {
            body.as_object_mut()
                .unwrap()
                .insert("msk_jkt".into(), json!(mailer_msk_jkt(key)));
        }
        let url = join_url(&self.base_url, &format!("/v1/mailboxes/{sha}/challenges"));
        let result = pubkey_request(&self.http, &url, "POST", Some(&body), false).await?;
        let id = result
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PubkeyError::new(
                    ErrorCodes::OTP_INVALID,
                    "Mailer challenge response did not return an id",
                )
            })?;
        self.otp_challenge_ids
            .insert(format!("{sha}:{purpose}"), id.to_string());
        Ok(())
    }

    /// Verify a mailbox OTP and return the grant.
    pub async fn verify_otp(
        &mut self,
        email: &str,
        otp: &str,
        purpose: &str,
    ) -> Result<MailerOtpGrant, PubkeyError> {
        self.require_base_url()?;
        let sha256 = email_sha256_hex(email)?;
        let challenge_id = self
            .otp_challenge_ids
            .get(&format!("{sha256}:{purpose}"))
            .cloned()
            .ok_or_else(|| {
                PubkeyError::new(ErrorCodes::OTP_INVALID, "Call requestOtp before verifyOtp")
            })?;
        let url = join_url(
            &self.base_url,
            &format!("/v1/mailboxes/{sha256}/challenges/{challenge_id}/responses"),
        );
        let body = json!({ "response": { "code": otp.trim() } });
        let result = pubkey_request(&self.http, &url, "POST", Some(&body), false).await?;
        Self::parse_grant(&result, is_vault_purpose(purpose))
    }

    /// Public, cacheable ID-token config.
    pub async fn fetch_id_token_config(&mut self) -> Result<MailerIdTokenConfig, PubkeyError> {
        self.require_base_url()?;
        if let (Some(cfg), Some(until)) = (&self.id_token_config, self.id_token_config_until) {
            if Instant::now() < until {
                return Ok(cfg.clone());
            }
        }
        let url = join_url(&self.base_url, "/v1/challenges/config");
        let response = self
            .http
            .inner()
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PubkeyError::from_response(0, &json!({ "message": e.to_string() })))?;
        let max_age = max_age_seconds(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
        );
        let status = response.status().as_u16();
        let data: Value = response.json().await.map_err(|e| {
            PubkeyError::new(ErrorCodes::INVALID_REQUEST, e.to_string())
        })?;
        if !(200..300).contains(&status) {
            return Err(PubkeyError::from_response(status, &data));
        }
        let Some(obj) = data.as_object() else {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "Mailer ID token config was not a JSON object",
            ));
        };
        let mut providers = HashMap::new();
        if let Some(raw) = obj.get("providers").and_then(|p| p.as_object()) {
            for (key, value) in raw {
                let Some(v) = value.as_object() else {
                    continue;
                };
                let purposes = v
                    .get("purposes")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|i| i.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                providers.insert(key.clone(), MailerIdTokenProviderConfig { purposes });
            }
        }
        let config = MailerIdTokenConfig {
            enabled: obj.get("enabled") == Some(&Value::Bool(true)),
            providers,
            challenge_ttl_seconds: obj
                .get("challenge_ttl_seconds")
                .and_then(|v| v.as_i64())
                .unwrap_or(300),
        };
        self.id_token_config = Some(config.clone());
        self.id_token_config_until = Some(Instant::now() + Duration::from_secs(max_age as u64));
        Ok(config)
    }

    /// Start an ID-token mailbox proof.
    pub async fn create_id_token_challenge(
        &mut self,
        email: &str,
        provider: &str,
        purpose: &str,
        msk_public_key: Option<&[u8]>,
    ) -> Result<MailerIdTokenChallenge, PubkeyError> {
        self.require_base_url()?;
        let canonical = require_canonical_email(Some(&normalize_email(Some(email))))?;
        Self::require_arming_key(purpose, msk_public_key)?;
        let sha = email_sha256_hex(&canonical)?;
        let mut body = json!({
            "type": OIDC_TYPE,
            "email": canonical,
            "provider": provider,
            "purpose": purpose_uri(purpose)?,
        });
        if let Some(key) = msk_public_key {
            body.as_object_mut()
                .unwrap()
                .insert("msk_jkt".into(), json!(mailer_msk_jkt(key)));
        }
        let url = join_url(&self.base_url, &format!("/v1/mailboxes/{sha}/challenges"));
        let result = pubkey_request(&self.http, &url, "POST", Some(&body), false).await?;
        let Some(obj) = result.as_object() else {
            return Err(PubkeyError::new(
                ErrorCodes::ID_TOKEN_CHALLENGE_INVALID,
                "Mailer challenge response was not a JSON object",
            ));
        };
        let challenge_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let nonce = obj.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
        let expires_in = obj
            .get("expiresAt")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono_like_expires_in(s));
        if challenge_id.is_empty() || nonce.is_empty() || expires_in.is_none() {
            return Err(PubkeyError::new(
                ErrorCodes::ID_TOKEN_CHALLENGE_INVALID,
                "Mailer challenge response is missing id, nonce, or expiresAt",
            ));
        }
        if obj.contains_key("email") || obj.contains_key("mailbox") {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "Mailer challenge must not return a mailbox address",
            ));
        }
        self.challenge_mailboxes
            .insert(challenge_id.to_string(), sha);
        Ok(MailerIdTokenChallenge {
            challenge_id: challenge_id.to_string(),
            nonce: nonce.to_string(),
            expires_in: expires_in.unwrap(),
        })
    }

    /// Verify an OIDC ID token and return the same grant shape as [`Self::verify_otp`].
    pub async fn verify_id_token(
        &mut self,
        challenge_id: &str,
        provider: &str,
        purpose: &str,
        id_token: &str,
        graph_access_token: Option<&str>,
    ) -> Result<MailerOtpGrant, PubkeyError> {
        self.require_base_url()?;
        if provider.is_empty() || purpose.is_empty() {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "provider and purpose are required",
            ));
        }
        let sha = self
            .challenge_mailboxes
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| {
                PubkeyError::new(
                    ErrorCodes::ID_TOKEN_INVALID,
                    "Call createIdTokenChallenge before verifyIdToken",
                )
            })?;
        let mut response = json!({ "id_token": id_token });
        if let Some(token) = graph_access_token.filter(|t| !t.is_empty()) {
            response
                .as_object_mut()
                .unwrap()
                .insert("graph_access_token".into(), json!(token));
        }
        let url = join_url(
            &self.base_url,
            &format!("/v1/mailboxes/{sha}/challenges/{challenge_id}/responses"),
        );
        let body = json!({ "response": response });
        let result = pubkey_request(&self.http, &url, "POST", Some(&body), false).await?;
        Self::parse_grant(&result, is_vault_purpose(purpose))
    }

    fn parse_grant(result: &Value, vault_purpose: bool) -> Result<MailerOtpGrant, PubkeyError> {
        let Some(obj) = result.as_object() else {
            return Err(PubkeyError::new(
                ErrorCodes::OTP_INVALID,
                "Mailer verify response was not a JSON object",
            ));
        };
        let otp_grant = obj
            .get("otp_grant")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                PubkeyError::new(
                    ErrorCodes::OTP_GRANT_INVALID,
                    "Mailer verify did not return otp_grant",
                )
            })?;
        let identity_id = obj.get("identity_id").and_then(|v| v.as_str());
        if let Some(id) = identity_id {
            if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(PubkeyError::new(
                    ErrorCodes::OTP_GRANT_INVALID,
                    "Mailer verify identity_id is not 64 hex characters",
                ));
            }
        }
        if vault_purpose && identity_id.is_none() {
            return Err(PubkeyError::new(
                ErrorCodes::OTP_GRANT_INVALID,
                "Mailer verify did not return identity_id and otp_grant",
            ));
        }
        if obj.contains_key("email") || obj.contains_key("mailbox") {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "Mailer verify must not return a mailbox address",
            ));
        }
        let vault_grant = obj
            .get("vault_grant")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        Ok(MailerOtpGrant {
            identity_id: identity_id.map(|s| s.to_string()),
            otp_grant: otp_grant.to_string(),
            vault_grant,
        })
    }
}

fn max_age_seconds(cache_control: Option<&str>) -> i64 {
    let Some(cc) = cache_control else {
        return 300;
    };
    for part in cc.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("max-age=") {
            if let Ok(n) = rest.parse::<i64>() {
                return n;
            }
        }
    }
    300
}

fn chrono_like_expires_in(expires_at: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let then = OffsetDateTime::parse(expires_at, &Rfc3339).ok()?;
    let now = OffsetDateTime::now_utc();
    Some((then - now).whole_seconds())
}
