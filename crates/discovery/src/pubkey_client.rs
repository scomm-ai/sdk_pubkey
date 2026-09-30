//! Discovery directory client (Track A + Dart Track B discovery/MSK/mailer paths).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::canonical::{
    canonical_signed_bytes, encode_base64url, decode_base64url,
};
use crate::config::PubkeyConfig;
use crate::constants::{
    operations, purposes, ARTIFACT_POP_OPERATION, MSK_HYBRID, PROTOCOL_VERSION,
};
use crate::device::{
    device_authorization_payload, must_not_generate_msk, resolve_identity_ux_state,
};
use crate::document::{DiscoveryChallenge, DiscoveryDocument, DiscoveryResource};
use crate::errors::{ErrorCodes, PubkeyError};
use crate::http::{join_url, pubkey_request, HttpClient};
use crate::identity::{
    bytes_to_hex, email_sha256_hex, sha256_bytes, sha256_to_uuid_v8,
};
use crate::identity_wire::{
    assert_pubkey_wire_has_no_mailbox, require_identity_id, require_mailbox_sha256,
};
use crate::signer::{require_msk_public_key, MskSigner};
use crate::types::DiscoveryProtocolContract;

static HEX64: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("hex64"));

fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_nonce() -> Result<String, PubkeyError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| PubkeyError::new(ErrorCodes::PROVIDER_UNAVAILABLE, e.to_string()))?;
    Ok(encode_base64url(&bytes))
}

/// Track A discovery client: public document fetch.
#[derive(Clone)]
pub struct DiscoveryClient {
    /// Public Discovery read host.
    pub read_base_url: String,
    http: HttpClient,
}

fn arm_proof_payload(algorithm: &str, public_key: &[u8]) -> Value {
    if algorithm == MSK_HYBRID {
        json!({
            "algorithm": algorithm,
            "public_key": encode_base64url(public_key),
        })
    } else {
        json!({})
    }
}

impl DiscoveryClient {
    /// Construct; `read_base_url` is required (no silent production default).
    pub fn new(read_base_url: impl Into<String>) -> Result<Self, PubkeyError> {
        let base = PubkeyConfig::require_url("PUBKEY_READ_BASE_URL", Some(&read_base_url.into()))
            .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        Ok(Self {
            read_base_url: base.trim_end_matches('/').to_string(),
            http: HttpClient::new()?,
        })
    }

    /// Construct with a shared HTTP client.
    pub fn with_http(read_base_url: impl Into<String>, http: HttpClient) -> Result<Self, PubkeyError> {
        let base = PubkeyConfig::require_url("PUBKEY_READ_BASE_URL", Some(&read_base_url.into()))
            .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        Ok(Self {
            read_base_url: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// `GET /v1/mailboxes/{mailboxSha256}`.
    pub async fn discover_mailbox(&self, mailbox: &str) -> Result<DiscoveryDocument, PubkeyError> {
        let sha256 = discovery_locator(mailbox)?;
        require_mailbox_sha256(&sha256)?;
        let path = format!("/v1/mailboxes/{sha256}");
        let url = join_url(&self.read_base_url, &path);
        let data = pubkey_request(&self.http, &url, "GET", None, false).await?;
        if !data.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Discovery document response was not a JSON object",
            ));
        }
        Ok(DiscoveryDocument::from_json(&data))
    }
}

/// Headless discovery-directory client: key publishing, lookups, OTP challenges, MSK arming.
pub struct PubkeyClient {
    /// Read tier base URL.
    pub read_base_url: String,
    /// Write tier base URL.
    pub write_base_url: String,
    http: HttpClient,
    /// SDK name in signed envelopes.
    pub sdk_name: String,
    /// SDK version in signed envelopes.
    pub sdk_version: String,
    /// Default capability families for key selection (empty = none advertised).
    pub default_capabilities: Value,
}

/// Builder for [`PubkeyClient`].
pub struct PubkeyClientBuilder {
    read_base_url: Option<String>,
    write_base_url: Option<String>,
    http: Option<HttpClient>,
    sdk_name: String,
    sdk_version: String,
    default_capabilities: Value,
}

impl Default for PubkeyClientBuilder {
    fn default() -> Self {
        Self {
            read_base_url: None,
            write_base_url: None,
            http: None,
            sdk_name: "scomm-pubkey-rust".into(),
            sdk_version: "0.1.0".into(),
            default_capabilities: json!({ "families": {} }),
        }
    }
}

impl PubkeyClientBuilder {
    /// Start a builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read base URL.
    pub fn read_base_url(mut self, url: impl Into<String>) -> Self {
        self.read_base_url = Some(url.into());
        self
    }

    /// Write base URL.
    pub fn write_base_url(mut self, url: impl Into<String>) -> Self {
        self.write_base_url = Some(url.into());
        self
    }

    /// Shared HTTP client.
    pub fn http(mut self, http: HttpClient) -> Self {
        self.http = Some(http);
        self
    }

    /// Default capabilities for GET /v1/keys when not overridden.
    pub fn default_capabilities(mut self, caps: Value) -> Self {
        self.default_capabilities = caps;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<PubkeyClient, PubkeyError> {
        let read = PubkeyConfig::require_url(
            "PUBKEY_READ_BASE_URL",
            self.read_base_url.as_deref(),
        )
        .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        let write = PubkeyConfig::require_url(
            "PUBKEY_WRITE_BASE_URL",
            self.write_base_url.as_deref(),
        )
        .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        Ok(PubkeyClient {
            read_base_url: read,
            write_base_url: write,
            http: self.http.unwrap_or(HttpClient::new()?),
            sdk_name: self.sdk_name,
            sdk_version: self.sdk_version,
            default_capabilities: self.default_capabilities,
        })
    }
}

fn discovery_locator(mailbox_or_sha256: &str) -> Result<String, PubkeyError> {
    if HEX64.is_match(mailbox_or_sha256) {
        return Ok(mailbox_or_sha256.to_string());
    }
    email_sha256_hex(mailbox_or_sha256)
}

impl PubkeyClient {
    /// Encode mailbox or digest to path segment.
    pub fn encode_mailbox_sha256_path(&self, mailbox_or_sha256: &str) -> Result<String, PubkeyError> {
        let sha = discovery_locator(mailbox_or_sha256)?;
        require_mailbox_sha256(&sha)?;
        Ok(sha)
    }

    /// Alias for [`Self::encode_mailbox_sha256_path`].
    pub fn encode_identity_path(&self, identity_id: &str) -> Result<String, PubkeyError> {
        self.encode_mailbox_sha256_path(identity_id)
    }

    /// Public discovery document.
    pub async fn discover_mailbox(&self, mailbox: &str) -> Result<DiscoveryDocument, PubkeyError> {
        let sha256 = self.encode_mailbox_sha256_path(mailbox)?;
        let path = format!("/v1/mailboxes/{sha256}");
        let data = pubkey_request(
            &self.http,
            &join_url(&self.read_base_url, &path),
            "GET",
            None,
            false,
        )
        .await?;
        if !data.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Discovery document response was not a JSON object",
            ));
        }
        Ok(DiscoveryDocument::from_json(&data))
    }

    /// List resources for an identity (read host).
    pub async fn list_resources(
        &self,
        identity_id: &str,
    ) -> Result<Vec<DiscoveryResource>, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/resources",
            self.encode_mailbox_sha256_path(identity_id)?
        );
        let data = pubkey_request(
            &self.http,
            &join_url(&self.read_base_url, &path),
            "GET",
            None,
            false,
        )
        .await?;
        let Some(list) = data.get("resources").and_then(|r| r.as_array()) else {
            return Ok(vec![]);
        };
        Ok(list
            .iter()
            .filter(|item| item.is_object())
            .map(DiscoveryResource::from_json)
            .collect())
    }

    /// Create a managed resource (write host).
    pub async fn create_resource(
        &self,
        mailbox: &str,
        envelope: &Value,
    ) -> Result<Value, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/resources",
            self.encode_mailbox_sha256_path(mailbox)?
        );
        pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, &path),
            "POST",
            Some(envelope),
            true,
        )
        .await
    }

    /// Execute an MSK-signed operation on the generic operations endpoint.
    pub async fn execute_operation(
        &self,
        mailbox: &str,
        envelope: &Value,
    ) -> Result<Value, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/operations",
            self.encode_mailbox_sha256_path(mailbox)?
        );
        pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, &path),
            "POST",
            Some(envelope),
            true,
        )
        .await
    }

    /// Create an email-OTP (or other) challenge.
    pub async fn create_challenge(
        &self,
        mailbox: &str,
        type_: &str,
        purpose: &str,
        input: Option<&Value>,
    ) -> Result<DiscoveryChallenge, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/challenges",
            self.encode_mailbox_sha256_path(mailbox)?
        );
        let mut body = json!({
            "type": type_,
            "purpose": purpose,
            "schemaVersion": DiscoveryProtocolContract::SCHEMA_VERSION,
        });
        if let Some(input) = input {
            body.as_object_mut()
                .unwrap()
                .insert("input".into(), input.clone());
        }
        let data = pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, &path),
            "POST",
            Some(&body),
            false,
        )
        .await?;
        if !data.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Challenge create response was not a JSON object",
            ));
        }
        Ok(DiscoveryChallenge::from_json(&data))
    }

    /// Respond to a challenge.
    pub async fn respond_to_challenge(
        &self,
        mailbox: &str,
        challenge_id: &str,
        response: &Value,
    ) -> Result<DiscoveryChallenge, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/challenges/{}/responses",
            self.encode_mailbox_sha256_path(mailbox)?,
            urlencoding::encode(challenge_id)
        );
        let body = json!({ "response": response });
        let data = pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, &path),
            "POST",
            Some(&body),
            false,
        )
        .await?;
        if !data.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Challenge response was not a JSON object",
            ));
        }
        Ok(DiscoveryChallenge::from_json(&data))
    }

    /// Get challenge status.
    pub async fn get_challenge(
        &self,
        mailbox: &str,
        challenge_id: &str,
    ) -> Result<DiscoveryChallenge, PubkeyError> {
        let path = format!(
            "/v1/mailboxes/{}/challenges/{}",
            self.encode_mailbox_sha256_path(mailbox)?,
            urlencoding::encode(challenge_id)
        );
        let data = pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, &path),
            "GET",
            None,
            false,
        )
        .await?;
        if !data.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Challenge status response was not a JSON object",
            ));
        }
        Ok(DiscoveryChallenge::from_json(&data))
    }

    /// Compatibility: verify mailbox OTP via challenges API.
    pub async fn verify_otp(
        &self,
        email: &str,
        challenge_id: &str,
        otp: &str,
    ) -> Result<DiscoveryChallenge, PubkeyError> {
        self.respond_to_challenge(email, challenge_id, &json!({ "code": otp }))
            .await
    }

    /// Mailbox OTP is requested from the mailer, not the pubkey host.
    pub async fn send_otp(
        &self,
        _email: &str,
        _msk_public_key: &[u8],
    ) -> Result<Value, PubkeyError> {
        Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "Mailbox OTP is requested from the mailer, not the pubkey host",
        ))
    }

    /// OTP cannot recover a vault or enroll a device via this client.
    pub async fn request_vault_recover(&self, _email: &str) -> Result<Value, PubkeyError> {
        Err(PubkeyError::new(
            ErrorCodes::OTP_NOT_DEVICE_ENROLLMENT,
            "OTP cannot recover a vault or enroll a device",
        ))
    }

    /// Resolve identity UX state.
    pub fn identity_state(
        &self,
        principal_exists: bool,
        local_msk: bool,
        device_authorized: Option<bool>,
        enrollment_state: Option<&str>,
        recovery_state: Option<&str>,
        vault_syncing: bool,
        historical_keys_available: Option<bool>,
    ) -> &'static str {
        resolve_identity_ux_state(
            principal_exists,
            local_msk,
            device_authorized,
            enrollment_state,
            recovery_state,
            vault_syncing,
            historical_keys_available,
        )
    }

    /// Assert silent MSK generation is forbidden.
    pub fn assert_no_silent_msk(
        &self,
        principal_exists: bool,
        local_msk: bool,
        explicit_recovery: bool,
    ) -> Result<(), PubkeyError> {
        if must_not_generate_msk(principal_exists, local_msk, explicit_recovery) {
            return Err(PubkeyError::new(
                ErrorCodes::MASTER_KEY_REPLACEMENT_REQUIRES_OTP,
                "Existing identity requires device transfer or explicit recovery",
            ));
        }
        Ok(())
    }

    /// Signing keys are not served by Discovery.
    pub async fn get_signing_key(&self) -> Result<Value, PubkeyError> {
        Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "Signing keys are not served by Discovery",
        ))
    }

    /// Gated verify-key fetch.
    pub async fn get_verification_key(
        &self,
        email: Option<&str>,
        identity_id: Option<&str>,
        key_id: &str,
    ) -> Result<Value, PubkeyError> {
        let unsalted = if let Some(email) = email.filter(|e| !e.trim().is_empty()) {
            email_sha256_hex(email)?
        } else {
            identity_id.unwrap_or("").to_string()
        };
        self.get_best_key_for_identity(
            &unsalted,
            Some(purposes::VERIFY),
            Some(key_id),
            Some(json!({ "families": {} })),
        )
        .await
    }

    /// Directory lookup by email.
    pub async fn select_directory_key(
        &self,
        email: &str,
        purpose: Option<&str>,
        key_id: Option<&str>,
        capabilities: Option<Value>,
    ) -> Result<Value, PubkeyError> {
        self.get_best_key_for_identity(
            &email_sha256_hex(email)?,
            purpose,
            key_id,
            capabilities,
        )
        .await
    }

    /// `GET /v1/keys` for an identity (unsalted mailbox hash).
    pub async fn get_best_key(
        &self,
        email: Option<&str>,
        identity_id: Option<&str>,
        purpose: Option<&str>,
        key_id: Option<&str>,
        capabilities: Option<Value>,
    ) -> Result<Value, PubkeyError> {
        let sha256 = if let Some(id) = identity_id.filter(|s| !s.is_empty()) {
            id.to_string()
        } else {
            email_sha256_hex(email.unwrap_or(""))?
        };
        self.get_best_key_for_identity(&sha256, purpose, key_id, capabilities)
            .await
    }

    /// Directory key selection.
    pub async fn get_best_key_for_identity(
        &self,
        identity_id: &str,
        purpose: Option<&str>,
        key_id: Option<&str>,
        capabilities: Option<Value>,
    ) -> Result<Value, PubkeyError> {
        require_mailbox_sha256(identity_id)?;
        if purpose == Some(purposes::SIGNING) || purpose == Some("verification") {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "purpose must be verify",
            ));
        }
        let is_verify = purpose == Some(purposes::VERIFY);
        let has_key_id = key_id.map(|k| !k.trim().is_empty()).unwrap_or(false);
        if is_verify && !has_key_id {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "key_id is required to fetch a verify key",
            ));
        }
        let exact = has_key_id && is_verify;
        let resolved = if exact {
            capabilities.unwrap_or_else(|| json!({ "families": {} }))
        } else {
            capabilities.unwrap_or_else(|| self.default_capabilities.clone())
        };
        let mut params: Vec<(String, String)> = vec![("sha256".into(), identity_id.into())];
        if !exact || !resolved.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            params.push((
                "capabilities".into(),
                serde_json::to_string(&resolved).unwrap_or_else(|_| "{}".into()),
            ));
        }
        if let Some(p) = purpose.filter(|p| !p.is_empty()) {
            params.push(("purpose".into(), p.into()));
        }
        if let Some(kid) = key_id.map(|k| k.trim()).filter(|k| !k.is_empty()) {
            params.push(("key_id".into(), kid.into()));
        }
        let query: String = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    urlencoding::encode(k),
                    urlencoding::encode(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let url = join_url(&self.read_base_url, &format!("/v1/keys?{query}"));
        assert_pubkey_wire_has_no_mailbox(&url, None)?;
        pubkey_request(&self.http, &url, "GET", None, false).await
    }

    /// Sign and POST `/v1/mutate`.
    pub async fn mutate(
        &self,
        email: &str,
        operation: &str,
        payload: &Value,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        if email.trim().is_empty() {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_EMAIL,
                "A local mailbox label is required",
            ));
        }
        let principal = email_sha256_hex(email)?;
        let envelope = self.sign_operation(operation, &principal, payload, msk, None, None)?;
        pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, "/v1/mutate"),
            "POST",
            Some(&envelope),
            true,
        )
        .await
    }

    /// `set_keys` mutate.
    pub async fn set_keys(
        &self,
        email: &str,
        artifacts: &[Value],
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        self.mutate(
            email,
            operations::SET_KEYS,
            &json!({ "artifacts": artifacts }),
            msk,
        )
        .await
    }

    /// Revoke a key. [reason] defaults to `UNSPECIFIED` when empty.
    pub async fn revoke_key(
        &self,
        email: &str,
        key_id: i64,
        msk: &dyn MskSigner,
        reason: &str,
    ) -> Result<Value, PubkeyError> {
        let reason = if reason.is_empty() {
            "UNSPECIFIED"
        } else {
            reason
        };
        self.mutate(
            email,
            operations::REVOKE_KEY,
            &json!({ "key_id": key_id, "revocation_reason": reason }),
            msk,
        )
        .await
    }

    /// Withdraw directory public material. Lifecycle is unchanged.
    pub async fn withdraw_key(
        &self,
        email: &str,
        key_id: i64,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        self.mutate(
            email,
            operations::WITHDRAW_KEY,
            &json!({ "key_id": key_id }),
            msk,
        )
        .await
    }

    /// Retire a key.
    pub async fn retire_key(
        &self,
        email: &str,
        key_id: i64,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        self.mutate(
            email,
            operations::RETIRE_KEY,
            &json!({ "key_id": key_id }),
            msk,
        )
        .await
    }

    /// Update preferences.
    pub async fn update_preferences(
        &self,
        email: &str,
        preferences: &Value,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        self.mutate(email, operations::UPDATE_PREFERENCES, preferences, msk)
            .await
    }

    /// Deferred enroll check (no pending MSK on directory).
    pub async fn enroll_msk_for_identity(
        &self,
        email: Option<&str>,
        identity_id: Option<&str>,
        vault_id: Option<&str>,
        msk_public_key: &[u8],
    ) -> Result<Value, PubkeyError> {
        let directory = email.map(|e| !e.trim().is_empty()).unwrap_or(false);
        if !directory {
            require_identity_id(identity_id.unwrap_or(""))?;
            require_identity_id(vault_id.unwrap_or(""))?;
        }
        require_msk_public_key(Some(msk_public_key))?;
        Ok(json!({ "status": "deferred" }))
    }

    /// `POST /v1/msk/arm`.
    pub async fn verify_enroll_for_identity(
        &self,
        email: Option<&str>,
        identity_id: Option<&str>,
        vault_id: Option<&str>,
        otp_grant: &str,
        msk: &dyn MskSigner,
        device: Option<&Value>,
    ) -> Result<Value, PubkeyError> {
        let public_key = require_msk_public_key(Some(msk.public_key()))?;
        let directory_sha = if let Some(email) = email.filter(|e| !e.trim().is_empty()) {
            Some(email_sha256_hex(email)?)
        } else {
            None
        };
        if directory_sha.is_none() {
            require_identity_id(identity_id.unwrap_or(""))?;
            require_identity_id(vault_id.unwrap_or(""))?;
        }
        if otp_grant.trim().is_empty() {
            return Err(PubkeyError::new(
                ErrorCodes::OTP_GRANT_INVALID,
                "otp_grant is required",
            ));
        }
        let principal = directory_sha
            .clone()
            .unwrap_or_else(|| identity_id.unwrap().to_string());
        let arm_payload = arm_proof_payload(msk.algorithm(), &public_key);
        let proof = self.sign_operation(
            operations::ARM_MSK,
            &principal,
            &arm_payload,
            msk,
            None,
            Some(PROTOCOL_VERSION),
        )?;
        let mut first_device = None;
        if let Some(device) = device {
            if directory_sha.is_none() {
                first_device = Some(self.sign_device_authorization(
                    identity_id.unwrap(),
                    msk,
                    device,
                    Some(identity_id.unwrap()),
                    Some(PROTOCOL_VERSION),
                )?);
            }
        }
        let mut body = json!({
            "identity_id": directory_sha.clone().unwrap_or_else(|| identity_id.unwrap().to_string()),
            "otp_grant": otp_grant,
            "msk": {
                "algorithm": msk.algorithm(),
                "public_key": encode_base64url(&public_key),
            },
            "msk_proof": proof,
        });
        if directory_sha.is_none() {
            body.as_object_mut()
                .unwrap()
                .insert("vault_id".into(), json!(vault_id.unwrap()));
        }
        if let Some(fd) = first_device {
            body.as_object_mut()
                .unwrap()
                .insert("first_device".into(), fd);
        }
        self.post_arm(&join_url(&self.write_base_url, "/v1/msk/arm"), &body)
            .await
    }

    /// Deferred replace check.
    pub async fn replace_msk_for_identity(
        &self,
        identity_id: &str,
        msk_public_key: &[u8],
    ) -> Result<Value, PubkeyError> {
        require_identity_id(identity_id)?;
        require_msk_public_key(Some(msk_public_key))?;
        Ok(json!({ "status": "deferred" }))
    }

    /// `POST /v1/msk/replace/arm`.
    pub async fn verify_replace_for_identity(
        &self,
        identity_id: &str,
        otp_grant: &str,
        msk: &dyn MskSigner,
        device: Option<&Value>,
    ) -> Result<Value, PubkeyError> {
        require_identity_id(identity_id)?;
        let public_key = require_msk_public_key(Some(msk.public_key()))?;
        let arm_payload = arm_proof_payload(msk.algorithm(), &public_key);
        let proof = self.sign_operation(
            operations::ARM_REPLACEMENT_MSK,
            identity_id,
            &arm_payload,
            msk,
            None,
            Some(PROTOCOL_VERSION),
        )?;
        let recovery_device = if let Some(device) = device {
            Some(self.sign_device_authorization(
                identity_id,
                msk,
                device,
                Some(identity_id),
                Some(PROTOCOL_VERSION),
            )?)
        } else {
            None
        };
        let mut body = json!({
            "identity_id": identity_id,
            "otp_grant": otp_grant,
            "msk": {
                "algorithm": msk.algorithm(),
                "public_key": encode_base64url(&public_key),
            },
            "msk_proof": proof,
        });
        if let Some(rd) = recovery_device {
            body.as_object_mut()
                .unwrap()
                .insert("recovery_device".into(), rd);
        }
        self.post_arm(
            &join_url(&self.write_base_url, "/v1/msk/replace/arm"),
            &body,
        )
        .await
    }

    /// Upload signing artifact with proof-of-possession.
    pub async fn set_signing_key_with_proof(
        &self,
        email: &str,
        mut artifact: Map<String, Value>,
        msk: &dyn MskSigner,
        content_signer: Option<&dyn MskSigner>,
    ) -> Result<Value, PubkeyError> {
        let Some(content_signer) = content_signer else {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                "contentSigningKey or compositePopSigner is required",
            ));
        };
        if let Some(wp) = artifact.get("purpose").and_then(|p| p.as_str()) {
            if wp == purposes::SIGNING || wp == "signing" || wp == "verification" {
                artifact.insert("purpose".into(), json!(purposes::VERIFY));
            }
        }
        let principal = email_sha256_hex(email)?;
        let timestamp = unix_ms_now();
        let nonce = random_nonce()?;
        let material = decode_base64url(
            artifact
                .get("public_material")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        let pop_payload = json!({
            "algorithm": artifact.get("algorithm"),
            "family": artifact.get("family"),
            "purpose": artifact.get("purpose"),
            "public_material_sha256": bytes_to_hex(&sha256_bytes(&material)),
        });
        let pop_bytes = canonical_signed_bytes(
            PROTOCOL_VERSION,
            ARTIFACT_POP_OPERATION,
            &principal,
            timestamp,
            &nonce,
            &pop_payload,
        )
        .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        let sig = content_signer.sign(&pop_bytes)?;
        let self_signature = json!({
            "algorithm": artifact.get("algorithm"),
            "value": encode_base64url(&sig),
        });
        artifact.insert("self_signature".into(), self_signature);
        let payload = json!({ "artifacts": [Value::Object(artifact)] });
        let envelope = self.sign_operation_with(
            operations::SET_SIGNING_KEY,
            &principal,
            &payload,
            msk,
            timestamp,
            &nonce,
            PROTOCOL_VERSION,
        )?;
        pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, "/v1/keys/signing"),
            "POST",
            Some(&envelope),
            true,
        )
        .await
    }

    /// Request encryption key decrypt challenge.
    pub async fn request_encryption_key_challenge(
        &self,
        email: &str,
        family: &str,
        algorithm: &str,
        public_material: &str,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        let principal = email_sha256_hex(email)?;
        let envelope = self.sign_operation(
            operations::REQUEST_KEY_CHALLENGE,
            &principal,
            &json!({
                "family": family,
                "algorithm": algorithm,
                "public_material": public_material,
            }),
            msk,
            None,
            None,
        )?;
        let result = pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, "/v1/keys/encryption/challenge"),
            "POST",
            Some(&envelope),
            false,
        )
        .await?;
        if !result.is_object() {
            return Err(PubkeyError::new(
                ErrorCodes::PROVIDER_UNAVAILABLE,
                "Challenge response was not a JSON object",
            ));
        }
        Ok(result)
    }

    /// Upload encryption key with decrypt proof.
    pub async fn set_encryption_key_with_proof(
        &self,
        email: &str,
        artifact: &Value,
        decrypt_proof: &Value,
        msk: &dyn MskSigner,
    ) -> Result<Value, PubkeyError> {
        let principal = email_sha256_hex(email)?;
        let mut art = artifact.as_object().cloned().unwrap_or_default();
        art.insert("decrypt_proof".into(), decrypt_proof.clone());
        let envelope = self.sign_operation(
            operations::SET_ENCRYPTION_KEY,
            &principal,
            &json!({ "artifacts": [Value::Object(art)] }),
            msk,
            None,
            None,
        )?;
        pubkey_request(
            &self.http,
            &join_url(&self.write_base_url, "/v1/keys/encryption"),
            "POST",
            Some(&envelope),
            true,
        )
        .await
    }

    /// Build a signed operation envelope.
    pub fn sign_operation(
        &self,
        operation: &str,
        principal: &str,
        payload: &Value,
        msk: &dyn MskSigner,
        timestamp: Option<i64>,
        version: Option<i64>,
    ) -> Result<Value, PubkeyError> {
        let timestamp = timestamp.unwrap_or_else(unix_ms_now);
        let nonce = random_nonce()?;
        let version = version.unwrap_or(PROTOCOL_VERSION);
        self.sign_operation_with(operation, principal, payload, msk, timestamp, &nonce, version)
    }

    fn sign_operation_with(
        &self,
        operation: &str,
        principal: &str,
        payload: &Value,
        msk: &dyn MskSigner,
        timestamp: i64,
        nonce: &str,
        version: i64,
    ) -> Result<Value, PubkeyError> {
        let bytes = canonical_signed_bytes(
            version, operation, principal, timestamp, nonce, payload,
        )
        .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        let signature = msk.sign(&bytes)?;
        Ok(json!({
            "protocol_version": version,
            "sdk": { "name": self.sdk_name, "version": self.sdk_version },
            "principal": principal,
            "operation": operation,
            "timestamp": timestamp,
            "nonce": nonce,
            "payload": payload,
            "signature": {
                "algorithm": msk.algorithm(),
                "value": encode_base64url(&signature),
            },
        }))
    }

    fn sign_device_authorization(
        &self,
        email_or_principal: &str,
        msk: &dyn MskSigner,
        device: &Value,
        principal_override: Option<&str>,
        version: Option<i64>,
    ) -> Result<Value, PubkeyError> {
        let principal = if let Some(p) = principal_override {
            p.to_string()
        } else {
            email_sha256_hex(email_or_principal)?
        };
        let device_public_key = if let Some(s) = device.get("devicePublicKey").and_then(|v| v.as_str())
        {
            decode_base64url(s).map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?
        } else if let Some(arr) = device.get("publicKey").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        } else {
            vec![]
        };
        let device_id = sha256_to_uuid_v8(&sha256_bytes(&device_public_key))
            .map_err(|e| PubkeyError::new(ErrorCodes::INVALID_REQUEST, e))?;
        let payload = device_authorization_payload(
            &principal,
            &device_id,
            &encode_base64url(&device_public_key),
            unix_ms_now(),
            &random_nonce()?,
            device.get("name").and_then(|v| v.as_str()),
        )?;
        let mut envelope = self.sign_operation(
            operations::AUTHORIZE_DEVICE,
            &principal,
            &payload,
            msk,
            None,
            version,
        )?;
        if let Some(obj) = envelope.as_object_mut() {
            obj.insert("payload".into(), payload);
        }
        Ok(envelope)
    }

    async fn post_arm(&self, url: &str, body: &Value) -> Result<Value, PubkeyError> {
        assert_pubkey_wire_has_no_mailbox(url, Some(body))?;
        match pubkey_request(&self.http, url, "POST", Some(body), true).await {
            Ok(v) => Ok(v),
            Err(error)
                if error.status == Some(404) && error.code != ErrorCodes::UNKNOWN_PRINCIPAL =>
            {
                Err(PubkeyError::with_status(
                    ErrorCodes::DIRECTORY_UPGRADE_REQUIRED,
                    "The directory host does not support single-call MSK arming",
                    404,
                ))
            }
            Err(e) => Err(e),
        }
    }
}

/// Shared Arc helper for callers that want a cloneable client.
pub type SharedPubkeyClient = Arc<PubkeyClient>;
