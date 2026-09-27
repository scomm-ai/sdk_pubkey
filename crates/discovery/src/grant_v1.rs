//! `Scomm/grant/v1` token claim parsing (clients never verify the signature).

use once_cell::sync::Lazy;
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::canonical::decode_base64url;

/// Grant header line.
pub const GRANT_V1_HEADER: &str = "Scomm/grant/v1";

/// Ordered claim field names.
pub const GRANT_V1_FIELDS: &[&str] = &[
    "iss",
    "aud",
    "kid",
    "purpose",
    "identity_id",
    "msk_fingerprint",
    "amr",
    "idp",
    "exp",
    "jti",
];

static HEX64: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("hex64"));
static JTI: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{22}$").expect("jti"));

/// Claims of a `Scomm/grant/v1` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantV1Claims {
    /// Issuer.
    pub iss: String,
    /// Audience origins.
    pub aud: Vec<String>,
    /// Key id.
    pub kid: String,
    /// Purpose.
    pub purpose: String,
    /// Identity id (64 hex).
    pub identity_id: String,
    /// Lowercase hex SHA-256 of the MSK public key, or empty.
    pub msk_fingerprint: String,
    /// `otp` or `id_token`.
    pub amr: String,
    /// `google`, `microsoft`, or empty.
    pub idp: String,
    /// Expiry as Unix milliseconds (UTC).
    pub exp_ms: i64,
    /// JWT id.
    pub jti: String,
}

impl GrantV1Claims {
    /// Whether the grant is expired at `now_ms` (defaults to current UTC ms).
    pub fn is_expired(&self, now_ms: Option<i64>) -> bool {
        let now = now_ms.unwrap_or_else(unix_ms_now);
        !(now < self.exp_ms)
    }
}

fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Returns claims of a v1 token, or `None` when opaque / malformed.
pub fn parse_grant_v1(token: &str) -> Option<GrantV1Claims> {
    let dot = token.find('.')?;
    if dot == 0 {
        return None;
    }
    let text = match decode_base64url(&token[..dot]) {
        Ok(bytes) => String::from_utf8(bytes).ok()?,
        Err(_) => return None,
    };
    parse_grant_v1_text(&text)
}

/// Parses the signed text of a v1 grant.
pub fn parse_grant_v1_text(text: &str) -> Option<GrantV1Claims> {
    if !text.ends_with('\n') {
        return None;
    }
    let body = &text[..text.len() - 1];
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.first().copied() != Some(GRANT_V1_HEADER)
        || lines.len() != GRANT_V1_FIELDS.len() + 1
    {
        return None;
    }
    let mut claims = std::collections::HashMap::new();
    for (i, field) in GRANT_V1_FIELDS.iter().enumerate() {
        let prefix = format!("{field}=");
        let line = lines[i + 1];
        if !line.starts_with(&prefix) {
            return None;
        }
        claims.insert(*field, line[prefix.len()..].to_string());
    }
    let exp: i64 = claims.get("exp")?.parse().ok()?;
    let msk = claims.get("msk_fingerprint")?;
    let amr = claims.get("amr")?;
    let identity_id = claims.get("identity_id")?;
    let jti = claims.get("jti")?;
    let iss = claims.get("iss")?;
    let aud = claims.get("aud")?;
    let kid = claims.get("kid")?;
    let purpose = claims.get("purpose")?;
    let idp = claims.get("idp")?;

    if !HEX64.is_match(identity_id) {
        return None;
    }
    if !msk.is_empty() && !HEX64.is_match(msk) {
        return None;
    }
    if amr != "otp" && amr != "id_token" {
        return None;
    }
    if !JTI.is_match(jti) {
        return None;
    }
    if iss.is_empty() || aud.is_empty() || kid.is_empty() || purpose.is_empty() {
        return None;
    }

    Some(GrantV1Claims {
        iss: iss.clone(),
        aud: aud.split(' ').map(|s| s.to_string()).collect(),
        kid: kid.clone(),
        purpose: purpose.clone(),
        identity_id: identity_id.clone(),
        msk_fingerprint: msk.clone(),
        amr: amr.clone(),
        idp: idp.clone(),
        exp_ms: exp,
        jti: jti.clone(),
    })
}
