//! Authorization headers and `Scomm/grant/v1` claim parsing.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// `Authorization` header for vault reads and pepper evaluation
/// (ckvf `profiles/vault-host.md` §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAuthorization {
    header: String,
}

impl VaultAuthorization {
    fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
        }
    }

    /// Signed `Scomm/grant/v1` vault grant. Single use.
    pub fn otp_grant(grant: impl AsRef<str>) -> Self {
        Self::new(format!("OtpGrant {}", grant.as_ref()))
    }

    /// Token from a pairing session. Single use.
    pub fn pairing_read(token: impl AsRef<str>) -> Self {
        Self::new(format!("PairingRead {}", token.as_ref()))
    }

    /// `oprf_token` returned with a grant-authorized read.
    pub fn oprf_token(token: impl AsRef<str>) -> Self {
        Self::new(format!("OprfToken {}", token.as_ref()))
    }

    /// Base64url JSON envelope signed by an enrolled device key.
    pub fn device(envelope_b64: impl AsRef<str>) -> Self {
        Self::new(format!("Device {}", envelope_b64.as_ref()))
    }

    pub fn header(&self) -> &str {
        &self.header
    }
}

/// Claims of a `Scomm/grant/v1` token. Clients read them to route a grant
/// and show expiry; the consuming host verifies the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantV1Claims {
    pub iss: String,
    pub aud: Vec<String>,
    pub purpose: String,
    pub identity_id: String,
    pub msk_fingerprint: String,
    /// Unix epoch milliseconds (UTC).
    pub exp: i64,
    pub jti: String,
}

impl GrantV1Claims {
    pub fn is_expired(&self, now_ms: Option<i64>) -> bool {
        let now = now_ms.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0)
        });
        now >= self.exp
    }
}

const FIELDS: &[&str] = &[
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

/// `None` for opaque directory grants and malformed tokens.
pub fn parse_grant_v1(token: &str) -> Option<GrantV1Claims> {
    let dot = token.find('.')?;
    if dot == 0 {
        return None;
    }
    let payload = &token[..dot];
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok().or_else(|| {
        // Accept padded base64url the way Dart's normalize does.
        let mut s = payload.to_string();
        while s.len() % 4 != 0 {
            s.push('=');
        }
        base64::engine::general_purpose::URL_SAFE
            .decode(s)
            .ok()
    })?;
    let text = String::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.first()? != &"Scomm/grant/v1" || lines.len() != FIELDS.len() + 1 {
        return None;
    }
    let mut c: Vec<(String, String)> = Vec::with_capacity(FIELDS.len());
    for (i, field) in FIELDS.iter().enumerate() {
        let prefix = format!("{field}=");
        let line = lines.get(i + 1)?;
        if !line.starts_with(&prefix) {
            return None;
        }
        c.push((field.to_string(), line[prefix.len()..].to_string()));
    }
    let get = |k: &str| -> Option<&str> {
        c.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    };
    let exp: i64 = get("exp")?.parse().ok()?;
    let identity_id = get("identity_id")?.to_string();
    if identity_id.len() != 64 || !identity_id.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    // identity_id must be lowercase hex (Dart: /^[0-9a-f]{64}$/)
    if identity_id.chars().any(|ch| ch.is_ascii_uppercase()) {
        return None;
    }
    Some(GrantV1Claims {
        iss: get("iss")?.to_string(),
        aud: get("aud")?.split(' ').map(str::to_string).collect(),
        purpose: get("purpose")?.to_string(),
        identity_id,
        msk_fingerprint: get("msk_fingerprint")?.to_string(),
        exp,
        jti: get("jti")?.to_string(),
    })
}
