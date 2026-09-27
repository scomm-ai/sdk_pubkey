//! SComm content-addressable signing key-id helpers.

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

static DISPLAY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$").expect("key id"));

/// First 32 bits of `SHA-256(public_material)`, displayed as `XXXX-XXXX`.
pub struct ScommKeyId;

impl ScommKeyId {
    /// Derive from published public key material bytes.
    pub fn derive(public_material: &[u8]) -> String {
        let digest = Sha256::digest(public_material);
        Self::format(&digest[..4]).expect("4 octets")
    }

    /// Derive from UTF-8 text (e.g. armored key).
    pub fn derive_from_utf8(text: &str) -> String {
        Self::derive(text.as_bytes())
    }

    /// Format four octets as `XXXX-XXXX`.
    pub fn format(four_bytes: &[u8]) -> Result<String, String> {
        if four_bytes.len() != 4 {
            return Err("SComm key-id requires exactly 4 octets".into());
        }
        let hex = hex::encode_upper(four_bytes);
        Ok(format!("{}-{}", &hex[0..4], &hex[4..8]))
    }

    /// Strip separators; uppercase. Empty → empty.
    pub fn normalize(raw: Option<&str>) -> String {
        let Some(raw) = raw else {
            return String::new();
        };
        raw.trim()
            .to_uppercase()
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | ':' | '-' | '_'))
            .collect()
    }

    /// Compare after normalize.
    pub fn equals(a: Option<&str>, b: Option<&str>) -> bool {
        let na = Self::normalize(a);
        let nb = Self::normalize(b);
        !na.is_empty() && !nb.is_empty() && na == nb
    }

    /// Whether raw looks like `XXXX-XXXX`.
    pub fn looks_like_display(raw: Option<&str>) -> bool {
        raw.map(|s| DISPLAY_PATTERN.is_match(s.trim()))
            .unwrap_or(false)
    }
}
