//! Mailbox identity helpers: normalize, validate, hash.

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::errors::{ErrorCodes, PubkeyError};

const MAX_EMAIL_OCTETS: usize = 254;
const MAX_LOCAL_OCTETS: usize = 64;
const MAX_DOMAIN_OCTETS: usize = 255;
const MAX_LABEL_OCTETS: usize = 63;

static LOCAL_CHARS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[\p{L}\p{N}\p{M}!#$%&'*+/=?^_`{|}~.-]+$").expect("local regex")
});
static DOMAIN_LABEL_CHARS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[\p{L}\p{N}\p{M}-]+$").expect("domain regex"));
static DISALLOWED_IN_ADDRESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\s\p{Cc}\p{Cf}]").expect("disallowed regex"));
static DIGITS_ONLY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d+$").expect("digits regex"));
static HAS_LETTER: Lazy<Regex> = Lazy::new(|| Regex::new(r"\p{L}").expect("letter regex"));

fn nfc(value: &str) -> String {
    value.nfc().collect()
}

fn fold_utf8(value: &str) -> String {
    nfc(&value.to_lowercase())
}

fn utf8_byte_length(value: &str) -> usize {
    value.len()
}

/// Lowercase hex of bytes.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode hex (whitespace ignored).
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    hex::decode(&clean).map_err(|e| e.to_string())
}

/// Public mailbox canonicalization. Must match pubkey `emailTid` / Dart `normalizeEmail`.
///
/// `+` in the local part is identity-significant.
pub fn normalize_email(email: Option<&str>) -> String {
    let Some(email) = email else {
        return String::new();
    };
    let trimmed = nfc(email.trim());
    let Some(at) = trimmed.rfind('@') else {
        return fold_utf8(&trimmed);
    };
    if at == 0 || at == trimmed.len() - 1 {
        return fold_utf8(&trimmed);
    }
    let local = fold_utf8(&trimmed[..at]);
    let domain = fold_utf8(&trimmed[at + 1..]);
    format!("{local}@{domain}")
}

fn is_valid_local_part(local: &str) -> bool {
    if local.is_empty() || local.starts_with('.') || local.ends_with('.') || local.contains("..")
    {
        return false;
    }
    LOCAL_CHARS.is_match(local)
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.starts_with('[')
        || domain.ends_with(']')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty()
            || utf8_byte_length(label) > MAX_LABEL_OCTETS
            || label.starts_with('-')
            || label.ends_with('-')
            || !DOMAIN_LABEL_CHARS.is_match(label)
        {
            return false;
        }
    }
    let tld = labels.last().unwrap();
    if tld.len() < 2 || DIGITS_ONLY.is_match(tld) || !HAS_LETTER.is_match(tld) {
        return false;
    }
    true
}

/// Validate a (preferably already-canonical) email.
pub fn is_valid_email(email: Option<&str>) -> bool {
    let Some(email) = email else {
        return false;
    };
    if email.is_empty() {
        return false;
    }
    if DISALLOWED_IN_ADDRESS.is_match(email) || email.contains('\0') {
        return false;
    }
    let Some(at) = email.find('@') else {
        return false;
    };
    if at == 0 || at != email.rfind('@').unwrap_or(usize::MAX) || at == email.len() - 1 {
        return false;
    }
    let local = &email[..at];
    let domain = &email[at + 1..];
    if utf8_byte_length(email) > MAX_EMAIL_OCTETS
        || utf8_byte_length(local) > MAX_LOCAL_OCTETS
        || utf8_byte_length(domain) > MAX_DOMAIN_OCTETS
    {
        return false;
    }
    is_valid_local_part(local) && is_valid_domain(domain)
}

/// Require email already in canonical form and valid.
pub fn require_canonical_email(email: Option<&str>) -> Result<String, PubkeyError> {
    let Some(email) = email.filter(|e| !e.is_empty()) else {
        return Err(PubkeyError::new(
            ErrorCodes::INVALID_EMAIL,
            "Valid email is required",
        ));
    };
    let canonical = normalize_email(Some(email));
    if email != canonical {
        return Err(PubkeyError::new(
            ErrorCodes::EMAIL_NOT_CANONICAL,
            "Email must be sent in canonical form",
        ));
    }
    if !is_valid_email(Some(&canonical)) {
        return Err(PubkeyError::new(
            ErrorCodes::INVALID_EMAIL,
            "Valid email is required",
        ));
    }
    Ok(canonical)
}

/// Unsalted SHA-256 of the canonical mailbox, lowercase hex.
pub fn email_sha256_hex(email: &str) -> Result<String, PubkeyError> {
    let canonical = require_canonical_email(Some(&normalize_email(Some(email))))?;
    Ok(bytes_to_hex(&sha256_bytes(canonical.as_bytes())))
}

/// SHA-256 digest of string or bytes.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// UUID v8 from the last 16 bytes of a SHA-256 digest (RFC 9562 version + variant).
pub fn sha256_to_uuid_v8(sha256: &[u8]) -> Result<String, String> {
    if sha256.len() != 32 {
        return Err("sha256 must be a 32-byte SHA-256 digest".into());
    }
    let mut bytes = sha256[16..32].to_vec();
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes_to_hex(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// UUID v8 from SHA-256 of UTF-8 text.
pub fn text_to_uuid_v8(value: &str) -> Result<String, String> {
    sha256_to_uuid_v8(&sha256_bytes(value.as_bytes()))
}

/// Last 16 bits of a UUID hex (without dashes).
pub fn uuid_last_16_bits(uuid: &str) -> Result<u16, String> {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    if hex.len() < 32 {
        return Err("uuid too short".into());
    }
    u16::from_str_radix(&hex[28..32], 16).map_err(|e| e.to_string())
}
