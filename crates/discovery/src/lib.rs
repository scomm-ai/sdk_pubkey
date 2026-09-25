//! Discovery locator and key URLs.
//!
//! The mailbox key is SHA-256 of the canonical mailbox UTF-8, lowercase hex.
//! This crate does not evaluate an OPRF and does not take a salt.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `canonical_mailbox` UTF-8 bytes.
/// The caller passes the already-canonical address.
pub fn mailbox_sha256_hex(canonical_mailbox: &str) -> String {
    let digest = Sha256::digest(canonical_mailbox.as_bytes());
    hex::encode(digest)
}

/// `GET /v1/keys` query for an encryption key or a gated verify key.
pub fn keys_path(sha256_hex: &str, purpose: &str, key_id: Option<&str>) -> String {
    let mut path = format!("/v1/keys?sha256={sha256_hex}&purpose={purpose}");
    if let Some(key_id) = key_id {
        path.push_str("&key_id=");
        path.push_str(key_id);
    }
    path
}

/// `GET /v1/mailboxes/{sha256}`.
pub fn mailbox_path(sha256_hex: &str) -> String {
    format!("/v1/mailboxes/{sha256_hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_64_lowercase_hex() {
        let hex = mailbox_sha256_hex("alice@example.com");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(hex, mailbox_sha256_hex("alice@example.com"));
    }

    #[test]
    fn verify_url_carries_purpose_and_key_id() {
        let sha = "ab".repeat(32);
        assert_eq!(
            keys_path(&sha, "verify", Some("A1B2-C3D4")),
            format!("/v1/keys?sha256={sha}&purpose=verify&key_id=A1B2-C3D4")
        );
    }
}
