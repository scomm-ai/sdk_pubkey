//! Wire assertions: pubkey/discovery must never carry a mailbox address.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use crate::errors::{ErrorCodes, PubkeyError};

static HEX64: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("hex64"));

/// Cached OPRF identity and random vault locator. Never includes a mailbox.
#[derive(Debug, Clone, Default)]
pub struct IdentityBinding {
    /// 64-hex identity id.
    pub identity_id: Option<String>,
    /// 64-hex vault locator.
    pub vault_id: Option<String>,
}

impl IdentityBinding {
    /// Whether identity_id is present and length 64.
    pub fn has_identity(&self) -> bool {
        self.identity_id
            .as_ref()
            .map(|id| id.len() == 64)
            .unwrap_or(false)
    }
}

/// Reject URLs/bodies that embed a mailbox address.
pub fn assert_no_mailbox_address(url: &str, body: Option<&Value>) -> Result<(), PubkeyError> {
    if url.contains('@') {
        return Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "Pubkey URL must not contain a mailbox address",
        ));
    }
    let Some(Value::Object(map)) = body else {
        return Ok(());
    };
    for key in ["email", "address", "mailbox", "rfc5322"] {
        if map.contains_key(key) {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                format!("Pubkey request must not include {key}"),
            ));
        }
    }
    Ok(())
}

/// Discovery may carry `sha256`. It must not carry an address.
pub fn assert_discovery_wire(url: &str, body: Option<&Value>) -> Result<(), PubkeyError> {
    assert_no_mailbox_address(url, body)
}

/// Vault/MSK/pairing must not carry an address or a directory hash.
pub fn assert_vault_wire(url: &str, body: Option<&Value>) -> Result<(), PubkeyError> {
    assert_no_mailbox_address(url, body)?;
    let Some(Value::Object(map)) = body else {
        return Ok(());
    };
    for key in ["sha256", "email_sha256", "mailboxSha256"] {
        if map.contains_key(key) {
            return Err(PubkeyError::new(
                ErrorCodes::INVALID_REQUEST,
                format!("Vault request must not include {key}"),
            ));
        }
    }
    Ok(())
}

/// Deprecated alias for [`assert_no_mailbox_address`].
pub fn assert_pubkey_wire_has_no_mailbox(
    url: &str,
    body: Option<&Value>,
) -> Result<(), PubkeyError> {
    assert_no_mailbox_address(url, body)
}

/// Require 64 lowercase hex identity_id.
pub fn require_identity_id(identity_id: &str) -> Result<(), PubkeyError> {
    if !HEX64.is_match(identity_id) {
        return Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "identity_id must be 64 lowercase hex characters",
        ));
    }
    Ok(())
}

/// Require 64 lowercase hex mailboxSha256.
pub fn require_mailbox_sha256(sha256: &str) -> Result<(), PubkeyError> {
    if !HEX64.is_match(sha256) {
        return Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "mailboxSha256 must be 64 lowercase hex characters",
        ));
    }
    Ok(())
}
