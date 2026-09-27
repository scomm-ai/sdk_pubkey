//! Canonical bytes that an MSK Ed25519 signature covers.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::constants::PROTOCOL_NAME;
use crate::jcs::canonicalize_json;

/// Domain separator: `SComm/Pubkey/{version}/{operation}`.
pub fn domain_separator(version: i64, operation: &str) -> String {
    format!("{PROTOCOL_NAME}/{version}/{operation}")
}

/// SHA-256 hex of JCS(payload).
pub fn payload_sha256_hex(payload: &Value) -> Result<String, String> {
    let jcs = canonicalize_json(payload)?;
    let digest = Sha256::digest(jcs.as_bytes());
    Ok(hex::encode(digest))
}

/// Canonical UTF-8 string covered by an MSK signature.
pub fn canonical_signed_utf8(
    protocol_version: i64,
    operation: &str,
    principal: &str,
    timestamp: i64,
    nonce: &str,
    payload: &Value,
) -> Result<String, String> {
    let payload_hash = payload_sha256_hex(payload)?;
    Ok(format!(
        "{}\nprincipal={principal}\ntimestamp={timestamp}\nnonce={nonce}\npayload_sha256={payload_hash}\n",
        domain_separator(protocol_version, operation)
    ))
}

/// Canonical UTF-8 bytes covered by an MSK signature.
pub fn canonical_signed_bytes(
    protocol_version: i64,
    operation: &str,
    principal: &str,
    timestamp: i64,
    nonce: &str,
    payload: &Value,
) -> Result<Vec<u8>, String> {
    Ok(canonical_signed_utf8(
        protocol_version,
        operation,
        principal,
        timestamp,
        nonce,
        payload,
    )?
    .into_bytes())
}

/// Unpadded base64url encode.
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url (tolerates standard alphabet and padding).
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    let normalized: String = value
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            _ => c,
        })
        .filter(|c| *c != '=')
        .collect();
    URL_SAFE_NO_PAD
        .decode(&normalized)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|e| e.to_string())
}
