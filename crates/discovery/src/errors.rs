//! Stable machine-readable pubkey protocol error codes.

use serde_json::Value;
use thiserror::Error;

/// Machine-readable error code constants (match Dart `ErrorCodes`).
pub struct ErrorCodes;

impl ErrorCodes {
    /// Invalid signature.
    pub const INVALID_SIGNATURE: &'static str = "invalid_signature";
    /// Unknown principal.
    pub const UNKNOWN_PRINCIPAL: &'static str = "unknown_principal";
    /// Master key not armed.
    pub const MASTER_KEY_NOT_ARMED: &'static str = "master_key_not_armed";
    /// Master key replacement requires OTP.
    pub const MASTER_KEY_REPLACEMENT_REQUIRES_OTP: &'static str =
        "master_key_replacement_requires_otp";
    /// Timestamp out of window.
    pub const TIMESTAMP_OUT_OF_WINDOW: &'static str = "timestamp_out_of_window";
    /// Nonce replayed.
    pub const NONCE_REPLAYED: &'static str = "nonce_replayed";
    /// Unsupported protocol version.
    pub const UNSUPPORTED_PROTOCOL_VERSION: &'static str = "unsupported_protocol_version";
    /// Unsupported algorithm.
    pub const UNSUPPORTED_ALGORITHM: &'static str = "unsupported_algorithm";
    /// Invalid public key.
    pub const INVALID_PUBLIC_KEY: &'static str = "invalid_public_key";
    /// Invalid proof of possession.
    pub const INVALID_PROOF_OF_POSSESSION: &'static str = "invalid_proof_of_possession";
    /// Key id conflict.
    pub const KEY_ID_CONFLICT: &'static str = "key_id_conflict";
    /// Capability mismatch.
    pub const CAPABILITY_MISMATCH: &'static str = "capability_mismatch";
    /// OTP invalid.
    pub const OTP_INVALID: &'static str = "otp_invalid";
    /// OTP expired.
    pub const OTP_EXPIRED: &'static str = "otp_expired";
    /// Principal mismatch.
    pub const PRINCIPAL_MISMATCH: &'static str = "principal_mismatch";
    /// Invalid request.
    pub const INVALID_REQUEST: &'static str = "invalid_request";
    /// Email not canonical.
    pub const EMAIL_NOT_CANONICAL: &'static str = "email_not_canonical";
    /// Invalid email.
    pub const INVALID_EMAIL: &'static str = "invalid_email";
    /// Vault conflict.
    pub const VAULT_CONFLICT: &'static str = "vault_conflict";
    /// Vault integrity.
    pub const VAULT_INTEGRITY: &'static str = "vault_integrity";
    /// Provider unavailable.
    pub const PROVIDER_UNAVAILABLE: &'static str = "provider_unavailable";
    /// Key not found.
    pub const KEY_NOT_FOUND: &'static str = "key_not_found";
    /// Replay rejection.
    pub const REPLAY_REJECTION: &'static str = "replay_rejection";
    /// Clock skew.
    pub const CLOCK_SKEW: &'static str = "clock_skew";
    /// Protocol version mismatch.
    pub const PROTOCOL_VERSION_MISMATCH: &'static str = "protocol_version_mismatch";
    /// Device not authorized.
    pub const DEVICE_NOT_AUTHORIZED: &'static str = "device_not_authorized";
    /// OTP not device enrollment.
    pub const OTP_NOT_DEVICE_ENROLLMENT: &'static str = "otp_not_device_enrollment";
    /// Unsupported structure version.
    pub const UNSUPPORTED_STRUCTURE_VERSION: &'static str = "unsupported_structure_version";
    /// Pubkey unreachable.
    pub const PUBKEY_UNREACHABLE: &'static str = "pubkey_unreachable";
    /// HTTPS could not be established.
    pub const HTTPS_COULD_NOT_BE_ESTABLISHED: &'static str = "https_could_not_be_established";
    /// Request timeout.
    pub const REQUEST_TIMEOUT: &'static str = "request_timeout";
    /// OTP grant invalid.
    pub const OTP_GRANT_INVALID: &'static str = "otp_grant_invalid";
    /// Single-call arm required.
    pub const SINGLE_CALL_ARM_REQUIRED: &'static str = "single_call_arm_required";
    /// Directory upgrade required.
    pub const DIRECTORY_UPGRADE_REQUIRED: &'static str = "directory_upgrade_required";
    /// ID token not supported.
    pub const ID_TOKEN_NOT_SUPPORTED: &'static str = "idtoken_not_supported";
    /// ID token challenge invalid.
    pub const ID_TOKEN_CHALLENGE_INVALID: &'static str = "idtoken_challenge_invalid";
    /// ID token invalid.
    pub const ID_TOKEN_INVALID: &'static str = "idtoken_invalid";
}

/// True for server codes that mean this exact signed envelope was already accepted.
pub fn is_pubkey_replay_rejection(code: &str) -> bool {
    code == ErrorCodes::NONCE_REPLAYED || code == ErrorCodes::REPLAY_REJECTION
}

/// Typed SDK / protocol failure with a machine-readable code.
#[derive(Debug, Error, Clone)]
#[error("PubkeyError({code}): {message}")]
pub struct PubkeyError {
    /// Machine-readable code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// HTTP status when from a response.
    pub status: Option<u16>,
    /// Optional server time from error details.
    pub server_time: Option<Value>,
}

impl PubkeyError {
    /// Construct a protocol error.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status: None,
            server_time: None,
        }
    }

    /// Construct with HTTP status.
    pub fn with_status(
        code: impl Into<String>,
        message: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status: Some(status),
            server_time: None,
        }
    }

    /// Whether this is a nonce replay rejection.
    pub fn is_replay_rejection(&self) -> bool {
        is_pubkey_replay_rejection(&self.code)
    }

    /// Parse a JSON error body from an HTTP response.
    pub fn from_response(status: u16, body: &Value) -> Self {
        if let Some(obj) = body.as_object() {
            if let Some(nested) = obj.get("error").and_then(|e| e.as_object()) {
                let code = nested
                    .get("code")
                    .and_then(|v| v.as_str())
                    .or_else(|| obj.get("code").and_then(|v| v.as_str()))
                    .unwrap_or("server_error");
                let message = nested
                    .get("message")
                    .and_then(|v| v.as_str())
                    .or_else(|| obj.get("message").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("Pubkey request failed ({status})"));
                let server_time = nested
                    .get("details")
                    .and_then(|d| d.get("server_time"))
                    .cloned()
                    .or_else(|| obj.get("server_time").cloned());
                return Self {
                    code: code.to_string(),
                    message,
                    status: Some(status),
                    server_time,
                };
            }
            let code = obj
                .get("error")
                .and_then(|v| v.as_str())
                .or_else(|| obj.get("code").and_then(|v| v.as_str()))
                .unwrap_or("server_error");
            let message = obj
                .get("message")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("Pubkey request failed ({status})"));
            return Self {
                code: code.to_string(),
                message,
                status: Some(status),
                server_time: obj.get("server_time").cloned(),
            };
        }
        Self {
            code: "server_error".into(),
            message: format!("Pubkey request failed ({status})"),
            status: Some(status),
            server_time: None,
        }
    }
}
