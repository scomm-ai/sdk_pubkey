//! Vault client errors (host codes and local codes).

use std::collections::HashMap;
use std::fmt;

use serde_json::Value;

/// Host error code (`unknown_vault`, `rate_limited`, …) or a client code:
/// `invalid_evaluation`, `network_error`, `bad_response`, `device_removed`, …
#[derive(Debug, Clone)]
pub struct VaultClientError {
    pub code: String,
    pub message: Option<String>,
    pub status: Option<u16>,
    /// Host `error.details` (for `generation_conflict`: the stored heads).
    pub details: Option<HashMap<String, Value>>,
}

impl VaultClientError {
    pub fn new(code: impl Into<String>, message: Option<String>) -> Self {
        Self::with_status(code, message, None, None)
    }

    pub fn with_status(
        code: impl Into<String>,
        message: Option<String>,
        status: Option<u16>,
        details: Option<HashMap<String, Value>>,
    ) -> Self {
        Self {
            code: code.into(),
            message,
            status,
            details,
        }
    }

    pub fn code_str(code: &'static str) -> Self {
        Self::new(code, None)
    }

    pub fn msg(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(code, Some(message.into()))
    }
}

impl fmt::Display for VaultClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultClientException({}", self.code)?;
        if let Some(s) = self.status {
            write!(f, " {s}")?;
        }
        if let Some(m) = &self.message {
            write!(f, ": {m}")?;
        }
        write!(f, ")")
    }
}

impl std::error::Error for VaultClientError {}

impl From<scomm_vault::CkvfError> for VaultClientError {
    fn from(e: scomm_vault::CkvfError) -> Self {
        match e {
            scomm_vault::CkvfError::Code { code } => Self::new(code, None),
            scomm_vault::CkvfError::WithMessage { code, message } => Self::new(code, Some(message)),
        }
    }
}
