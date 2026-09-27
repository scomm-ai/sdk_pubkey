//! Compile-time / runtime pubkey host configuration.

/// Origin helpers. Empty config must not fall back to a live host.
pub struct PubkeyConfig;

impl PubkeyConfig {
    /// Returns `value` when it is a non-empty origin; otherwise errors.
    pub fn require_url(name: &str, value: Option<&str>) -> Result<String, String> {
        let resolved = value.unwrap_or("").trim();
        if resolved.is_empty() {
            return Err(format!("{name} is required and must not be empty"));
        }
        Ok(resolved.to_string())
    }
}
