//! RFC 8785 JSON Canonicalization Scheme for protocol payloads.

use serde_json::Value;

/// Canonicalize a JSON value with RFC 8785 JCS.
pub fn canonicalize_json(value: &Value) -> Result<String, String> {
    serde_json_canonicalizer::to_string(value).map_err(|e| e.to_string())
}
