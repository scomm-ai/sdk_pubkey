//! Parsed Discovery Document and related envelopes.

use serde_json::{json, Map, Value};

use crate::constants::{families, purposes};
use crate::select::{select_best_artifact, Artifact, SelectPreferences};

/// Parsed Discovery Document (core schema 1.0).
#[derive(Debug, Clone)]
pub struct DiscoveryDocument {
    /// Schema version string.
    pub schema_version: String,
    /// Unsalted mailbox SHA-256 hex.
    pub mailbox_sha256: String,
    /// Optional `$schema` URI.
    pub schema: Option<String>,
    /// Capabilities object.
    pub capabilities: Map<String, Value>,
    /// Extensions object.
    pub extensions: Map<String, Value>,
    /// Full JSON map as returned by the server.
    pub raw: Map<String, Value>,
}

impl DiscoveryDocument {
    /// Parse from a JSON object.
    pub fn from_json(json: &Value) -> Self {
        let obj = json.as_object().cloned().unwrap_or_default();
        let caps = obj
            .get("capabilities")
            .and_then(|c| c.as_object())
            .cloned()
            .unwrap_or_default();
        let ext = obj
            .get("extensions")
            .and_then(|e| e.as_object())
            .cloned()
            .unwrap_or_default();
        Self {
            schema_version: obj
                .get("schemaVersion")
                .map(|v| value_to_string(v))
                .unwrap_or_default(),
            mailbox_sha256: obj
                .get("mailboxSha256")
                .map(|v| value_to_string(v))
                .unwrap_or_default(),
            schema: obj.get("$schema").map(value_to_string),
            capabilities: caps,
            extensions: ext,
            raw: obj,
        }
    }

    /// `capabilities.crypto` object.
    pub fn crypto(&self) -> Option<&Map<String, Value>> {
        self.capabilities
            .get("crypto")
            .and_then(|c| c.as_object())
    }

    /// Encryption keys from the document.
    pub fn encryption_keys(&self) -> Vec<Map<String, Value>> {
        let Some(crypto) = self.crypto() else {
            return vec![];
        };
        let Some(enc) = crypto.get("encryption").and_then(|e| e.as_object()) else {
            return vec![];
        };
        let Some(keys) = enc.get("keys").and_then(|k| k.as_array()) else {
            return vec![];
        };
        keys.iter()
            .filter_map(|k| k.as_object().cloned())
            .collect()
    }

    /// Project encryption keys into artifacts for [`select_best_artifact`].
    pub fn encryption_artifacts_for_selection(&self) -> Vec<Value> {
        let mut out = Vec::new();
        let mut index = 0i64;
        for key in self.encryption_keys() {
            let family_raw = key
                .get("family")
                .map(value_to_string)
                .unwrap_or_default();
            let family = if family_raw == "openpgp" {
                families::PGP.to_string()
            } else {
                family_raw
            };
            if family != families::PGP && family != families::SMIME {
                continue;
            }
            let algorithm = key
                .get("algorithms")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .map(value_to_string);
            let Some(algorithm) = algorithm.filter(|a| !a.is_empty()) else {
                continue;
            };
            let Some(material) = key.get("publicKey").map(value_to_string).filter(|m| !m.is_empty())
            else {
                continue;
            };
            let mut artifact = Map::new();
            artifact.insert("family".into(), json!(family));
            artifact.insert("algorithm".into(), json!(algorithm));
            artifact.insert("purpose".into(), json!(purposes::ENCRYPTION));
            artifact.insert("status".into(), json!("active"));
            artifact.insert("key_id".into(), json!(index));
            index += 1;
            if let Some(kid) = key.get("keyId") {
                artifact.insert("published_key_id".into(), kid.clone());
            }
            artifact.insert("public_material".into(), json!(material));
            out.push(Value::Object(artifact));
        }
        out
    }

    /// Pick one encryption key mutually supported by `capabilities`.
    pub fn select_best_encryption_key(
        &self,
        capabilities: &Value,
        preferences: Option<&SelectPreferences>,
    ) -> Option<Artifact> {
        select_best_artifact(
            &self.encryption_artifacts_for_selection(),
            Some(capabilities),
            preferences,
            Some(purposes::ENCRYPTION),
        )
    }

    /// Verification keys from the document.
    pub fn verification_keys(&self) -> Vec<Map<String, Value>> {
        let Some(crypto) = self.crypto() else {
            return vec![];
        };
        let Some(ver) = crypto.get("verification").and_then(|e| e.as_object()) else {
            return vec![];
        };
        let Some(keys) = ver.get("keys").and_then(|k| k.as_array()) else {
            return vec![];
        };
        keys.iter()
            .filter_map(|k| k.as_object().cloned())
            .collect()
    }

    /// Preferred languages list.
    pub fn preferred_languages(&self) -> Vec<String> {
        let Some(prefs) = self.capabilities.get("preferences").and_then(|p| p.as_object()) else {
            return vec![];
        };
        let Some(languages) = prefs.get("languages").and_then(|l| l.as_array()) else {
            return vec![];
        };
        languages.iter().map(value_to_string).collect()
    }
}

/// Management resource envelope.
#[derive(Debug, Clone)]
pub struct DiscoveryResource {
    /// Resource id.
    pub id: String,
    /// Type URI.
    pub type_: String,
    /// Schema version.
    pub schema_version: String,
    /// Value object.
    pub value: Map<String, Value>,
    /// Visibility.
    pub visibility: Option<String>,
    /// Metadata.
    pub metadata: Map<String, Value>,
    /// Raw JSON.
    pub raw: Map<String, Value>,
}

impl DiscoveryResource {
    /// Parse from JSON.
    pub fn from_json(json: &Value) -> Self {
        let obj = json.as_object().cloned().unwrap_or_default();
        let value = obj
            .get("value")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let metadata = obj
            .get("metadata")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        Self {
            id: obj.get("id").map(value_to_string).unwrap_or_default(),
            type_: obj.get("type").map(value_to_string).unwrap_or_default(),
            schema_version: obj
                .get("schemaVersion")
                .map(value_to_string)
                .unwrap_or_default(),
            value,
            visibility: obj.get("visibility").map(value_to_string),
            metadata,
            raw: obj,
        }
    }
}

/// Challenge status returned by the generic challenge API.
#[derive(Debug, Clone)]
pub struct DiscoveryChallenge {
    /// Challenge id.
    pub id: String,
    /// Type URI.
    pub type_: String,
    /// Status.
    pub status: String,
    /// Purpose URI.
    pub purpose: Option<String>,
    /// Expiry timestamp string.
    pub expires_at: Option<String>,
    /// Attempts remaining.
    pub attempts_remaining: Option<i64>,
    /// Short-lived proof after success.
    pub proof: Option<String>,
    /// Raw JSON.
    pub raw: Map<String, Value>,
}

impl DiscoveryChallenge {
    /// Parse from JSON.
    pub fn from_json(json: &Value) -> Self {
        let obj = json.as_object().cloned().unwrap_or_default();
        let attempts = obj.get("attemptsRemaining").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        Self {
            id: obj.get("id").map(value_to_string).unwrap_or_default(),
            type_: obj.get("type").map(value_to_string).unwrap_or_default(),
            status: obj.get("status").map(value_to_string).unwrap_or_default(),
            purpose: obj.get("purpose").map(value_to_string),
            expires_at: obj.get("expiresAt").map(value_to_string),
            attempts_remaining: attempts,
            proof: obj.get("proof").map(value_to_string),
            raw: obj,
        }
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}
