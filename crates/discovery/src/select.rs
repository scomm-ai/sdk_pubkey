//! Artifact selection ranking (Track A / Dart `selectBestArtifact`).

use serde_json::{Map, Value};

use crate::constants::families;

/// Client capability advertisement: `{ "families": { "pgp": [...], "smime": [...] } }`.
pub type Capabilities = Map<String, Value>;

/// Optional selection preferences.
#[derive(Debug, Clone, Default)]
pub struct SelectPreferences {
    /// Preferred wire family.
    pub preferred_family: Option<String>,
    /// Preferred algorithm within that family.
    pub preferred_algorithm: Option<String>,
}

/// Selected artifact map (family, algorithm, purpose, public_material, …).
pub type Artifact = Map<String, Value>;

fn is_pq_algorithm(algorithm: &str) -> bool {
    let n = algorithm.to_lowercase();
    n.contains("mlkem")
        || n.contains("mldsa")
        || n.contains("slhdsa")
        || n.contains("hqc")
        || n.starts_with("pqc-")
}

/// PQC algorithms rank higher.
pub fn algorithm_preference_rank(algorithm: &str) -> i32 {
    if is_pq_algorithm(algorithm) {
        1
    } else {
        0
    }
}

/// smime > pgp.
pub fn family_preference_rank(family: &str) -> i32 {
    if family == families::SMIME {
        1
    } else if family == families::PGP {
        0
    } else {
        -1
    }
}

fn as_int(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn is_wire_family(family: &str) -> bool {
    family == families::PGP || family == families::SMIME
}

/// Select the best mutually supported artifact.
pub fn select_best_artifact(
    artifacts: &[Value],
    capabilities: Option<&Value>,
    preferences: Option<&SelectPreferences>,
    purpose: Option<&str>,
) -> Option<Artifact> {
    let mut supported = std::collections::HashSet::new();
    if let Some(caps) = capabilities {
        if let Some(families_map) = caps.get("families").and_then(|f| f.as_object()) {
            for (family, algos) in families_map {
                if !is_wire_family(family) {
                    continue;
                }
                if let Some(list) = algos.as_array() {
                    for algo in list {
                        if let Some(a) = algo.as_str() {
                            supported.insert(format!("{family}:{a}"));
                        }
                    }
                }
            }
        }
    }

    let mut candidates: Vec<Artifact> = Vec::new();
    for raw in artifacts {
        let Some(obj) = raw.as_object() else {
            continue;
        };
        if let Some(status) = obj.get("status").and_then(|s| s.as_str()) {
            if status != "active" {
                continue;
            }
        }
        if let Some(Value::String(pm)) = obj.get("public_material") {
            if pm.is_empty() {
                continue;
            }
        }
        let Some(family) = obj.get("family").and_then(|f| f.as_str()) else {
            continue;
        };
        if !is_wire_family(family) {
            continue;
        }
        if let (Some(want), Some(have)) = (purpose, obj.get("purpose").and_then(|p| p.as_str())) {
            if have != want {
                continue;
            }
        }
        let algo = obj
            .get("algorithm")
            .and_then(|a| a.as_str())
            .unwrap_or("");
        if supported.contains(&format!("{family}:{algo}")) {
            candidates.push(obj.clone());
        }
    }

    if candidates.is_empty() {
        return None;
    }

    if let Some(prefs) = preferences {
        if let Some(ref preferred_family) = prefs.preferred_family {
            if is_wire_family(preferred_family) {
                for artifact in &candidates {
                    let family = artifact.get("family").and_then(|f| f.as_str());
                    let algo = artifact.get("algorithm").and_then(|a| a.as_str());
                    if family == Some(preferred_family.as_str())
                        && (prefs.preferred_algorithm.is_none()
                            || prefs.preferred_algorithm.as_deref() == algo)
                    {
                        return Some(artifact.clone());
                    }
                }
            }
        }
    }

    candidates.sort_by(|a, b| {
        let pq = algorithm_preference_rank(b.get("algorithm").and_then(|v| v.as_str()).unwrap_or(""))
            .cmp(&algorithm_preference_rank(
                a.get("algorithm").and_then(|v| v.as_str()).unwrap_or(""),
            ));
        if pq != std::cmp::Ordering::Equal {
            return pq;
        }
        let family = family_preference_rank(b.get("family").and_then(|v| v.as_str()).unwrap_or(""))
            .cmp(&family_preference_rank(
                a.get("family").and_then(|v| v.as_str()).unwrap_or(""),
            ));
        if family != std::cmp::Ordering::Equal {
            return family;
        }
        as_int(b.get("key_id")).cmp(&as_int(a.get("key_id")))
    });
    candidates.into_iter().next()
}
