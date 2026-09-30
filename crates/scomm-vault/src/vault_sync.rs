//! Immutable CKVF generations on untrusted storage.
//!
//! The VEK stays inside the container. This module only moves ciphertext.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::errors::VaultClientError;

fn sync_err(code: &'static str, message: impl Into<String>) -> VaultClientError {
    VaultClientError::new(code, Some(message.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHead {
    pub vault_id: String,
    pub generation: u64,
    pub generation_hash: String,
}

pub trait VaultSyncStore {
    fn get_head(&self, vault_id: &str) -> Result<Option<VaultHead>, VaultClientError>;
    fn get_generation(&self, vault_id: &str, generation: u64) -> Result<Option<String>, VaultClientError>;
    fn put_if_absent(
        &self,
        vault_id: &str,
        generation: u64,
        container_json: &str,
    ) -> Result<(), VaultClientError>;
    fn compare_and_swap_head(
        &self,
        next: &VaultHead,
        expected_hash: Option<&str>,
    ) -> Result<bool, VaultClientError>;
}

pub struct FolderVaultSync {
    pub root: PathBuf,
}

impl FolderVaultSync {
    fn dir(&self, vault_id: &str) -> Result<PathBuf, VaultClientError> {
        if vault_id.is_empty()
            || !vault_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(sync_err("sync_path", "vault id"));
        }
        Ok(self.root.join(vault_id))
    }

    fn head_path(&self, vault_id: &str) -> Result<PathBuf, VaultClientError> {
        Ok(self.dir(vault_id)?.join("head.json"))
    }

    fn generation_path(&self, vault_id: &str, generation: u64) -> Result<PathBuf, VaultClientError> {
        Ok(self.dir(vault_id)?.join("g").join(format!("{generation}.json")))
    }
}

fn read_to_string(path: &Path) -> Result<Option<String>, VaultClientError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(sync_err("sync_io", err.to_string())),
    }
}

fn parse_head(raw: &str) -> Result<VaultHead, VaultClientError> {
    let json: Value = serde_json::from_str(raw)
        .map_err(|_| sync_err("sync_head", "head is not json"))?;
    if json.get("format").and_then(|v| v.as_str()) != Some("CKVF-HEAD") {
        return Err(sync_err("sync_head", "unrecognized head"));
    }
    Ok(VaultHead {
        vault_id: json
            .get("vault_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        generation: json.get("generation").and_then(|v| v.as_u64()).unwrap_or(0),
        generation_hash: json
            .get("generation_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

impl VaultSyncStore for FolderVaultSync {
    fn get_head(&self, vault_id: &str) -> Result<Option<VaultHead>, VaultClientError> {
        let Some(raw) = read_to_string(&self.head_path(vault_id)?)? else {
            return Ok(None);
        };
        Ok(Some(parse_head(&raw)?))
    }

    fn get_generation(
        &self,
        vault_id: &str,
        generation: u64,
    ) -> Result<Option<String>, VaultClientError> {
        read_to_string(&self.generation_path(vault_id, generation)?)
    }

    fn put_if_absent(
        &self,
        vault_id: &str,
        generation: u64,
        container_json: &str,
    ) -> Result<(), VaultClientError> {
        let path = self.generation_path(vault_id, generation)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| sync_err("sync_io", err.to_string()))?;
        }
        if path.exists() {
            let existing = fs::read_to_string(&path)
                .map_err(|err| sync_err("sync_io", err.to_string()))?;
            if existing != container_json {
                return Err(sync_err(
                    "sync_tamper",
                    format!("generation {generation} already has different bytes"),
                ));
            }
            return Ok(());
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, container_json)
            .map_err(|err| sync_err("sync_io", err.to_string()))?;
        fs::rename(&tmp, &path).map_err(|err| sync_err("sync_io", err.to_string()))?;
        Ok(())
    }

    fn compare_and_swap_head(
        &self,
        next: &VaultHead,
        expected_hash: Option<&str>,
    ) -> Result<bool, VaultClientError> {
        let path = self.head_path(&next.vault_id)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| sync_err("sync_io", err.to_string()))?;
        }
        let current = self.get_head(&next.vault_id)?;
        let current_hash = current.as_ref().map(|h| h.generation_hash.as_str());
        if current_hash != expected_hash {
            return Ok(false);
        }
        let body = json!({
            "format": "CKVF-HEAD",
            "version": "1",
            "vault_id": next.vault_id,
            "generation": next.generation,
            "generation_hash": next.generation_hash,
        });
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string(&body).unwrap())
            .map_err(|err| sync_err("sync_io", err.to_string()))?;
        fs::rename(&tmp, &path).map_err(|err| sync_err("sync_io", err.to_string()))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_cas_rejects_a_stale_expected_hash() {
        let root = std::env::temp_dir().join(format!(
            "ckvf-sync-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let sync = FolderVaultSync { root: root.clone() };
        let head = VaultHead {
            vault_id: "vault".into(),
            generation: 1,
            generation_hash: "h1".into(),
        };
        sync.put_if_absent("vault", 1, "gen1").unwrap();
        assert!(sync.compare_and_swap_head(&head, None).unwrap());
        let next = VaultHead {
            vault_id: "vault".into(),
            generation: 2,
            generation_hash: "h2".into(),
        };
        assert!(!sync.compare_and_swap_head(&next, Some("other")).unwrap());
        assert!(sync.compare_and_swap_head(&next, Some("h1")).unwrap());
        assert_eq!(sync.get_head("vault").unwrap().unwrap().generation, 2);
        let _ = fs::remove_dir_all(&root);
    }
}
