//! Device-local storage for a [`KeyVault`]. Values are strings; the device KEK
//! is secret and belongs in platform secure storage.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[async_trait]
pub trait LocalVaultStore: Send + Sync {
    async fn read(&self, key: &str) -> Result<Option<String>, crate::errors::VaultClientError>;

    /// A `None` value deletes `key`.
    async fn write(
        &self,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), crate::errors::VaultClientError>;
}

/// Keys a [`KeyVault`] reads and writes.
pub mod local_vault_keys {
    pub const CONTAINER: &str = "container";
    /// Base64url 32-byte KEK of this device's `device-wrap-a256gcm` slot.
    pub const DEVICE_KEK: &str = "device_kek";
    pub const DEVICE_SLOT_ID: &str = "device_slot_id";
    /// `generation_hash` of the container last confirmed stored on the host.
    pub const SYNCED_HASH: &str = "synced_hash";

    pub const ALL: &[&str] = &[CONTAINER, DEVICE_KEK, DEVICE_SLOT_ID, SYNCED_HASH];
}

#[derive(Clone, Default)]
pub struct MemoryLocalVaultStore {
    values: Arc<Mutex<HashMap<String, String>>>,
}

impl MemoryLocalVaultStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.values.lock().expect("lock").clone()
    }
}

#[async_trait]
impl LocalVaultStore for MemoryLocalVaultStore {
    async fn read(&self, key: &str) -> Result<Option<String>, crate::errors::VaultClientError> {
        Ok(self.values.lock().expect("lock").get(key).cloned())
    }

    async fn write(
        &self,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), crate::errors::VaultClientError> {
        let mut map = self.values.lock().expect("lock");
        match value {
            None => {
                map.remove(key);
            }
            Some(v) => {
                map.insert(key.to_string(), v.to_string());
            }
        }
        Ok(())
    }
}
