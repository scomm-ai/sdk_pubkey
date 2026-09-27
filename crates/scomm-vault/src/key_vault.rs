//! Local-first CKVF vault opened with this device's slot.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use scomm_vault::{
    base64url_decode, base64url_encode, canonical_openpgp_public_key, commit_unlock_slots,
    create_vault, delete_private_key, ed25519_verify, generate_recovery_code, get_key,
    import_private_key, key_ids, merge_onto, open_vault as ckvf_open_vault,
    open_vault_with_device_kek, open_vault_with_pepper, random_bytes, rechain,
    remove_unlock_slot, retire_key, revoke_key, rfc3339, serialize_container, set_preferred_key,
    update_extensions, wrap_device_slot, wrap_pepper_slot, Argon2idParams, CreateVaultOptions,
    Extension, MergeConflict, PepperKey, PepperOprf, UnlockedVault, VaultPayload,
    PASSWORD_OPRF_METHOD, PEPPER_MIN_ARGON2ID, RECOMMENDED_ARGON2ID, RECOVERY_CODE_OPRF_METHOD,
};
use serde_json::{json, Map, Value};

use crate::authorization::VaultAuthorization;
use crate::errors::VaultClientError;
use crate::host_pepper_oprf::HostPepperOprf;
use crate::local_vault_store::{local_vault_keys, LocalVaultStore};
use crate::signing::{vault_operations, vault_records_signing_text, MskSigner};
use crate::vault_host_client::{VaultHostApi, VaultRecord};

/// App metadata for devices, by `slot_id` of their device slot.
pub const DEVICES_EXTENSION_ID: &str = "priv:scomm.devices";

/// App metadata for keys, by `absolute_key_id`, sharded over 16 extensions.
pub const KEY_META_EXTENSION_PREFIX: &str = "priv:scomm.keys.";

pub fn key_meta_extension_id(absolute_key_id: &str) -> String {
    let c = absolute_key_id.as_bytes().first().copied().unwrap_or(0);
    format!("{KEY_META_EXTENSION_PREFIX}{:x}", c % 16)
}

/// A device that holds a slot in the vault.
#[derive(Clone, Debug)]
pub struct VaultDevice {
    pub device_id: String,
    pub name: String,
    pub slot_id: Option<String>,
    pub added_at: Option<String>,
}

impl VaultDevice {
    pub fn new(device_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            name: name.into(),
            slot_id: None,
            added_at: None,
        }
    }

    pub fn from_json(slot_id: &str, json: &Value) -> Self {
        Self {
            slot_id: Some(slot_id.to_string()),
            device_id: json
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            name: json
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            added_at: json
                .get("added_at")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("device_id".into(), json!(self.device_id));
        m.insert("name".into(), json!(self.name));
        if let Some(a) = &self.added_at {
            m.insert("added_at".into(), json!(a));
        }
        Value::Object(m)
    }
}

#[async_trait]
pub trait VaultAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        vault_id: &str,
        operation: &str,
    ) -> Result<VaultAuthorization, VaultClientError>;
}

/// Static device / test authorizer that always returns the same header.
pub struct StaticAuthorizer {
    pub authorization: VaultAuthorization,
}

#[async_trait]
impl VaultAuthorizer for StaticAuthorizer {
    async fn authorize(
        &self,
        _vault_id: &str,
        _operation: &str,
    ) -> Result<VaultAuthorization, VaultClientError> {
        Ok(self.authorization.clone())
    }
}

/// Where and as whom a [`KeyVault`] syncs.
#[derive(Clone)]
pub struct VaultHostBinding {
    pub host: Arc<dyn VaultHostApi>,
    pub identity_id: String,
    pub authorize: Arc<dyn VaultAuthorizer>,
    pub license_device_id: Option<String>,
}

impl VaultHostBinding {
    pub fn new(
        host: Arc<dyn VaultHostApi>,
        identity_id: impl Into<String>,
        authorize: Arc<dyn VaultAuthorizer>,
    ) -> Self {
        Self {
            host,
            identity_id: identity_id.into(),
            authorize,
            license_device_id: None,
        }
    }

    pub fn device(
        host: Arc<dyn VaultHostApi>,
        identity_id: impl Into<String>,
        device_seed: Vec<u8>,
        license_device_id: Option<String>,
    ) -> Self {
        let identity_id = identity_id.into();
        let authorize = Arc::new(DeviceAuthorizer {
            device_seed,
            identity_id: identity_id.clone(),
        });
        Self {
            host,
            identity_id,
            authorize,
            license_device_id,
        }
    }
}

struct DeviceAuthorizer {
    device_seed: Vec<u8>,
    identity_id: String,
}

#[async_trait]
impl VaultAuthorizer for DeviceAuthorizer {
    async fn authorize(
        &self,
        vault_id: &str,
        operation: &str,
    ) -> Result<VaultAuthorization, VaultClientError> {
        crate::signing::device_read_authorization(
            &self.device_seed,
            &self.identity_id,
            vault_id,
            operation,
            None,
            None,
        )
    }
}

/// A local-first CKVF vault opened with this device's slot.
pub struct KeyVault {
    store: Arc<dyn LocalVaultStore>,
    pub binding: Option<VaultHostBinding>,
    vault: Option<UnlockedVault>,
}

impl KeyVault {
    pub fn new(store: Arc<dyn LocalVaultStore>) -> Self {
        Self {
            store,
            binding: None,
            vault: None,
        }
    }

    pub fn with_binding(store: Arc<dyn LocalVaultStore>, binding: VaultHostBinding) -> Self {
        Self {
            store,
            binding: Some(binding),
            vault: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.vault.is_some()
    }

    pub fn vault(&self) -> Result<&UnlockedVault, VaultClientError> {
        self.vault
            .as_ref()
            .ok_or_else(|| VaultClientError::msg("bad_response", "KeyVault is not open"))
    }

    pub fn vault_mut(&mut self) -> Result<&mut UnlockedVault, VaultClientError> {
        self.vault
            .as_mut()
            .ok_or_else(|| VaultClientError::msg("bad_response", "KeyVault is not open"))
    }

    pub fn vault_id(&self) -> Result<&str, VaultClientError> {
        Ok(&self.vault()?.container.vault_id)
    }

    pub fn generation(&self) -> Result<u64, VaultClientError> {
        Ok(self.vault()?.container.generation)
    }

    pub fn msk_seed(&self) -> Result<Vec<u8>, VaultClientError> {
        let pk = &self.vault()?.payload.msk.current.private_key;
        base64url_decode(pk).map_err(|e| VaultClientError::msg("bad_response", e.0))
    }

    pub fn msk_public_key(&self) -> Result<Vec<u8>, VaultClientError> {
        let pk = &self.vault()?.payload.msk.current.public_key;
        base64url_decode(pk).map_err(|e| VaultClientError::msg("bad_response", e.0))
    }

    pub fn signer(&self) -> Result<MskSigner, VaultClientError> {
        MskSigner::new(&self.msk_seed()?)
    }

    pub fn keys(&self) -> Result<&[scomm_vault::KeyRecord], VaultClientError> {
        Ok(&self.vault()?.payload.keys)
    }

    pub fn key(&self, absolute_key_id: &str) -> Result<Option<&scomm_vault::KeyRecord>, VaultClientError> {
        Ok(get_key(self.vault()?, absolute_key_id))
    }

    pub fn key_meta(&self, absolute_key_id: &str) -> Result<Option<Value>, VaultClientError> {
        let data = extension_data(&self.vault()?.payload, &key_meta_extension_id(absolute_key_id));
        Ok(data.get(absolute_key_id).cloned())
    }

    pub fn preferred_key(&self, family: &str, purpose: &str) -> Result<Option<String>, VaultClientError> {
        let v = self.vault()?;
        Ok(v.payload
            .preferred_keys
            .get(family)
            .and_then(|m| m.get(purpose))
            .and_then(|v| v.as_str())
            .map(str::to_string))
    }

    pub fn devices(&self) -> Result<Vec<VaultDevice>, VaultClientError> {
        let v = self.vault()?;
        let slots: std::collections::HashSet<_> = v
            .container
            .unlock_slots
            .iter()
            .map(|s| s.slot_id.as_str())
            .collect();
        let data = extension_data(&v.payload, DEVICES_EXTENSION_ID);
        Ok(data
            .iter()
            .filter(|(k, val)| slots.contains(k.as_str()) && val.is_object())
            .map(|(k, val)| VaultDevice::from_json(k, val))
            .collect())
    }

    pub async fn has_local_vault(&self) -> Result<bool, VaultClientError> {
        Ok(self
            .store
            .read(local_vault_keys::CONTAINER)
            .await?
            .is_some())
    }

    /// Generation 1 with a device slot for this device.
    pub async fn create(
        &mut self,
        email: &str,
        device: VaultDevice,
        msk_seed: Option<&[u8]>,
        now: Option<&str>,
    ) -> Result<(), VaultClientError> {
        let kek = random_bytes(32);
        let slot_id = base64url_encode(&random_bytes(16));
        let ts = rfc3339(now);
        let slot_id_c = slot_id.clone();
        let kek_c = kek.clone();
        let ts_c = ts.clone();
        let device_json = device_json(&device, &ts);
        let v = create_vault(CreateVaultOptions {
            identity_type: "email",
            identity_value: email,
            password: None,
            now: Some(&ts),
            kdf: None,
            vault_id: None,
            msk_seed,
            extensions: vec![Extension {
                id: DEVICES_EXTENSION_ID.into(),
                critical: false,
                data: json!({ slot_id_c.clone(): device_json }),
            }],
            extra_slots: Some(Box::new(move |vault_id, vek| {
                Ok(vec![wrap_device_slot(
                    vault_id,
                    vek,
                    &kek_c,
                    Some(&slot_id_c),
                    Some(&ts_c),
                )?])
            })),
        })?;
        self.write_device(&kek, &slot_id).await?;
        self.store
            .write(local_vault_keys::SYNCED_HASH, None)
            .await?;
        self.persist(v).await?;
        Ok(())
    }

    pub async fn open(&mut self) -> Result<bool, VaultClientError> {
        let Some(json) = self.store.read(local_vault_keys::CONTAINER).await? else {
            return Ok(false);
        };
        let raw: Value = serde_json::from_str(&json)
            .map_err(|e| VaultClientError::msg("bad_response", e.to_string()))?;
        self.vault = Some(self.open_with_device_slot(&raw).await?);
        Ok(true)
    }

    pub async fn adopt(
        &mut self,
        opened: UnlockedVault,
        device: VaultDevice,
        stored_on_host: bool,
        now: Option<&str>,
    ) -> Result<(), VaultClientError> {
        let kek = random_bytes(32);
        let slot_id = base64url_encode(&random_bytes(16));
        let ts = rfc3339(now);
        let slot = wrap_device_slot(
            &opened.container.vault_id,
            &opened.vek,
            &kek,
            Some(&slot_id),
            Some(&ts),
        )?;
        let mut with_device = UnlockedVault {
            container: opened.container.clone(),
            payload: with_extension_entry(
                &opened.payload,
                DEVICES_EXTENSION_ID,
                &slot_id,
                device_json(&device, &ts),
            ),
            vek: opened.vek.clone(),
        };
        let mut slots = opened.container.unlock_slots.clone();
        slots.push(slot);
        let v = commit_unlock_slots(&with_device, slots)?;
        // commit_unlock_slots reseals; keep payload we built
        with_device = v;
        self.write_device(&kek, &slot_id).await?;
        self.store
            .write(
                local_vault_keys::SYNCED_HASH,
                if stored_on_host {
                    Some(opened.container.generation_hash.as_str())
                } else {
                    None
                },
            )
            .await?;
        self.persist(with_device).await?;
        Ok(())
    }

    pub async fn clear(&mut self) -> Result<(), VaultClientError> {
        for k in local_vault_keys::ALL {
            self.store.write(k, None).await?;
        }
        self.vault = None;
        Ok(())
    }

    pub async fn commit<F>(&mut self, change: F, push: bool) -> Result<(), VaultClientError>
    where
        F: FnOnce(UnlockedVault) -> Result<UnlockedVault, VaultClientError>,
    {
        let current = self
            .vault
            .take()
            .ok_or_else(|| VaultClientError::msg("bad_response", "KeyVault is not open"))?;
        let next = change(current)?;
        self.persist(next).await?;
        if push {
            let _ = self.push_quietly().await;
        }
        Ok(())
    }

    pub async fn import_key(
        &mut self,
        family: &str,
        encoding: &str,
        algorithm: &str,
        purpose: Vec<String>,
        private_key: &[u8],
        public_key: &[u8],
        meta: Option<Value>,
        created_at: Option<&str>,
        status: Option<&str>,
        push: bool,
    ) -> Result<String, VaultClientError> {
        let mut id = String::new();
        let encoding = encoding.to_string();
        let family = family.to_string();
        let algorithm = algorithm.to_string();
        let private_key = private_key.to_vec();
        let public_key = public_key.to_vec();
        let meta = meta;
        let created_at = created_at.map(str::to_string);
        let status = status.map(str::to_string);
        self.commit(
            |mut v| {
                match import_private_key(
                    &v,
                    &family,
                    &encoding,
                    &algorithm,
                    None,
                    &purpose.iter().map(String::as_str).collect::<Vec<_>>(),
                    &private_key,
                    &public_key,
                    created_at.as_deref(),
                    None,
                ) {
                    Ok(next) => {
                        id = next.payload.keys.last().unwrap().absolute_key_id.clone();
                        v = next;
                    }
                    Err(e) if e.code() == "ERR_KEY_ID" => {
                        let canonical = if encoding == "openpgp-tsk" {
                            canonical_openpgp_public_key(&public_key, Some(&private_key))?
                        } else {
                            public_key.clone()
                        };
                        let (abs, _) = key_ids(&canonical)?;
                        id = abs;
                    }
                    Err(e) => return Err(e.into()),
                }
                if status.as_deref() == Some("retired")
                    && get_key(&v, &id).map(|k| k.status.as_str()) == Some("active")
                {
                    v = retire_key(&v, &id, None)?;
                } else if status.as_deref() == Some("revoked")
                    && get_key(&v, &id).map(|k| k.status.as_str()) != Some("revoked")
                {
                    v = revoke_key(&v, &id, None)?;
                }
                if let Some(meta) = &meta {
                    v = set_meta(v, &id, meta.clone())?;
                }
                Ok(v)
            },
            push,
        )
        .await?;
        Ok(id)
    }

    pub async fn set_key_meta(
        &mut self,
        absolute_key_id: &str,
        meta: Value,
    ) -> Result<(), VaultClientError> {
        let id = absolute_key_id.to_string();
        self.commit(|v| set_meta(v, &id, meta), true).await
    }

    pub async fn retire(&mut self, absolute_key_id: &str) -> Result<(), VaultClientError> {
        let id = absolute_key_id.to_string();
        self.commit(|v| Ok(retire_key(&v, &id, None)?), true).await
    }

    pub async fn revoke(&mut self, absolute_key_id: &str) -> Result<(), VaultClientError> {
        let id = absolute_key_id.to_string();
        self.commit(|v| Ok(revoke_key(&v, &id, None)?), true).await
    }

    pub async fn delete_private(
        &mut self,
        absolute_key_id: &str,
        reason: &str,
    ) -> Result<(), VaultClientError> {
        let id = absolute_key_id.to_string();
        let reason = reason.to_string();
        self.commit(|v| Ok(delete_private_key(&v, &id, &reason, None)?), true)
            .await
    }

    pub async fn set_preferred(
        &mut self,
        family: &str,
        purpose: &str,
        absolute_key_id: Option<&str>,
    ) -> Result<(), VaultClientError> {
        let family = family.to_string();
        let purpose = purpose.to_string();
        let absolute_key_id = absolute_key_id.map(str::to_string);
        self.commit(
            |v| {
                Ok(set_preferred_key(
                    &v,
                    &family,
                    &purpose,
                    absolute_key_id.as_deref(),
                    None,
                )?)
            },
            true,
        )
        .await
    }

    pub async fn remove_device(&mut self, slot_id: &str) -> Result<(), VaultClientError> {
        let slot_id = slot_id.to_string();
        self.commit(
            |v| {
                let next = remove_unlock_slot(&v, &slot_id)?;
                let mut data = extension_data(&next.payload, DEVICES_EXTENSION_ID);
                data.remove(&slot_id);
                Ok(update_extensions(
                    &next,
                    replace_extension(&next.payload.extensions, DEVICES_EXTENSION_ID, data),
                    None,
                )?)
            },
            true,
        )
        .await
    }

    pub async fn add_recovery_code(
        &mut self,
        pepper: &dyn PepperOprf,
        key: &PepperKey,
    ) -> Result<String, VaultClientError> {
        let code = generate_recovery_code();
        self.replace_pepper_slot(RECOVERY_CODE_OPRF_METHOD, &code, pepper, key)
            .await?;
        Ok(code)
    }

    pub async fn set_backup_password(
        &mut self,
        password: &str,
        pepper: &dyn PepperOprf,
        key: &PepperKey,
    ) -> Result<(), VaultClientError> {
        self.replace_pepper_slot(PASSWORD_OPRF_METHOD, password, pepper, key)
            .await
    }

    async fn replace_pepper_slot(
        &mut self,
        method: &str,
        secret: &str,
        pepper: &dyn PepperOprf,
        key: &PepperKey,
    ) -> Result<(), VaultClientError> {
        let method = method.to_string();
        let secret = secret.to_string();
        let key = PepperKey {
            kid: key.kid.clone(),
            public_key: key.public_key.clone(),
        };
        // PepperOprf is sync — caller supplies LocalPepperOprf or PrecomputedPepperOprf.
        self.commit(
            |v| {
                let slot = wrap_pepper_slot(
                    &v.container.vault_id,
                    &v.vek,
                    &method,
                    &secret,
                    pepper,
                    &key,
                    PEPPER_MIN_ARGON2ID,
                    None,
                    None,
                )?;
                let mut slots: Vec<_> = v
                    .container
                    .unlock_slots
                    .iter()
                    .filter(|s| s.method != method)
                    .cloned()
                    .collect();
                slots.push(slot);
                Ok(commit_unlock_slots(&v, slots)?)
            },
            true,
        )
        .await
    }

    pub fn has_slot(&self, method: &str) -> Result<bool, VaultClientError> {
        Ok(self
            .vault()?
            .container
            .unlock_slots
            .iter()
            .any(|s| s.method == method))
    }

    pub async fn sync(&mut self) -> Result<(), VaultClientError> {
        self.pull().await?;
        self.push().await?;
        Ok(())
    }

    pub async fn pull(&mut self) -> Result<bool, VaultClientError> {
        let Some(b) = self.binding.clone() else {
            return Ok(false);
        };
        let vault_id = self.vault_id()?.to_string();
        let auth = b
            .authorize
            .authorize(&vault_id, vault_operations::VAULT_GET_CURRENT)
            .await?;
        let read = b.host.current_record(&vault_id, &auth).await?;
        let Some(record) = read.record else {
            return Ok(false);
        };
        let local = self.vault()?.clone();
        if record.generation_hash() == local.container.generation_hash {
            self.store
                .write(
                    local_vault_keys::SYNCED_HASH,
                    Some(record.generation_hash()),
                )
                .await?;
            return Ok(false);
        }
        let head = self.open_record(&record, &b.identity_id).await?;
        let synced = self.store.read(local_vault_keys::SYNCED_HASH).await?;
        if synced.as_deref() == Some(local.container.generation_hash.as_str()) {
            self.store
                .write(
                    local_vault_keys::SYNCED_HASH,
                    Some(record.generation_hash()),
                )
                .await?;
            self.persist(head).await?;
        } else {
            let (merged, _) = merge_normalized(&head, &local)?;
            self.persist(merged).await?;
        }
        Ok(true)
    }

    pub async fn push(&mut self) -> Result<(), VaultClientError> {
        let Some(b) = self.binding.clone() else {
            return Ok(());
        };
        for _ in 0..4 {
            let local = self.vault()?.clone();
            let hash = local.container.generation_hash.clone();
            if self.store.read(local_vault_keys::SYNCED_HASH).await?.as_deref() == Some(hash.as_str())
            {
                return Ok(());
            }
            let signer = self.signer()?;
            match b
                .host
                .put_record(
                    &b.identity_id,
                    &local.container,
                    &signer,
                    b.license_device_id.as_deref(),
                )
                .await
            {
                Ok(_) => {
                    self.store
                        .write(local_vault_keys::SYNCED_HASH, Some(&hash))
                        .await?;
                    return Ok(());
                }
                Err(e) if e.code == "generation_conflict" => {
                    let head_generation = e
                        .details
                        .as_ref()
                        .and_then(|d| d.get("head_generation"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(u64::MAX);
                    if head_generation == 0 {
                        self.persist(rechain(&local, 1, None)?).await?;
                        continue;
                    }
                    let vault_id = self.vault_id()?.to_string();
                    let auth = b
                        .authorize
                        .authorize(&vault_id, vault_operations::VAULT_GET_CURRENT)
                        .await?;
                    let read = b.host.current_record(&vault_id, &auth).await?;
                    let Some(record) = read.record else {
                        self.persist(rechain(&local, 1, None)?).await?;
                        continue;
                    };
                    if Some(record.generation_hash())
                        == self.store.read(local_vault_keys::SYNCED_HASH).await?.as_deref()
                    {
                        self.persist(rechain(
                            &local,
                            record.generation() + 1,
                            Some(record.generation_hash()),
                        )?)
                        .await?;
                        continue;
                    }
                    let head = self.open_record(&record, &b.identity_id).await?;
                    let (merged, _) = merge_normalized(&head, &local)?;
                    self.persist(merged).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(VaultClientError::msg(
            "generation_conflict",
            "the host head kept moving; try again",
        ))
    }

    pub async fn host_mutation(
        &self,
        operation: &str,
        payload: Value,
    ) -> Result<Value, VaultClientError> {
        let b = self
            .binding
            .as_ref()
            .ok_or_else(|| VaultClientError::msg("not_bound", "no vault host binding"))?;
        let envelope = self.signer()?.envelope(&b.identity_id, operation, payload, None)?;
        b.host.mutate(envelope).await
    }

    pub async fn authorize_device(
        &self,
        device_id: &str,
        device_name: &str,
        device_public_key: &[u8],
    ) -> Result<Value, VaultClientError> {
        self.host_mutation(
            vault_operations::AUTHORIZE_DEVICE,
            json!({
                "version": 1,
                "device_id": device_id,
                "device_name": device_name,
                "device_public_key": base64url_encode(device_public_key),
            }),
        )
        .await
    }

    async fn push_quietly(&mut self) -> Result<(), VaultClientError> {
        if self.binding.is_none() {
            return Ok(());
        }
        match self.push().await {
            Err(e) if e.code == "network_error" => Ok(()),
            other => other,
        }
    }

    async fn open_record(
        &self,
        record: &VaultRecord,
        identity_id: &str,
    ) -> Result<UnlockedVault, VaultClientError> {
        let head = match self
            .open_with_device_slot(&record.container.to_json())
            .await
        {
            Ok(v) => v,
            Err(e) if e.code == "ERR_SLOT_ID" => {
                return Err(VaultClientError::msg(
                    "device_removed",
                    "this device no longer has a slot in the stored vault",
                ));
            }
            Err(e) => return Err(e),
        };
        verify_record_signature(record, &head, identity_id)?;
        Ok(head)
    }

    async fn open_with_device_slot(
        &self,
        container: &Value,
    ) -> Result<UnlockedVault, VaultClientError> {
        let slot_id = self.device_slot_id().await?;
        let kek = self.device_kek().await?;
        open_vault_with_device_kek(container, &slot_id, &kek, None).map_err(Into::into)
    }

    async fn device_kek(&self) -> Result<Vec<u8>, VaultClientError> {
        let raw = self
            .store
            .read(local_vault_keys::DEVICE_KEK)
            .await?
            .ok_or_else(|| {
                VaultClientError::msg("device_removed", "no device key on this device")
            })?;
        base64url_decode(&raw)
            .map_err(|e| VaultClientError::msg("bad_response", e.0))
            .and_then(|b| {
                if b.len() == 32 {
                    Ok(b)
                } else {
                    Err(VaultClientError::msg("bad_response", "device kek length"))
                }
            })
    }

    async fn device_slot_id(&self) -> Result<String, VaultClientError> {
        self.store
            .read(local_vault_keys::DEVICE_SLOT_ID)
            .await?
            .ok_or_else(|| {
                VaultClientError::msg("device_removed", "no device slot on this device")
            })
    }

    async fn write_device(&self, kek: &[u8], slot_id: &str) -> Result<(), VaultClientError> {
        self.store
            .write(local_vault_keys::DEVICE_KEK, Some(&base64url_encode(kek)))
            .await?;
        self.store
            .write(local_vault_keys::DEVICE_SLOT_ID, Some(slot_id))
            .await?;
        Ok(())
    }

    async fn persist(&mut self, v: UnlockedVault) -> Result<(), VaultClientError> {
        let json = serialize_container(&v.container)?;
        self.store
            .write(local_vault_keys::CONTAINER, Some(&json))
            .await?;
        self.vault = Some(v);
        Ok(())
    }
}

/// Recovery on a device without a slot (sync [`PepperOprf`]).
pub async fn open_host_vault_with_secret(
    host: &dyn VaultHostApi,
    vault_id: &str,
    identity_id: &str,
    authorization: &VaultAuthorization,
    secret: &str,
    method: Option<&str>,
    pepper: &dyn PepperOprf,
) -> Result<UnlockedVault, VaultClientError> {
    let method = method.unwrap_or(RECOVERY_CODE_OPRF_METHOD);
    let read = host.current_record(vault_id, authorization).await?;
    let record = read
        .record
        .ok_or_else(|| VaultClientError::msg("vault_not_synced", "the host stores no vault"))?;
    let _token = read
        .oprf_token
        .ok_or_else(|| VaultClientError::msg("bad_response", "no oprf_token with the read"))?;
    let opened = open_vault_with_pepper(
        &record.container.to_json(),
        secret,
        pepper,
        method,
        None,
        None,
    )?;
    verify_record_signature(&record, &opened, identity_id)?;
    Ok(opened)
}

/// Opens a host vault using [`HostPepperOprf`] (async evaluate + precomputed wrap).
pub async fn open_host_vault_with_host_pepper(
    host: Arc<dyn VaultHostApi>,
    vault_id: &str,
    identity_id: &str,
    authorization: VaultAuthorization,
    secret: &str,
    method: Option<&str>,
) -> Result<UnlockedVault, VaultClientError> {
    let method = method.unwrap_or(RECOVERY_CODE_OPRF_METHOD);
    let read = host.current_record(vault_id, &authorization).await?;
    let record = read
        .record
        .ok_or_else(|| VaultClientError::msg("vault_not_synced", "the host stores no vault"))?;
    let token = read
        .oprf_token
        .ok_or_else(|| VaultClientError::msg("bad_response", "no oprf_token with the read"))?;
    let pepper = HostPepperOprf::new(host, VaultAuthorization::oprf_token(token));
    // Find candidate slots and try each.
    let container = record.container.to_json();
    let slots: Vec<_> = record
        .container
        .unlock_slots
        .iter()
        .filter(|s| s.method == method)
        .cloned()
        .collect();
    if slots.is_empty() {
        return Err(VaultClientError::msg(
            "ERR_UNLOCK",
            format!("no {method} slot"),
        ));
    }
    let secret_bytes = scomm_vault::pepper_secret(method, secret)?;
    let last = slots.len() - 1;
    let mut last_err = None;
    for (i, slot) in slots.iter().enumerate() {
        let oprf = slot.oprf.as_ref().ok_or_else(|| {
            VaultClientError::msg("ERR_UNLOCK", "missing oprf params")
        })?;
        let pk = base64url_decode(&oprf.public_key)
            .map_err(|e| VaultClientError::msg("bad_response", e.0))?;
        match pepper
            .finalize(
                &record.container.vault_id,
                &slot.slot_id,
                &oprf.kid,
                &pk,
                &secret_bytes,
            )
            .await
        {
            Ok(rwd) => {
                let pre = HostPepperOprf::precomputed(
                    record.container.vault_id.clone(),
                    slot.slot_id.clone(),
                    oprf.kid.clone(),
                    secret_bytes.clone(),
                    rwd,
                );
                match open_vault_with_pepper(&container, secret, &pre, method, Some(&slot.slot_id), None)
                {
                    Ok(opened) => {
                        verify_record_signature(&record, &opened, identity_id)?;
                        return Ok(opened);
                    }
                    Err(e) if e.code() == "ERR_WRAP_DECRYPT" && i != last => {
                        last_err = Some(e);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) if i != last => {
                last_err = Some(scomm_vault::CkvfError::msg("ERR_UNLOCK", e.to_string()));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err
        .map(Into::into)
        .unwrap_or_else(|| VaultClientError::code_str("ERR_WRAP_DECRYPT")))
}

pub fn verify_record_signature(
    record: &VaultRecord,
    opened: &UnlockedVault,
    identity_id: &str,
) -> Result<(), VaultClientError> {
    let text = vault_records_signing_text(
        identity_id,
        &record.container.vault_id,
        record.generation(),
        record.generation_hash(),
    );
    let msk = &opened.payload.msk;
    let mut keys = vec![msk.current.public_key.clone()];
    keys.extend(msk.history.iter().map(|h| h.public_key.clone()));
    for pk_b64 in keys {
        let pk = base64url_decode(&pk_b64).map_err(|e| VaultClientError::msg("bad_response", e.0))?;
        if ed25519_verify(&pk, text.as_bytes(), &record.msk_signature) {
            return Ok(());
        }
    }
    Err(VaultClientError::msg(
        "invalid_signature",
        "record msk_signature is invalid",
    ))
}

fn device_json(device: &VaultDevice, ts: &str) -> Value {
    json!({
        "device_id": device.device_id,
        "name": device.name,
        "added_at": device.added_at.as_deref().unwrap_or(ts),
    })
}

fn extension_data(payload: &VaultPayload, id: &str) -> Map<String, Value> {
    for e in &payload.extensions {
        if e.id == id {
            if let Some(obj) = e.data.as_object() {
                return obj.clone();
            }
        }
    }
    Map::new()
}

fn replace_extension(
    extensions: &[Extension],
    id: &str,
    data: Map<String, Value>,
) -> Vec<Extension> {
    let mut out: Vec<Extension> = extensions.iter().filter(|e| e.id != id).cloned().collect();
    if !data.is_empty() {
        out.push(Extension {
            id: id.into(),
            critical: false,
            data: Value::Object(data),
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn with_extensions(p: &VaultPayload, extensions: Vec<Extension>) -> VaultPayload {
    VaultPayload {
        identity: p.identity.clone(),
        msk: p.msk.clone(),
        keys: p.keys.clone(),
        preferred_keys: p.preferred_keys.clone(),
        metadata: p.metadata.clone(),
        tombstones: p.tombstones.clone(),
        extensions,
        critical_extensions: p.critical_extensions.clone(),
    }
}

fn with_extension_entry(
    p: &VaultPayload,
    id: &str,
    key: &str,
    value: Value,
) -> VaultPayload {
    let mut data = extension_data(p, id);
    data.insert(key.into(), value);
    with_extensions(p, replace_extension(&p.extensions, id, data))
}

fn set_meta(
    v: UnlockedVault,
    absolute_key_id: &str,
    meta: Value,
) -> Result<UnlockedVault, VaultClientError> {
    let payload = with_extension_entry(
        &v.payload,
        &key_meta_extension_id(absolute_key_id),
        absolute_key_id,
        meta,
    );
    Ok(update_extensions(&v, payload.extensions, None)?)
}

fn merge_normalized(
    head: &UnlockedVault,
    local: &UnlockedVault,
) -> Result<(UnlockedVault, Vec<MergeConflict>), VaultClientError> {
    let mut ids = BTreeMap::new();
    for e in head.payload.extensions.iter().chain(local.payload.extensions.iter()) {
        if e.id.starts_with("priv:scomm.") {
            ids.insert(e.id.clone(), ());
        }
    }
    let mut head_payload = head.payload.clone();
    let mut local_payload = local.payload.clone();
    for id in ids.keys() {
        let mut merged = extension_data(&head.payload, id);
        for (k, v) in extension_data(&local.payload, id) {
            merged.insert(k, v);
        }
        head_payload = with_extensions(
            &head_payload,
            replace_extension(&head_payload.extensions, id, merged.clone()),
        );
        local_payload = with_extensions(
            &local_payload,
            replace_extension(&local_payload.extensions, id, merged),
        );
    }
    Ok(merge_onto(
        &UnlockedVault {
            container: head.container.clone(),
            payload: head_payload,
            vek: head.vek.clone(),
        },
        &UnlockedVault {
            container: local.container.clone(),
            payload: local_payload,
            vek: local.vek.clone(),
        },
        None,
    )?)
}

/// Opens a password-exported container.
pub fn open_export(json: &str, password: &str) -> Result<UnlockedVault, VaultClientError> {
    let raw: Value = serde_json::from_str(json)
        .map_err(|e| VaultClientError::msg("bad_response", e.to_string()))?;
    Ok(ckvf_open_vault(&raw, password, None, None)?)
}

/// Re-export argon params for export helpers.
pub fn recommended_argon2id() -> Argon2idParams {
    RECOMMENDED_ARGON2ID
}
