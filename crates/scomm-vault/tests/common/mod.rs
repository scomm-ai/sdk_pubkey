//! In-memory vault host with records rules and pairing mailbox.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use ckvf::{base64url_decode, ed25519_verify, validate};
use serde_json::{json, Value};
use scomm_vault::{
    vault_records_signing_text, MskSigner, PepperEvaluation, PepperKeySet, VaultAuthorization,
    VaultClientError, VaultHostApi, VaultRead,
};

pub struct FakeVaultHost {
    inner: Mutex<FakeInner>,
}

struct FakeInner {
    records: Vec<Value>,
    pairings: HashMap<String, Value>,
    mutations: Vec<Value>,
    read_tokens: HashSet<String>,
    offline: bool,
}

impl FakeVaultHost {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FakeInner {
                records: vec![],
                pairings: HashMap::new(),
                mutations: vec![],
                read_tokens: HashSet::new(),
                offline: false,
            }),
        }
    }

    pub fn set_offline(&self, offline: bool) {
        self.inner.lock().unwrap().offline = offline;
    }

    pub fn records_len(&self) -> usize {
        self.inner.lock().unwrap().records.len()
    }
}

fn online(inner: &FakeInner) -> Result<(), VaultClientError> {
    if inner.offline {
        Err(VaultClientError::msg("network_error", "offline"))
    } else {
        Ok(())
    }
}

#[async_trait]
impl VaultHostApi for FakeVaultHost {
    async fn identity_oprf_key(&self) -> Result<Vec<u8>, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "identity_oprf_key"))
    }

    async fn identity_id(
        &self,
        _canonical_mailbox: &str,
        _public_key: Option<&[u8]>,
    ) -> Result<String, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "identity_id"))
    }

    async fn pepper_keys(&self) -> Result<PepperKeySet, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "pepper_keys"))
    }

    async fn evaluate_pepper(
        &self,
        _vault_id: &str,
        _slot_id: &str,
        _kid: &str,
        _blinded: &[u8],
        _authorization: &VaultAuthorization,
    ) -> Result<PepperEvaluation, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "evaluate_pepper"))
    }

    async fn current(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError> {
        let read = self.current_record(vault_id, authorization).await?;
        if let Some(r) = read.record {
            Ok(json!({
                "record": {
                    "container": r.container.to_json(),
                    "generation": r.generation(),
                    "generation_hash": r.generation_hash(),
                    "msk_signature": {
                        "algorithm": "ed25519",
                        "value": ckvf::base64url_encode(&r.msk_signature),
                    },
                    "created_at": r.created_at,
                }
            }))
        } else {
            Ok(json!({}))
        }
    }

    async fn generation(
        &self,
        vault_id: &str,
        _n: u64,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError> {
        self.current(vault_id, authorization).await
    }

    async fn current_record(
        &self,
        _vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<VaultRead, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        online(&inner)?;
        if let Some(token) = authorization.header().strip_prefix("PairingRead ") {
            if !inner.read_tokens.remove(token) {
                return Err(VaultClientError::with_status(
                    "pairing_read_token_invalid",
                    None,
                    Some(401),
                    None,
                ));
            }
        }
        if inner.records.is_empty() {
            return Ok(VaultRead::default());
        }
        let last = inner.records.last().unwrap().clone();
        drop(inner);
        VaultRead::from_json(&json!({ "record": last }))
    }

    async fn put_record(
        &self,
        identity_id: &str,
        container: &ckvf::VaultContainer,
        signer: &MskSigner,
        _license_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        online(&inner)?;
        validate(container)?;
        let sig = signer.record_signature(identity_id, container)?;
        let value = sig
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VaultClientError::msg("bad_response", "signature"))?;
        let sig_bytes = base64url_decode(value).map_err(|e| VaultClientError::msg("bad_response", e.0))?;
        let text = vault_records_signing_text(
            identity_id,
            &container.vault_id,
            container.generation,
            &container.generation_hash,
        );
        if !ed25519_verify(&signer.public_key(), text.as_bytes(), &sig_bytes) {
            return Err(VaultClientError::with_status(
                "invalid_signature",
                None,
                Some(401),
                None,
            ));
        }
        let head = inner.records.last().cloned();
        let head_generation = head
            .as_ref()
            .and_then(|h| h.get("generation"))
            .and_then(|g| g.as_u64())
            .unwrap_or(0);
        let head_hash = head
            .as_ref()
            .and_then(|h| h.get("generation_hash"))
            .and_then(|h| h.as_str())
            .map(str::to_string);
        let g = container.generation;
        if g <= head_generation {
            let stored = &inner.records[(g as usize) - 1];
            if stored.get("generation_hash").and_then(|h| h.as_str())
                == Some(container.generation_hash.as_str())
            {
                return Ok(json!({ "generation": g, "duplicate": true }));
            }
        }
        if g != head_generation + 1
            || container.previous_generation_hash.as_deref() != head_hash.as_deref()
        {
            let mut details = std::collections::HashMap::new();
            details.insert("generation".into(), json!(g));
            details.insert("head_generation".into(), json!(head_generation));
            details.insert(
                "head_generation_hash".into(),
                json!(head_hash),
            );
            return Err(VaultClientError::with_status(
                "generation_conflict",
                Some("does not extend the head".into()),
                Some(409),
                Some(details),
            ));
        }
        let container_json: Value = serde_json::from_str(&ckvf::serialize_container(container)?)
            .map_err(|e| VaultClientError::msg("bad_response", e.to_string()))?;
        inner.records.push(json!({
            "container": container_json,
            "generation": g,
            "generation_hash": container.generation_hash,
            "msk_signature": Value::Object(sig),
        }));
        Ok(json!({ "generation": g }))
    }

    async fn mutate(&self, envelope: Value) -> Result<Value, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        online(&inner)?;
        inner.mutations.push(envelope);
        Ok(json!({ "ok": true }))
    }

    async fn pending_mutations(
        &self,
        _vault_id: &str,
        _authorization: &VaultAuthorization,
    ) -> Result<Vec<Value>, VaultClientError> {
        Ok(vec![])
    }

    async fn create_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        let mut row = body;
        row.as_object_mut()
            .unwrap()
            .insert("state".into(), json!("PENDING"));
        inner.pairings.insert(session_id.to_string(), row);
        Ok(json!({ "session_id": session_id, "state": "PENDING" }))
    }

    async fn get_pairing(
        &self,
        session_id: &str,
        retriever_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        let row = inner
            .pairings
            .get_mut(session_id)
            .ok_or_else(|| VaultClientError::msg("not_found", "pairing"))?;
        let state = row
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if state == "PENDING" {
            return Ok(json!({
                "session_id": session_id,
                "state": "PENDING",
                "device_name": row.get("device_name"),
                "device_id": row.get("device_id"),
                "b_pake_element": row.get("b_pake_element"),
            }));
        }
        if state == "RESPONDED"
            && retriever_device_id == row.get("device_id").and_then(|v| v.as_str())
        {
            row.as_object_mut()
                .unwrap()
                .insert("state".into(), json!("COMPLETED"));
            let token = format!("token-{session_id}");
            inner.read_tokens.insert(token.clone());
            let vault_id = inner
                .records
                .last()
                .and_then(|r| r.get("container"))
                .and_then(|c| c.get("vault_id"))
                .cloned();
            // Re-borrow row after using inner.records
            let row = inner.pairings.get(session_id).unwrap();
            return Ok(json!({
                "session_id": session_id,
                "state": "RESPONDED",
                "a_pake_element": row.get("a_pake_element"),
                "vek_envelope": row.get("vek_envelope"),
                "confirmation_tag": row.get("confirmation_tag"),
                "msk_signature": row.get("msk_signature"),
                "vault_id": vault_id,
                "pairing_read_token": token,
            }));
        }
        Ok(json!({ "session_id": session_id, "state": state }))
    }

    async fn respond_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError> {
        let mut inner = self.inner.lock().unwrap();
        let row = inner
            .pairings
            .get_mut(session_id)
            .ok_or_else(|| VaultClientError::msg("not_found", "pairing"))?;
        if row.get("state").and_then(|v| v.as_str()) != Some("PENDING") {
            return Err(VaultClientError::with_status(
                "pairing_session_already_responded",
                None,
                Some(409),
                None,
            ));
        }
        if let Some(obj) = body.as_object() {
            for (k, v) in obj {
                row.as_object_mut().unwrap().insert(k.clone(), v.clone());
            }
        }
        row.as_object_mut()
            .unwrap()
            .insert("state".into(), json!("RESPONDED"));
        Ok(json!({ "session_id": session_id, "state": "RESPONDED" }))
    }

    async fn open_vault(
        &self,
        _identity_id: &str,
        _vault_id: &str,
        _otp_grant: &str,
        _msk: Value,
        _msk_proof: Value,
    ) -> Result<Value, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "open_vault"))
    }

    async fn rebind_msk(
        &self,
        _identity_id: &str,
        _vault_id: &str,
        _otp_grant: &str,
        _msk: Value,
        _msk_proof: Value,
    ) -> Result<Value, VaultClientError> {
        Err(VaultClientError::msg("not_implemented", "rebind_msk"))
    }
}
