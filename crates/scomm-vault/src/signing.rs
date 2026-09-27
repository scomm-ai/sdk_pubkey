//! MSK envelopes and device-read authorization.

use std::time::{SystemTime, UNIX_EPOCH};

use ckvf::{base64url_encode, canonicalize, ed25519_public_from_seed, ed25519_sign, random_bytes};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::authorization::VaultAuthorization;
use crate::errors::VaultClientError;

pub const PROTOCOL_VERSION: u32 = 1;

/// Operation names the vault host checks in signed envelopes.
pub mod vault_operations {
    pub const VAULT_RECORDS_PUT: &str = "vault_records_put";
    pub const VAULT_GET_CURRENT: &str = "vault_get_current";
    pub const VAULT_GET_GENERATION: &str = "vault_get_generation";
    pub const VAULT_GET_PENDING_MUTATIONS: &str = "vault_get_pending_mutations";
    pub const PW_OPRF_EVALUATE: &str = "pw_oprf_evaluate";
    pub const AUTHORIZE_DEVICE: &str = "authorize_device";
    pub const REVOKE_DEVICE: &str = "revoke_device";
    pub const LIST_DEVICES: &str = "list_devices";
    pub const GET_ME: &str = "get_me";
    pub const REPORT_VAULT_COVERAGE: &str = "report_vault_coverage";
    pub const CANCEL_HIGH_RISK_MUTATION: &str = "cancel_high_risk_mutation";
    pub const VAULT_OPEN: &str = "vault_open";
    pub const ARM_REPLACEMENT_MSK: &str = "arm_replacement_msk";
}

pub fn domain_separator(operation: &str) -> String {
    format!("SComm/Pubkey/{PROTOCOL_VERSION}/{operation}")
}

pub fn payload_sha256_hex(payload: &Value) -> Result<String, VaultClientError> {
    let jcs = canonicalize(payload).map_err(|e| VaultClientError::msg("bad_response", e.0))?;
    let digest = Sha256::digest(jcs.as_bytes());
    Ok(hex::encode(digest))
}

fn nonce() -> String {
    base64url_encode(&random_bytes(16))
}

fn now_ms(now: Option<i64>) -> i64 {
    now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

/// `SComm/Pubkey/1/vault_records_put` text the MSK signs for
/// `POST /v1/vault/{vault_id}/records`.
pub fn vault_records_signing_text(
    identity_id: &str,
    vault_id: &str,
    generation: u64,
    generation_hash: &str,
) -> String {
    format!(
        "{}\nprincipal={identity_id}\nvault_id={vault_id}\ngeneration={generation}\ngeneration_hash={generation_hash}\n",
        domain_separator(vault_operations::VAULT_RECORDS_PUT),
    )
}

/// Signs with an Ed25519 MSK seed (the CKVF payload's `msk.current`).
#[derive(Clone)]
pub struct MskSigner {
    seed: [u8; 32],
}

impl MskSigner {
    pub fn new(seed: &[u8]) -> Result<Self, VaultClientError> {
        if seed.len() != 32 {
            return Err(VaultClientError::msg("bad_response", "seed must be 32 bytes"));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        Ok(Self { seed: s })
    }

    pub fn from_vault(vault: &ckvf::UnlockedVault) -> Result<Self, VaultClientError> {
        let pk = ckvf::base64url_decode(&vault.payload.msk.current.private_key)
            .map_err(|e| VaultClientError::msg("bad_response", e.0))?;
        Self::new(&pk)
    }

    pub fn public_key(&self) -> Vec<u8> {
        ed25519_public_from_seed(&self.seed)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, VaultClientError> {
        ed25519_sign(&self.seed, message).map_err(Into::into)
    }

    /// Envelope for `/v1/mutate` and MSK proofs.
    pub fn envelope(
        &self,
        principal: &str,
        operation: &str,
        payload: Value,
        now: Option<i64>,
    ) -> Result<Value, VaultClientError> {
        let timestamp = now_ms(now);
        let nonce = nonce();
        let text = format!(
            "{}\nprincipal={principal}\ntimestamp={timestamp}\nnonce={nonce}\npayload_sha256={}\n",
            domain_separator(operation),
            payload_sha256_hex(&payload)?,
        );
        let signature = self.sign(text.as_bytes())?;
        Ok(json!({
            "protocol_version": PROTOCOL_VERSION,
            "principal": principal,
            "operation": operation,
            "timestamp": timestamp,
            "nonce": nonce,
            "payload": payload,
            "signature": {
                "algorithm": "ed25519",
                "value": base64url_encode(&signature),
            },
        }))
    }

    /// `msk_signature` for a records upload.
    pub fn record_signature(
        &self,
        identity_id: &str,
        container: &ckvf::VaultContainer,
    ) -> Result<Map<String, Value>, VaultClientError> {
        let text = vault_records_signing_text(
            identity_id,
            &container.vault_id,
            container.generation,
            &container.generation_hash,
        );
        let signature = self.sign(text.as_bytes())?;
        let mut m = Map::new();
        m.insert("algorithm".into(), Value::String("ed25519".into()));
        m.insert("value".into(), Value::String(base64url_encode(&signature)));
        Ok(m)
    }
}

/// `Authorization: Device …` for vault reads, signed by an enrolled device key.
pub fn device_read_authorization(
    device_seed: &[u8],
    identity_id: &str,
    vault_id: &str,
    operation: &str,
    payload: Option<Value>,
    now: Option<i64>,
) -> Result<VaultAuthorization, VaultClientError> {
    if device_seed.len() != 32 {
        return Err(VaultClientError::msg(
            "bad_response",
            "device seed must be 32 bytes",
        ));
    }
    let payload = payload.unwrap_or_else(|| json!({}));
    let timestamp = now_ms(now);
    let nonce = nonce();
    let payload_hash = payload_sha256_hex(&payload)?;
    let text = format!(
        "{}\nprincipal={identity_id}\nvault_id={vault_id}\ntimestamp={timestamp}\nnonce={nonce}\npayload_sha256={payload_hash}\n",
        domain_separator(operation),
    );
    let signature = ed25519_sign(device_seed, text.as_bytes())?;
    let envelope = json!({
        "protocol_version": PROTOCOL_VERSION,
        "principal": identity_id,
        "vault_id": vault_id,
        "operation": operation,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload_sha256": payload_hash,
        "signature": base64url_encode(&signature),
    });
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|e| VaultClientError::msg("bad_response", e.to_string()))?;
    Ok(VaultAuthorization::device(base64url_encode(&bytes)))
}
