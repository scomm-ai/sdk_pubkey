//! `PepperOprf` backed by `POST /v1/pw-oprf/evaluate` with proof verification.

use std::sync::Arc;

use async_trait::async_trait;
use scomm_vault::{CkvfError, PepperOprf};

use crate::authorization::VaultAuthorization;
use crate::errors::VaultClientError;
use crate::oprf::{pepper_info, poprf_blind, poprf_finalize};
use crate::vault_host_client::VaultHostApi;

/// Host-backed pepper evaluation (async). Use [`HostPepperOprf::precomputed`]
/// to bridge into CKVF's sync [`PepperOprf`] trait after awaiting.
#[derive(Clone)]
pub struct HostPepperOprf {
    host: Arc<dyn VaultHostApi>,
    authorization: VaultAuthorization,
}

impl HostPepperOprf {
    pub fn new(host: Arc<dyn VaultHostApi>, authorization: VaultAuthorization) -> Self {
        Self {
            host,
            authorization,
        }
    }

    /// Blind, call the host, check `kid`, verify the POPRF proof.
    pub async fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, VaultClientError> {
        let info = pepper_info(vault_id, slot_id);
        let state = poprf_blind(secret, &info, public_key, None)?;
        let evaluation = self
            .host
            .evaluate_pepper(
                vault_id,
                slot_id,
                kid,
                &state.blinded,
                &self.authorization,
            )
            .await?;
        if evaluation.kid != kid {
            return Err(VaultClientError::msg(
                "invalid_evaluation",
                format!(
                    "the vault host answered with kid {}, not {kid}",
                    evaluation.kid
                ),
            ));
        }
        poprf_finalize(&state, &evaluation.evaluated, &evaluation.proof)
    }

    /// Build a sync [`PepperOprf`] that returns a single precomputed RWD.
    /// Call [`Self::finalize`] first, then pass this into CKVF slot APIs.
    pub fn precomputed(
        vault_id: impl Into<String>,
        slot_id: impl Into<String>,
        kid: impl Into<String>,
        secret: Vec<u8>,
        rwd: Vec<u8>,
    ) -> PrecomputedPepperOprf {
        PrecomputedPepperOprf {
            vault_id: vault_id.into(),
            slot_id: slot_id.into(),
            kid: kid.into(),
            secret,
            rwd,
        }
    }
}

/// Sync [`PepperOprf`] returning one precomputed evaluation.
pub struct PrecomputedPepperOprf {
    vault_id: String,
    slot_id: String,
    kid: String,
    secret: Vec<u8>,
    rwd: Vec<u8>,
}

impl PepperOprf for PrecomputedPepperOprf {
    fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        _public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, CkvfError> {
        if vault_id == self.vault_id
            && slot_id == self.slot_id
            && kid == self.kid
            && secret == self.secret.as_slice()
        {
            Ok(self.rwd.clone())
        } else {
            Err(CkvfError::msg(
                "ERR_UNLOCK",
                "precomputed pepper evaluation mismatch",
            ))
        }
    }
}

/// Local POPRF evaluator for tests (holds the pepper secret key).
pub struct LocalPepperOprf {
    secret_key: Vec<u8>,
}

impl LocalPepperOprf {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self { secret_key }
    }
}

impl PepperOprf for LocalPepperOprf {
    fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        _kid: &str,
        public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, CkvfError> {
        let info = pepper_info(vault_id, slot_id);
        let state = poprf_blind(secret, &info, public_key, None)
            .map_err(|e| CkvfError::msg("ERR_UNLOCK", e.to_string()))?;
        let (evaluated, proof) =
            crate::oprf::poprf_blind_evaluate(&self.secret_key, &info, &state.blinded, None)
                .map_err(|e| CkvfError::msg("ERR_UNLOCK", e.to_string()))?;
        poprf_finalize(&state, &evaluated, &proof)
            .map_err(|e| CkvfError::msg("ERR_UNLOCK", e.to_string()))
    }
}

/// Async trait object helper so hosts can also be used as pepper backends in tests.
#[async_trait]
pub trait AsyncPepperOprf: Send + Sync {
    async fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, VaultClientError>;
}

#[async_trait]
impl AsyncPepperOprf for HostPepperOprf {
    async fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, VaultClientError> {
        HostPepperOprf::finalize(self, vault_id, slot_id, kid, public_key, secret).await
    }
}
