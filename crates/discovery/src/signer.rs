//! MSK signing trait and Ed25519 helper.

use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};

use crate::canonical::encode_base64url;
use crate::errors::{ErrorCodes, PubkeyError};

/// Signs canonical MSK request bytes.
pub trait MskSigner: Send + Sync {
    /// Raw 32-byte public key.
    fn public_key(&self) -> &[u8];

    /// Sign `message` bytes; return raw signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PubkeyError>;

    /// Base64url public key.
    fn public_key_b64url(&self) -> String {
        encode_base64url(self.public_key())
    }
}

/// In-memory Ed25519 signer (32-byte seed, matching Dart `raw-32` MSK).
#[derive(Clone)]
pub struct Ed25519Signer {
    seed: [u8; 32],
    public: [u8; 32],
}

impl Ed25519Signer {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying: VerifyingKey = signing.verifying_key();
        Self {
            seed,
            public: verifying.to_bytes(),
        }
    }

    /// Generate a fresh random seed.
    pub fn generate() -> Result<Self, PubkeyError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| {
            PubkeyError::new(ErrorCodes::PROVIDER_UNAVAILABLE, e.to_string())
        })?;
        Ok(Self::from_seed(seed))
    }

    /// Seed bytes.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl MskSigner for Ed25519Signer {
    fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PubkeyError> {
        let signing = SigningKey::from_bytes(&self.seed);
        Ok(signing.sign(message).to_bytes().to_vec())
    }
}

/// Require a 32-byte MSK public key.
pub fn require_msk_public_key(key: Option<&[u8]>) -> Result<Vec<u8>, PubkeyError> {
    match key {
        Some(k) if k.len() == 32 => Ok(k.to_vec()),
        _ => Err(PubkeyError::new(
            ErrorCodes::INVALID_REQUEST,
            "A 32-byte ed25519 MSK public key is required to arm",
        )),
    }
}
