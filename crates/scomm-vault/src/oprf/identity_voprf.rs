//! Identity OPRF against the vault host (ckvf `profiles/vault-host.md` §2.1).
//!
//! Blind and Finalize are RFC 9497 mode `0x00`, so `identity_id` matches
//! every earlier client. The host adds a DLEQ proof under the VOPRF (`0x01`)
//! context; [`identity_finalize`] verifies it against the host public key.

use curve25519_dalek::traits::IsIdentity;

use super::rfc9497::{
    decode_element, decode_scalar, enc, enc_scalar, finalize_hash, generate_proof, hash_to_group,
    mul, mul_gen, random_scalar, verify_proof, MODE_OPRF, MODE_VOPRF,
};
use crate::errors::VaultClientError;

#[derive(Clone)]
pub struct IdentityBlindState {
    pub input: Vec<u8>,
    pub blind: Vec<u8>,
    pub blinded: Vec<u8>,
}

pub fn identity_blind(
    input: &[u8],
    blind: Option<&[u8]>,
) -> Result<IdentityBlindState, VaultClientError> {
    let r = if let Some(b) = blind {
        decode_scalar(b)?
    } else {
        random_scalar(None)?
    };
    let point = hash_to_group(input, MODE_OPRF)?;
    if point.is_identity() {
        return Err(VaultClientError::msg(
            "oprf_failed",
            "input maps to the identity",
        ));
    }
    Ok(IdentityBlindState {
        input: input.to_vec(),
        blind: enc_scalar(&r).to_vec(),
        blinded: enc(&mul(&r, &point)).to_vec(),
    })
}

/// Verifies `proof` against `public_key` and returns the 64-byte output.
pub fn identity_finalize(
    state: &IdentityBlindState,
    evaluated: &[u8],
    proof: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, VaultClientError> {
    let ev = decode_element(evaluated)?;
    let ok = verify_proof(
        MODE_VOPRF,
        &decode_element(public_key)?,
        &decode_element(&state.blinded)?,
        &ev,
        proof,
    );
    if !ok {
        return Err(VaultClientError::msg(
            "invalid_evaluation",
            "the vault host returned an identity evaluation that does not verify",
        ));
    }
    let inverse = decode_scalar(&state.blind)?.invert();
    Ok(finalize_hash(&state.input, &mul(&inverse, &ev), None))
}

/// Host evaluation plus VOPRF proof (tests / local harnesses only).
pub fn identity_blind_evaluate_for_tests(
    secret_key: &[u8],
    blinded: &[u8],
    random64: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), VaultClientError> {
    let k = decode_scalar(secret_key)?;
    let c = decode_element(blinded)?;
    let d = mul(&k, &c);
    let proof = generate_proof(MODE_VOPRF, &k, &mul_gen(&k), &c, &d, random64)?;
    Ok((enc(&d).to_vec(), proof))
}

/// First 32 bytes of Finalize, lowercase hex.
pub fn identity_id_from_output(output: &[u8]) -> String {
    hex::encode(&output[..32.min(output.len())])
}
