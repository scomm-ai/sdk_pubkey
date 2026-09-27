//! Pepper POPRF (RFC 9497 mode 0x02) for CKVF pepper slots.

use curve25519_dalek::traits::IsIdentity;

use super::rfc9497::{
    add, decode_element, decode_scalar, enc, enc_scalar, finalize_hash, hash_to_group,
    hash_to_scalar, lp, mul, mul_gen, random_scalar, verify_proof, MODE_POPRF,
};
use crate::errors::VaultClientError;

/// `info = "CKVF-pepper-v1" || 0x00 || vault_id || 0x00 || slot_id` (ASCII).
pub fn pepper_info(vault_id: &str, slot_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"CKVF-pepper-v1");
    out.push(0);
    out.extend_from_slice(vault_id.as_bytes());
    out.push(0);
    out.extend_from_slice(slot_id.as_bytes());
    out
}

#[derive(Clone)]
pub struct PoprfBlindState {
    pub input: Vec<u8>,
    pub info: Vec<u8>,
    /// Stays on the device.
    pub blind: Vec<u8>,
    /// Sent to the host as `blind`.
    pub blinded: Vec<u8>,
    pub tweaked_key: Vec<u8>,
}

fn info_scalar(info: &[u8]) -> Result<curve25519_dalek::scalar::Scalar, VaultClientError> {
    let mut input = b"Info".to_vec();
    input.extend_from_slice(&lp(info));
    hash_to_scalar(&input, MODE_POPRF)
}

/// RFC 9497 §3.3.3 Blind. `blind` fixes the scalar (vectors only).
pub fn poprf_blind(
    input: &[u8],
    info: &[u8],
    public_key: &[u8],
    blind: Option<&[u8]>,
) -> Result<PoprfBlindState, VaultClientError> {
    let tweaked = add(&mul_gen(&info_scalar(info)?), &decode_element(public_key)?);
    if tweaked.is_identity() {
        return Err(VaultClientError::msg(
            "oprf_failed",
            "tweaked key is the identity",
        ));
    }
    let r = if let Some(b) = blind {
        decode_scalar(b)?
    } else {
        random_scalar(None)?
    };
    let point = hash_to_group(input, MODE_POPRF)?;
    if point.is_identity() {
        return Err(VaultClientError::msg(
            "oprf_failed",
            "input maps to the identity",
        ));
    }
    Ok(PoprfBlindState {
        input: input.to_vec(),
        info: info.to_vec(),
        blind: enc_scalar(&r).to_vec(),
        blinded: enc(&mul(&r, &point)).to_vec(),
        tweaked_key: enc(&tweaked).to_vec(),
    })
}

/// RFC 9497 §3.3.3 Finalize. Throws `invalid_evaluation` when the proof fails.
pub fn poprf_finalize(
    state: &PoprfBlindState,
    evaluated: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, VaultClientError> {
    let ev = decode_element(evaluated)?;
    let ok = verify_proof(
        MODE_POPRF,
        &decode_element(&state.tweaked_key)?,
        &ev,
        &decode_element(&state.blinded)?,
        proof,
    );
    if !ok {
        return Err(VaultClientError::msg(
            "invalid_evaluation",
            "the vault host returned a pepper evaluation that does not verify",
        ));
    }
    let inverse = decode_scalar(&state.blind)?.invert();
    Ok(finalize_hash(
        &state.input,
        &mul(&inverse, &ev),
        Some(&state.info),
    ))
}

/// Host BlindEvaluate. The app never holds the pepper key; tests only.
pub fn poprf_blind_evaluate(
    secret_key: &[u8],
    info: &[u8],
    blinded: &[u8],
    random64: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), VaultClientError> {
    let t = decode_scalar(secret_key)? + info_scalar(info)?;
    if t == curve25519_dalek::scalar::Scalar::ZERO {
        return Err(VaultClientError::msg("oprf_failed", "inverse error"));
    }
    let d = decode_element(blinded)?;
    let c = mul(&t.invert(), &d);
    let proof = super::rfc9497::generate_proof(
        MODE_POPRF,
        &t,
        &mul_gen(&t),
        &c,
        &d,
        random64,
    )?;
    Ok((enc(&c).to_vec(), proof))
}

/// Public key for a 32-byte secret scalar.
pub fn oprf_public_key(secret_key: &[u8]) -> Result<Vec<u8>, VaultClientError> {
    Ok(enc(&mul_gen(&decode_scalar(secret_key)?)).to_vec())
}
