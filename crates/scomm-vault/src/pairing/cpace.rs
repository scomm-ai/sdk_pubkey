//! CPace-Ristretto255-SHA512 as in draft-irtf-cfrg-cpace-21 §8.3.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use sha2::{Digest, Sha512};

use crate::errors::VaultClientError;

pub const CPACE_CIPHERSUITE: &str = "CPaceRistretto255-SHA512";

const SHA512_BLOCK_BYTES: usize = 128;
const FIELD_BYTES: usize = 32;

fn dsi() -> &'static [u8] {
    b"CPaceRistretto255"
}

fn dsi_isk() -> &'static [u8] {
    b"CPaceRistretto255_ISK"
}

#[derive(Clone)]
pub struct CPaceInitiator {
    pub scalar: Vec<u8>,
    /// Public element sent to the responder.
    pub ya: Vec<u8>,
    pub sid: Vec<u8>,
    pub ci: Vec<u8>,
}

fn fail(message: &str) -> VaultClientError {
    VaultClientError::msg("pairing_protocol_error", message)
}

pub fn cpace_lv_cat(parts: &[&[u8]]) -> Result<Vec<u8>, VaultClientError> {
    let mut out = Vec::new();
    for part in parts {
        if part.len() > 255 {
            return Err(fail("CPace lv_cat field longer than 255 bytes"));
        }
        out.push(part.len() as u8);
        out.extend_from_slice(part);
    }
    Ok(out)
}

fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> Result<RistrettoPoint, VaultClientError> {
    let zpad = (SHA512_BLOCK_BYTES as isize
        - 1
        - (1 + prs.len() as isize)
        - (1 + dsi().len() as isize))
    .max(0) as usize;
    let gen_str = cpace_lv_cat(&[dsi(), prs, &vec![0u8; zpad], ci, sid])?;
    let hash = Sha512::digest(&gen_str);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&hash);
    Ok(RistrettoPoint::from_uniform_bytes(&arr))
}

fn scalar_from_seed(random64: &[u8]) -> Result<Scalar, VaultClientError> {
    if random64.len() != 64 {
        return Err(VaultClientError::msg(
            "pairing_protocol_error",
            "CPace scalar seed must be 64 bytes",
        ));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(random64);
    let s = Scalar::from_bytes_mod_order_wide(&arr);
    if s == Scalar::ZERO {
        return Err(fail("CPace sampled a zero scalar"));
    }
    Ok(s)
}

fn decode(bytes: &[u8]) -> Result<RistrettoPoint, VaultClientError> {
    if bytes.len() != FIELD_BYTES {
        return Err(fail("CPace element must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| fail("CPace element is not a valid ristretto255 encoding"))
}

fn isk(sid: &[u8], k: &[u8], ya: &[u8], yb: &[u8]) -> Result<Vec<u8>, VaultClientError> {
    let prefix = cpace_lv_cat(&[dsi_isk(), sid, k])?;
    let mut data = prefix;
    data.extend_from_slice(&cpace_lv_cat(&[ya, &[]])?);
    data.extend_from_slice(&cpace_lv_cat(&[yb, &[]])?);
    Ok(Sha512::digest(&data).to_vec())
}

fn shared(s: &Scalar, peer: &RistrettoPoint) -> Result<RistrettoPoint, VaultClientError> {
    let k = peer * s;
    if k.is_identity() {
        return Err(fail("CPace shared element is identity"));
    }
    Ok(k)
}

pub fn cpace_start(
    password: &[u8],
    sid: &[u8],
    ci: &[u8],
    random64: &[u8],
) -> Result<CPaceInitiator, VaultClientError> {
    let s = scalar_from_seed(random64)?;
    let ya = generator(password, ci, sid)? * s;
    Ok(CPaceInitiator {
        scalar: s.to_bytes().to_vec(),
        ya: ya.compress().to_bytes().to_vec(),
        sid: sid.to_vec(),
        ci: ci.to_vec(),
    })
}

pub struct CPaceResponse {
    pub yb: Vec<u8>,
    pub isk: Vec<u8>,
}

pub fn cpace_respond(
    password: &[u8],
    sid: &[u8],
    ci: &[u8],
    peer_ya: &[u8],
    random64: &[u8],
) -> Result<CPaceResponse, VaultClientError> {
    let s = scalar_from_seed(random64)?;
    let yb = (generator(password, ci, sid)? * s)
        .compress()
        .to_bytes()
        .to_vec();
    let k = shared(&s, &decode(peer_ya)?)?;
    Ok(CPaceResponse {
        isk: isk(sid, &k.compress().to_bytes(), peer_ya, &yb)?,
        yb,
    })
}

pub fn cpace_finish(state: &CPaceInitiator, peer_yb: &[u8]) -> Result<Vec<u8>, VaultClientError> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&state.scalar);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| fail("CPace scalar is not canonical"))?;
    let k = shared(&s, &decode(peer_yb)?)?;
    isk(&state.sid, &k.compress().to_bytes(), &state.ya, peer_yb)
}

#[allow(dead_code)]
fn _identity() -> RistrettoPoint {
    RistrettoPoint::identity()
}
