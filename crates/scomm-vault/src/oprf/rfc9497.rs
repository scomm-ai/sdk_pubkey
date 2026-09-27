//! RFC 9497 building blocks for `ristretto255-SHA512`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity, VartimeMultiscalarMul};
use sha2::{Digest, Sha512};

use crate::errors::VaultClientError;

pub const OPRF_SUITE: &str = "ristretto255-SHA512";
pub const MODE_OPRF: u8 = 0x00;
pub const MODE_VOPRF: u8 = 0x01;
pub const MODE_POPRF: u8 = 0x02;

pub fn context_string(mode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 1 + 1 + OPRF_SUITE.len());
    out.extend_from_slice(b"OPRFV1-");
    out.push(mode);
    out.push(b'-');
    out.extend_from_slice(OPRF_SUITE.as_bytes());
    out
}

pub fn hash_to_group(input: &[u8], mode: u8) -> Result<RistrettoPoint, VaultClientError> {
    let mut dst = b"HashToGroup-".to_vec();
    dst.extend_from_slice(&context_string(mode));
    let uniform = expand_message_xmd_sha512(input, &dst, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&uniform);
    Ok(RistrettoPoint::from_uniform_bytes(&arr))
}

pub fn hash_to_scalar(input: &[u8], mode: u8) -> Result<Scalar, VaultClientError> {
    let mut dst = b"HashToScalar-".to_vec();
    dst.extend_from_slice(&context_string(mode));
    let uniform = expand_message_xmd_sha512(input, &dst, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&uniform);
    Ok(Scalar::from_bytes_mod_order_wide(&arr))
}

pub fn random_scalar(seed64: Option<&[u8]>) -> Result<Scalar, VaultClientError> {
    let bytes: [u8; 64] = if let Some(s) = seed64 {
        if s.len() != 64 {
            return Err(VaultClientError::msg("oprf_failed", "seed must be 64 bytes"));
        }
        let mut a = [0u8; 64];
        a.copy_from_slice(s);
        a
    } else {
        let mut a = [0u8; 64];
        getrandom::getrandom(&mut a)
            .map_err(|e| VaultClientError::msg("oprf_failed", e.to_string()))?;
        a
    };
    let s = Scalar::from_bytes_mod_order_wide(&bytes);
    if s == Scalar::ZERO {
        return Err(VaultClientError::msg("oprf_failed", "sampled a zero scalar"));
    }
    Ok(s)
}

pub fn decode_scalar(bytes: &[u8]) -> Result<Scalar, VaultClientError> {
    if bytes.len() != 32 {
        return Err(VaultClientError::msg(
            "invalid_evaluation",
            "scalar must be 32 bytes",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| {
        VaultClientError::msg("invalid_evaluation", "non-canonical scalar")
    })
}

/// Canonical, non-identity ristretto255 element.
pub fn decode_element(bytes: &[u8]) -> Result<RistrettoPoint, VaultClientError> {
    if bytes.len() != 32 {
        return Err(VaultClientError::msg(
            "invalid_evaluation",
            "element must be 32 bytes",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    let e = CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| VaultClientError::msg("invalid_evaluation", "non-canonical element"))?;
    if e.is_identity() {
        return Err(VaultClientError::msg(
            "invalid_evaluation",
            "identity element",
        ));
    }
    Ok(e)
}

pub fn enc(e: &RistrettoPoint) -> [u8; 32] {
    e.compress().to_bytes()
}

pub fn enc_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

pub fn mul(s: &Scalar, e: &RistrettoPoint) -> RistrettoPoint {
    e * s
}

pub fn mul_gen(s: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT * s
}

pub fn add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
    a + b
}

/// `I2OSP(len(x), 2) || x`.
pub fn lp(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + x.len());
    out.extend_from_slice(&i2osp(x.len(), 2));
    out.extend_from_slice(x);
    out
}

fn composites(
    mode: u8,
    b: &RistrettoPoint,
    c: &RistrettoPoint,
    d: &RistrettoPoint,
    k: Option<&Scalar>,
) -> Result<(RistrettoPoint, RistrettoPoint), VaultClientError> {
    let mut seed_dst = b"Seed-".to_vec();
    seed_dst.extend_from_slice(&context_string(mode));
    let mut seed_input = lp(&enc(b));
    seed_input.extend_from_slice(&lp(&seed_dst));
    let seed = Sha512::digest(&seed_input);

    let mut di_input = lp(&seed);
    di_input.extend_from_slice(&i2osp(0, 2));
    di_input.extend_from_slice(&lp(&enc(c)));
    di_input.extend_from_slice(&lp(&enc(d)));
    di_input.extend_from_slice(b"Composite");
    let di = hash_to_scalar(&di_input, mode)?;
    let m = mul(&di, c);
    let z = if let Some(k) = k {
        mul(k, &m)
    } else {
        mul(&di, d)
    };
    Ok((m, z))
}

fn challenge(
    mode: u8,
    b: &RistrettoPoint,
    m: &RistrettoPoint,
    z: &RistrettoPoint,
    t2: &RistrettoPoint,
    t3: &RistrettoPoint,
) -> Result<Scalar, VaultClientError> {
    let mut input = lp(&enc(b));
    input.extend_from_slice(&lp(&enc(m)));
    input.extend_from_slice(&lp(&enc(z)));
    input.extend_from_slice(&lp(&enc(t2)));
    input.extend_from_slice(&lp(&enc(t3)));
    input.extend_from_slice(b"Challenge");
    hash_to_scalar(&input, mode)
}

/// RFC 9497 §2.2.2 VerifyProof for one element, with A = generator.
pub fn verify_proof(
    mode: u8,
    b: &RistrettoPoint,
    c: &RistrettoPoint,
    d: &RistrettoPoint,
    proof: &[u8],
) -> bool {
    if proof.len() != 64 {
        return false;
    }
    let cs = match decode_scalar(&proof[..32]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let ss = match decode_scalar(&proof[32..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (m, z) = match composites(mode, b, c, d, None) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // t2 = ss*B + cs*b
    let t2 = RistrettoPoint::vartime_double_scalar_mul_basepoint(&cs, b, &ss);
    // t3 = ss*m + cs*z
    let t3 = RistrettoPoint::vartime_multiscalar_mul([&ss, &cs], [&m, &z]);
    match challenge(mode, b, &m, &z, &t2, &t3) {
        Ok(expected) => expected == cs,
        Err(_) => false,
    }
}

/// RFC 9497 §2.2.1 GenerateProof for one element (host-side / tests).
pub fn generate_proof(
    mode: u8,
    k: &Scalar,
    b: &RistrettoPoint,
    c: &RistrettoPoint,
    d: &RistrettoPoint,
    random64: Option<&[u8]>,
) -> Result<Vec<u8>, VaultClientError> {
    let (m, z) = composites(mode, b, c, d, Some(k))?;
    let r = random_scalar(random64)?;
    let t2 = mul_gen(&r);
    let t3 = mul(&r, &m);
    let cs = challenge(mode, b, &m, &z, &t2, &t3)?;
    let ss = r - (cs * k);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&enc_scalar(&cs));
    out.extend_from_slice(&enc_scalar(&ss));
    Ok(out)
}

/// `Hash(I2OSP(len(input),2) || input || [info] || I2OSP(len(N),2) || N || "Finalize")`.
pub fn finalize_hash(
    input: &[u8],
    unblinded: &RistrettoPoint,
    info: Option<&[u8]>,
) -> Vec<u8> {
    let mut data = lp(input);
    if let Some(info) = info {
        data.extend_from_slice(&lp(info));
    }
    data.extend_from_slice(&lp(&enc(unblinded)));
    data.extend_from_slice(b"Finalize");
    Sha512::digest(&data).to_vec()
}

/// `expand_message_xmd` with SHA-512 (RFC 9380 §5.3.1).
pub fn expand_message_xmd_sha512(
    msg: &[u8],
    dst: &[u8],
    len: usize,
) -> Result<Vec<u8>, VaultClientError> {
    const HASH_BYTES: usize = 64;
    const BLOCK_BYTES: usize = 128;
    if len == 0 || len > 255 * HASH_BYTES || dst.len() > 255 {
        return Err(VaultClientError::msg(
            "oprf_failed",
            "expand_message_xmd parameters out of range",
        ));
    }
    let ell = (len + HASH_BYTES - 1) / HASH_BYTES;
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    let mut b0_input = vec![0u8; BLOCK_BYTES];
    b0_input.extend_from_slice(msg);
    b0_input.extend_from_slice(&i2osp(len, 2));
    b0_input.push(0);
    b0_input.extend_from_slice(&dst_prime);
    let b0 = Sha512::digest(&b0_input);

    let mut prev_input = b0.to_vec();
    prev_input.push(1);
    prev_input.extend_from_slice(&dst_prime);
    let mut prev = Sha512::digest(&prev_input).to_vec();
    let mut out = prev.clone();
    for i in 2..=ell {
        let x: Vec<u8> = b0.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        let mut next_input = x;
        next_input.push(i as u8);
        next_input.extend_from_slice(&dst_prime);
        prev = Sha512::digest(&next_input).to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    Ok(out)
}

fn i2osp(value: usize, length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    let mut v = value;
    for i in (0..length).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    out
}

#[allow(dead_code)]
pub fn identity_element() -> RistrettoPoint {
    RistrettoPoint::identity()
}
