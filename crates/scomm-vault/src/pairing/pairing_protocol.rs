//! Pairing mailbox protocol constants, URI, TEK, and AEAD boxes.

use scomm_vault::{aes256gcm_decrypt, aes256gcm_encrypt, base64url_decode, base64url_encode, random_bytes};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::errors::VaultClientError;

type HmacSha256 = Hmac<Sha256>;

pub const PAIRING_CPACE_SID_INFO: &str = "SComm/Pubkey/pairing/cpace/v2";
pub const PAIRING_TEK_HKDF_INFO: &str = "SComm/Pubkey/pairing/tek/v2";
pub const PAIRING_TRANSCRIPT_HEADER: &str = "SComm/Pubkey/pairing/transcript/v2";
pub const PAIRING_CONFIRM_PLAINTEXT: &str = "SComm/Pubkey/pairing/confirm/v2";
pub const PAIRING_URI_SCHEME: &str = "scomm-pair";
pub const PAIRING_URI_VERSION: &str = "v2";

/// The host still requires a tier field; CKVF pairing always transfers the VEK.
pub const PAIRING_TIER: &str = "full";

pub const PAIRING_SESSION_ID_BYTES: usize = 16;
pub const PAIRING_HIGH_ENTROPY_PASSWORD_BYTES: usize = 16;
pub const PAIRING_TYPED_PASSWORD_LENGTH: usize = 16;

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `{iv, ciphertext}` with the 16-byte GCM tag appended to the ciphertext.
#[derive(Clone, Debug)]
pub struct PairingBox {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl PairingBox {
    pub fn from_json(json: &serde_json::Value) -> Result<Self, VaultClientError> {
        let iv = decode_b64_field(json, "iv", Some(12))?;
        let ciphertext = decode_b64_field(json, "ciphertext", None)?;
        Ok(Self { iv, ciphertext })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "iv": base64url_encode(&self.iv),
            "ciphertext": base64url_encode(&self.ciphertext),
        })
    }

    pub fn wire(&self) -> String {
        let mut all = self.iv.clone();
        all.extend_from_slice(&self.ciphertext);
        base64url_encode(&all)
    }
}

/// `scomm-pair:v2?sid=…&pw=…`, shown as a QR code by the new device.
#[derive(Clone, Debug)]
pub struct PairingUri {
    pub session_id: String,
    pub password: Vec<u8>,
}

impl PairingUri {
    pub fn to_uri_string(&self) -> String {
        format!(
            "{PAIRING_URI_SCHEME}:{PAIRING_URI_VERSION}?sid={}&pw={}",
            urlencoding_encode(&self.session_id),
            urlencoding_encode(&base64url_encode(&self.password)),
        )
    }

    pub fn try_parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let opaque = trimmed.strip_prefix(&format!("{PAIRING_URI_SCHEME}:"))?;
        let (ver, rest) = opaque.split_once('?')?;
        if ver != PAIRING_URI_VERSION {
            return None;
        }
        parse_query(rest)
    }
}

fn parse_query(rest: &str) -> Option<PairingUri> {
    let mut sid = None;
    let mut pw = None;
    for part in rest.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let v = urlencoding_decode(v);
            match k {
                "sid" => sid = Some(v),
                "pw" => pw = Some(v),
                _ => {}
            }
        }
    }
    let sid = sid.filter(|s| !s.is_empty())?;
    let pw = pw.filter(|s| !s.is_empty())?;
    let password = base64url_decode(&pw).ok()?;
    if password.len() < PAIRING_HIGH_ENTROPY_PASSWORD_BYTES {
        return None;
    }
    Some(PairingUri {
        session_id: sid,
        password,
    })
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_b64_field(
    json: &serde_json::Value,
    field: &str,
    expected: Option<usize>,
) -> Result<Vec<u8>, VaultClientError> {
    let s = json
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultClientError::msg("bad_response", format!("missing {field}")))?;
    let b = base64url_decode(s).map_err(|e| VaultClientError::msg("bad_response", e.0))?;
    if let Some(n) = expected {
        if b.len() != n {
            return Err(VaultClientError::msg(
                "bad_response",
                format!("{field} must be {n} bytes"),
            ));
        }
    }
    Ok(b)
}

pub struct PairingProtocol;

impl PairingProtocol {
    pub fn generate_session_id() -> String {
        random_bytes(PAIRING_SESSION_ID_BYTES)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn generate_high_entropy_password() -> Vec<u8> {
        random_bytes(PAIRING_HIGH_ENTROPY_PASSWORD_BYTES)
    }

    /// 16 Crockford Base32 characters (80 bits) for typing on the other device.
    pub fn generate_typed_password() -> String {
        let bytes = random_bytes(10);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut i = 0usize;
        let mut out = String::new();
        while out.len() < PAIRING_TYPED_PASSWORD_LENGTH {
            if bits < 5 {
                acc = ((acc << 8) | (bytes[i] as u32)) & 0xffff;
                bits += 8;
                i += 1;
            }
            bits -= 5;
            out.push(CROCKFORD[((acc >> bits) & 0x1f) as usize] as char);
        }
        out
    }

    pub fn typed_password_bytes(typed: &str) -> Result<Vec<u8>, VaultClientError> {
        let normalized = typed.trim().to_ascii_uppercase();
        if normalized.len() != PAIRING_TYPED_PASSWORD_LENGTH
            || normalized.bytes().any(|c| !CROCKFORD.contains(&c))
        {
            return Err(VaultClientError::msg(
                "pairing_password_mismatch",
                format!(
                    "Typed pairing password must be {PAIRING_TYPED_PASSWORD_LENGTH} Crockford characters"
                ),
            ));
        }
        Ok(normalized.into_bytes())
    }

    pub fn sid(session_id: &str, identity_id: &str) -> Vec<u8> {
        let mut material = Vec::new();
        material.extend_from_slice(PAIRING_CPACE_SID_INFO.as_bytes());
        material.push(0);
        material.extend_from_slice(session_id.as_bytes());
        material.push(0);
        material.extend_from_slice(identity_id.as_bytes());
        material.push(0);
        material.extend_from_slice(PAIRING_TIER.as_bytes());
        Sha256::digest(&material).to_vec()
    }

    pub fn ci(identity_id: &str) -> Vec<u8> {
        identity_id.as_bytes().to_vec()
    }

    pub fn tek(
        isk: &[u8],
        session_id: &str,
        ya: &[u8],
        yb: &[u8],
        identity_id: &str,
    ) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(PAIRING_TEK_HKDF_INFO.as_bytes());
        info.extend_from_slice(session_id.as_bytes());
        info.extend_from_slice(ya);
        info.extend_from_slice(yb);
        info.extend_from_slice(identity_id.as_bytes());
        info.extend_from_slice(PAIRING_TIER.as_bytes());
        info.extend_from_slice(b"v2");
        hkdf_sha256(isk, &info, 32, None)
    }

    pub fn transcript(
        session_id: &str,
        identity_id: &str,
        ya: &[u8],
        yb: &[u8],
        confirmation_tag: &PairingBox,
    ) -> Vec<u8> {
        format!(
            "{PAIRING_TRANSCRIPT_HEADER}\n\
             session_id={session_id}\n\
             identity={identity_id}\n\
             requested_tier={PAIRING_TIER}\n\
             ya={}\n\
             yb={}\n\
             confirmation_tag={}\n",
            base64url_encode(ya),
            base64url_encode(yb),
            confirmation_tag.wire(),
        )
        .into_bytes()
    }

    pub fn seal(key: &[u8], plaintext: &[u8]) -> Result<PairingBox, VaultClientError> {
        let iv = random_bytes(12);
        let enc = aes256gcm_encrypt(key, &iv, plaintext, &[])?;
        let mut ciphertext = enc.ciphertext;
        ciphertext.extend_from_slice(&enc.tag);
        Ok(PairingBox { iv, ciphertext })
    }

    pub fn open(key: &[u8], box_: &PairingBox) -> Result<Vec<u8>, VaultClientError> {
        let n = box_.ciphertext.len();
        if n < 16 {
            return Err(VaultClientError::msg(
                "pairing_protocol_error",
                "box is truncated",
            ));
        }
        aes256gcm_decrypt(
            key,
            &box_.iv,
            &box_.ciphertext[..n - 16],
            &box_.ciphertext[n - 16..],
            &[],
        )
        .map_err(|_| {
            VaultClientError::msg(
                "pairing_password_mismatch",
                "the confirmation failed: wrong password or tampering",
            )
        })
    }
}

/// RFC 5869 HKDF-SHA-256; the default salt is 32 zero bytes.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], length: usize, salt: Option<&[u8]>) -> Vec<u8> {
    let salt = salt.unwrap_or(&[0u8; 32]);
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC key");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut i = 1u8;
    while out.len() < length {
        let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC key");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i]);
        t = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        i = i.wrapping_add(1);
    }
    out.truncate(length);
    let mut prk_z = prk;
    prk_z.zeroize();
    out
}
