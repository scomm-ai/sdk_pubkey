//! SComm key-id: last 8 octets of the key fingerprint, 16 uppercase hex digits.
//!
//! OpenPGP material uses the OpenPGP fingerprint of the key packet Sequoia
//! uses (v4 SHA-1 or v6 SHA-256). Verify uses the primary key; encryption
//! uses the encryption subkey. That value is Sequoia's Key ID.
//!
//! S/MIME and any other bytes use SHA-256 of the published material. The last
//! 8 octets of that digest are the key-id.

use once_cell::sync::Lazy;
use regex::Regex;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

static DISPLAY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9A-Fa-f]{16}$").expect("key id"));

/// Last 8 octets of the fingerprint, as 16 uppercase hex digits.
pub struct ScommKeyId;

impl ScommKeyId {
    /// Derive from published public key material bytes.
    pub fn derive(public_material: &[u8]) -> String {
        Self::derive_for(public_material, None, None)
    }

    /// Derive, selecting the OpenPGP key packet for [purpose] and [algorithm].
    pub fn derive_for(
        public_material: &[u8],
        purpose: Option<&str>,
        algorithm: Option<&str>,
    ) -> String {
        if let Some(id) = openpgp_key_id(public_material, purpose, algorithm) {
            return id;
        }
        let digest = Sha256::digest(public_material);
        Self::format(&digest[digest.len() - 8..]).expect("8 octets")
    }

    /// Derive from UTF-8 text (e.g. armored key).
    pub fn derive_from_utf8(text: &str) -> String {
        Self::derive(text.as_bytes())
    }

    /// Format eight octets as 16 uppercase hex digits.
    pub fn format(eight_bytes: &[u8]) -> Result<String, String> {
        if eight_bytes.len() != 8 {
            return Err("SComm key-id requires exactly 8 octets".into());
        }
        Ok(hex::encode_upper(eight_bytes))
    }

    /// Strip separators; uppercase. Empty → empty.
    pub fn normalize(raw: Option<&str>) -> String {
        let Some(raw) = raw else {
            return String::new();
        };
        raw.trim()
            .to_uppercase()
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | ':' | '-' | '_'))
            .collect()
    }

    /// Compare after normalize.
    pub fn equals(a: Option<&str>, b: Option<&str>) -> bool {
        let na = Self::normalize(a);
        let nb = Self::normalize(b);
        !na.is_empty() && !nb.is_empty() && na == nb
    }

    /// Whether raw normalizes to 16 hex digits.
    pub fn looks_like_display(raw: Option<&str>) -> bool {
        DISPLAY_PATTERN.is_match(&Self::normalize(raw))
    }
}

fn openpgp_key_id(blob: &[u8], purpose: Option<&str>, algorithm: Option<&str>) -> Option<String> {
    let packets = packets(blob)?;
    let keys: Vec<&Packet> = packets.iter().filter(|p| p.tag == 6 || p.tag == 14).collect();
    if keys.is_empty() {
        return None;
    }
    let encrypt = matches!(purpose, Some("encryption") | Some("key_agreement"));
    let body = if keys.len() == 1 {
        keys[0].body.as_slice()
    } else if encrypt {
        let subs: Vec<_> = keys.iter().filter(|k| k.tag == 14).collect();
        let matched = algorithm.and_then(|alg| {
            subs.iter().find(|k| subkey_matches(&k.body, alg)).map(|k| k.body.as_slice())
        });
        matched
            .or_else(|| subs.first().map(|k| k.body.as_slice()))
            .unwrap_or(keys[0].body.as_slice())
    } else {
        keys.iter()
            .find(|k| k.tag == 6)
            .map(|k| k.body.as_slice())
            .unwrap_or(keys[0].body.as_slice())
    };
    key_id_from_body(body)
}

struct Packet {
    tag: u8,
    body: Vec<u8>,
}

fn packets(blob: &[u8]) -> Option<Vec<Packet>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset < blob.len() {
        let first = blob[offset];
        if first & 0x80 == 0 {
            return None;
        }
        let (tag, hdr, length) = if first & 0x40 != 0 {
            let (length, size) = new_length(blob, offset + 1)?;
            (first & 0x3f, 1 + size, length)
        } else {
            let tag = (first & 0x3c) >> 2;
            let len_type = first & 0x03;
            let (length, size) = match len_type {
                0 => (*blob.get(offset + 1)? as usize, 1usize),
                1 => {
                    let b = blob.get(offset + 1..offset + 3)?;
                    (u16::from_be_bytes([b[0], b[1]]) as usize, 2)
                }
                2 => {
                    let b = blob.get(offset + 1..offset + 5)?;
                    (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 4)
                }
                _ => return None,
            };
            (tag, 1 + size, length)
        };
        let start = offset + hdr;
        let end = start.checked_add(length)?;
        if end > blob.len() {
            return None;
        }
        out.push(Packet {
            tag,
            body: blob[start..end].to_vec(),
        });
        offset = end;
    }
    Some(out)
}

fn new_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *data.get(offset)?;
    if first < 192 {
        return Some((first as usize, 1));
    }
    if first < 224 {
        let second = *data.get(offset + 1)?;
        return Some((((first as usize) - 192) * 256 + second as usize + 192, 2));
    }
    if first == 255 {
        let b = data.get(offset + 1..offset + 5)?;
        return Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5));
    }
    None
}

fn key_id_from_body(body: &[u8]) -> Option<String> {
    let version = *body.first()?;
    let digest = if version == 4 {
        if body.len() > 0xffff {
            return None;
        }
        let mut hashed = Vec::with_capacity(3 + body.len());
        hashed.push(0x99);
        hashed.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hashed.extend_from_slice(body);
        Sha1::digest(&hashed).to_vec()
    } else if version == 6 {
        let mut hashed = Vec::with_capacity(5 + body.len());
        hashed.push(0x9b);
        hashed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        hashed.extend_from_slice(body);
        Sha256::digest(&hashed).to_vec()
    } else {
        return None;
    };
    ScommKeyId::format(&digest[digest.len() - 8..]).ok()
}

fn subkey_matches(body: &[u8], algorithm_name: &str) -> bool {
    if body.first().copied() != Some(4) && body.first().copied() != Some(6) {
        return false;
    }
    let mut offset = 5usize;
    let algorithm = match body.get(offset) {
        Some(a) => *a,
        None => return false,
    };
    offset += 1;
    if body[0] == 6 {
        offset += 4;
    }
    match algorithm_name {
        "openpgp-cv25519" => {
            algorithm == 25
                || (algorithm == 18
                    && (oid_eq(body, offset, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])
                        || oid_eq(body, offset, &[0x2b, 0x65, 0x6e])))
        }
        "openpgp-cv448" => {
            algorithm == 26 || (algorithm == 18 && oid_eq(body, offset, &[0x2b, 0x65, 0x6f]))
        }
        "openpgp-mlkem768-x25519" => algorithm == 35,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::ScommKeyId;
    use sha1::{Digest, Sha1};
    use sha2::Sha256;

    #[test]
    fn sha256_suffix_for_non_openpgp() {
        let material = b"sig-key-material";
        let digest = Sha256::digest(material);
        let expect = hex::encode_upper(&digest[digest.len() - 8..]);
        assert_eq!(ScommKeyId::derive(material), expect);
    }

    #[test]
    fn v4_fingerprint_last_eight() {
        let body = [
            4u8, 0, 0, 0, 1, 27, 10, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x01,
            0x07, 0x40, 1, 2, 3, 4, 5, 6, 7,
        ];
        let mut packet = vec![0xc6, body.len() as u8];
        packet.extend_from_slice(&body);
        let mut hashed = vec![0x99, 0, body.len() as u8];
        hashed.extend_from_slice(&body);
        let digest = Sha1::digest(&hashed);
        let expect = hex::encode_upper(&digest[digest.len() - 8..]);
        assert_eq!(ScommKeyId::derive(&packet), expect);
    }
}

fn oid_eq(body: &[u8], offset: usize, oid: &[u8]) -> bool {
    let Some(len) = body.get(offset).copied() else {
        return false;
    };
    let start = offset + 1;
    body.get(start..start + len as usize) == Some(oid)
}
