//! Vault-host HTTP client (ckvf `profiles/vault-host.md`).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use scomm_vault::{base64url_decode, base64url_encode, validate_container_shape, DEFAULT_LIMITS, PepperKey};
use serde_json::{json, Value};

use crate::authorization::VaultAuthorization;
use crate::errors::VaultClientError;
use crate::oprf::{
    identity_blind, identity_finalize, identity_id_from_output,
};
use crate::signing::MskSigner;

/// A stored CKVF generation (`record` of a vault read).
#[derive(Clone, Debug)]
pub struct VaultRecord {
    pub container: scomm_vault::VaultContainer,
    /// Raw 64-byte Ed25519 signature over [`crate::signing::vault_records_signing_text`].
    pub msk_signature: Vec<u8>,
    pub created_at: Option<String>,
}

impl VaultRecord {
    pub fn generation(&self) -> u64 {
        self.container.generation
    }

    pub fn generation_hash(&self) -> &str {
        &self.container.generation_hash
    }
}

/// Parsed `GET /v1/vault/{vault_id}/current|generation/{n}`.
#[derive(Clone, Debug, Default)]
pub struct VaultRead {
    pub record: Option<VaultRecord>,
    pub msk_public_key: Option<Vec<u8>>,
    pub archived_msk_public_keys: Vec<Vec<u8>>,
    pub oprf_token: Option<String>,
}

impl VaultRead {
    pub fn from_json(body: &Value) -> Result<Self, VaultClientError> {
        let record = if let Some(raw) = body.get("record").and_then(|v| v.as_object()) {
            let value = raw
                .get("msk_signature")
                .and_then(|s| s.get("value"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VaultClientError::msg("bad_response", "record.msk_signature")
                })?;
            let container_val = raw.get("container").ok_or_else(|| {
                VaultClientError::msg("bad_response", "record.container")
            })?;
            let container = validate_container_shape(container_val, DEFAULT_LIMITS)?;
            if let Some(g) = raw.get("generation") {
                if g.as_u64() != Some(container.generation) {
                    return Err(VaultClientError::msg("bad_response", "record.generation"));
                }
            }
            Some(VaultRecord {
                container,
                msk_signature: decode_len(value, 64)?,
                created_at: raw
                    .get("created_at")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            })
        } else {
            None
        };
        let msk_public_key = match body.get("msk_public_key") {
            Some(Value::String(s)) => Some(decode_len(s, 32)?),
            _ => None,
        };
        let archived_msk_public_keys = match body.get("archived_msk_public_keys") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|k| {
                    let s = k.as_str().unwrap_or("");
                    decode_len(s, 32)
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => vec![],
        };
        Ok(Self {
            record,
            msk_public_key,
            archived_msk_public_keys,
            oprf_token: body
                .get("oprf_token")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PepperKeyInfo {
    pub kid: String,
    pub public_key: Vec<u8>,
    /// `current` or `retired`.
    pub status: String,
}

impl PepperKeyInfo {
    pub fn as_pepper_key(&self) -> PepperKey {
        PepperKey {
            kid: self.kid.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

/// `GET /v1/pw-oprf/keys`.
#[derive(Clone, Debug)]
pub struct PepperKeySet {
    pub current_kid: String,
    pub keys: Vec<PepperKeyInfo>,
}

impl PepperKeySet {
    pub fn current(&self) -> Result<PepperKey, VaultClientError> {
        self.by_kid(&self.current_kid)
            .map(|k| k.as_pepper_key())
            .ok_or_else(|| VaultClientError::msg("bad_response", "current_kid is not listed"))
    }

    pub fn by_kid(&self, kid: &str) -> Option<&PepperKeyInfo> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// A slot pinned to `kid` should be rewrapped after unlock.
    pub fn needs_rewrap(&self, kid: &str) -> bool {
        kid != self.current_kid
    }
}

#[derive(Clone, Debug)]
pub struct PepperEvaluation {
    pub kid: String,
    pub evaluated: Vec<u8>,
    pub proof: Vec<u8>,
}

/// Async vault-host API (HTTP or in-memory fake).
#[async_trait]
pub trait VaultHostApi: Send + Sync {
    async fn identity_oprf_key(&self) -> Result<Vec<u8>, VaultClientError>;

    async fn identity_id(
        &self,
        canonical_mailbox: &str,
        public_key: Option<&[u8]>,
    ) -> Result<String, VaultClientError>;

    async fn pepper_keys(&self) -> Result<PepperKeySet, VaultClientError>;

    async fn evaluate_pepper(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        blinded: &[u8],
        authorization: &VaultAuthorization,
    ) -> Result<PepperEvaluation, VaultClientError>;

    async fn current(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError>;

    async fn generation(
        &self,
        vault_id: &str,
        n: u64,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError>;

    async fn current_record(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<VaultRead, VaultClientError> {
        VaultRead::from_json(&self.current(vault_id, authorization).await?)
    }

    async fn generation_record(
        &self,
        vault_id: &str,
        n: u64,
        authorization: &VaultAuthorization,
    ) -> Result<VaultRead, VaultClientError> {
        VaultRead::from_json(&self.generation(vault_id, n, authorization).await?)
    }

    async fn put_record(
        &self,
        identity_id: &str,
        container: &scomm_vault::VaultContainer,
        signer: &MskSigner,
        license_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError>;

    async fn mutate(&self, envelope: Value) -> Result<Value, VaultClientError>;

    async fn pending_mutations(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<Vec<Value>, VaultClientError>;

    async fn create_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError>;

    async fn get_pairing(
        &self,
        session_id: &str,
        retriever_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError>;

    async fn respond_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError>;

    async fn open_vault(
        &self,
        identity_id: &str,
        vault_id: &str,
        otp_grant: &str,
        msk: Value,
        msk_proof: Value,
    ) -> Result<Value, VaultClientError>;

    async fn rebind_msk(
        &self,
        identity_id: &str,
        vault_id: &str,
        otp_grant: &str,
        msk: Value,
        msk_proof: Value,
    ) -> Result<Value, VaultClientError>;
}

/// HTTP client for the vault host.
#[derive(Clone)]
pub struct VaultHostClient {
    base: String,
    http: reqwest::Client,
}

impl VaultHostClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, VaultClientError> {
        let base = base_url.as_ref().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| VaultClientError::msg("network_error", e.to_string()))?;
        Ok(Self { base, http })
    }

    pub fn shared(base_url: impl AsRef<str>) -> Result<Arc<Self>, VaultClientError> {
        Ok(Arc::new(Self::new(base_url)?))
    }

    async fn get(
        &self,
        path: &str,
        authorization: Option<&VaultAuthorization>,
    ) -> Result<Value, VaultClientError> {
        let mut req = self.http.get(format!("{}{path}", self.base));
        if let Some(a) = authorization {
            req = req.header("Authorization", a.header());
        }
        self.send(req).await
    }

    async fn post(
        &self,
        path: &str,
        body: Value,
        authorization: Option<&VaultAuthorization>,
    ) -> Result<Value, VaultClientError> {
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body);
        if let Some(a) = authorization {
            req = req.header("Authorization", a.header());
        }
        self.send(req).await
    }

    async fn put(
        &self,
        path: &str,
        body: Value,
        authorization: Option<&VaultAuthorization>,
    ) -> Result<Value, VaultClientError> {
        let mut req = self.http.put(format!("{}{path}", self.base)).json(&body);
        if let Some(a) = authorization {
            req = req.header("Authorization", a.header());
        }
        self.send(req).await
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value, VaultClientError> {
        let res = req
            .send()
            .await
            .map_err(|e| VaultClientError::msg("network_error", e.to_string()))?;
        let status = res.status().as_u16();
        let body: Value = res.json().await.map_err(|e| {
            if status >= 400 {
                VaultClientError::with_status(
                    format!("http_{status}"),
                    Some(e.to_string()),
                    Some(status),
                    None,
                )
            } else {
                VaultClientError::msg("bad_response", e.to_string())
            }
        })?;
        if status >= 400 {
            return Err(map_error_body(&body, status));
        }
        if !body.is_object() {
            return Err(VaultClientError::msg(
                "bad_response",
                "expected a JSON object",
            ));
        }
        Ok(body)
    }
}

fn map_error_body(body: &Value, status: u16) -> VaultClientError {
    let error = body
        .get("error")
        .filter(|e| e.is_object())
        .unwrap_or(body);
    let code = error
        .get("code")
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("http_{status}"));
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    let details = error.get("details").and_then(|d| {
        d.as_object().map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<_, _>>()
        })
    });
    VaultClientError::with_status(code, message, Some(status), details)
}

fn decode_len(s: &str, len: usize) -> Result<Vec<u8>, VaultClientError> {
    let b = base64url_decode(s).map_err(|_| {
        VaultClientError::msg("bad_response", format!("field must be {len} bytes"))
    })?;
    if b.len() != len {
        return Err(VaultClientError::msg(
            "bad_response",
            format!("field must be {len} bytes"),
        ));
    }
    Ok(b)
}

fn bytes_field(body: &Value, field: &str, len: usize) -> Result<Vec<u8>, VaultClientError> {
    let s = body
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultClientError::msg("bad_response", format!("{field} must be {len} bytes")))?;
    decode_len(s, len).map_err(|_| {
        VaultClientError::msg("bad_response", format!("{field} must be {len} bytes"))
    })
}

#[async_trait]
impl VaultHostApi for VaultHostClient {
    async fn identity_oprf_key(&self) -> Result<Vec<u8>, VaultClientError> {
        let body = self.get("/v1/id/oprf/key", None).await?;
        bytes_field(&body, "public_key", 32)
    }

    async fn identity_id(
        &self,
        canonical_mailbox: &str,
        public_key: Option<&[u8]>,
    ) -> Result<String, VaultClientError> {
        let key = match public_key {
            Some(k) => k.to_vec(),
            None => self.identity_oprf_key().await?,
        };
        let state = identity_blind(canonical_mailbox.as_bytes(), None)?;
        let body = self
            .post(
                "/v1/id/oprf/evaluate",
                json!({ "blind": base64url_encode(&state.blinded) }),
                None,
            )
            .await?;
        let out = identity_finalize(
            &state,
            &bytes_field(&body, "evaluation", 32)?,
            &bytes_field(&body, "proof", 64)?,
            &key,
        )?;
        Ok(identity_id_from_output(&out))
    }

    async fn pepper_keys(&self) -> Result<PepperKeySet, VaultClientError> {
        let body = self.get("/v1/pw-oprf/keys", None).await?;
        let keys = body
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| VaultClientError::msg("bad_response", "pw-oprf keys"))?;
        let current = body
            .get("current_kid")
            .and_then(|c| c.as_str())
            .ok_or_else(|| VaultClientError::msg("bad_response", "pw-oprf keys"))?
            .to_string();
        let set = PepperKeySet {
            current_kid: current.clone(),
            keys: keys
                .iter()
                .map(|k| {
                    Ok(PepperKeyInfo {
                        kid: k
                            .get("kid")
                            .map(|v| v.to_string().trim_matches('"').to_string())
                            .unwrap_or_default(),
                        public_key: bytes_field(k, "public_key", 32)?,
                        status: k
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                })
                .collect::<Result<Vec<_>, VaultClientError>>()?,
        };
        if set.by_kid(&current).is_none() {
            return Err(VaultClientError::msg(
                "bad_response",
                "current_kid is not listed",
            ));
        }
        Ok(set)
    }

    async fn evaluate_pepper(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        blinded: &[u8],
        authorization: &VaultAuthorization,
    ) -> Result<PepperEvaluation, VaultClientError> {
        let body = self
            .post(
                "/v1/pw-oprf/evaluate",
                json!({
                    "vault_id": vault_id,
                    "slot_id": slot_id,
                    "kid": kid,
                    "blind": base64url_encode(blinded),
                }),
                Some(authorization),
            )
            .await?;
        Ok(PepperEvaluation {
            kid: body
                .get("kid")
                .map(|v| v.as_str().unwrap_or("").to_string())
                .unwrap_or_default(),
            evaluated: bytes_field(&body, "evaluation", 32)?,
            proof: bytes_field(&body, "proof", 64)?,
        })
    }

    async fn current(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError> {
        self.get(
            &format!("/v1/vault/{vault_id}/current"),
            Some(authorization),
        )
        .await
    }

    async fn generation(
        &self,
        vault_id: &str,
        n: u64,
        authorization: &VaultAuthorization,
    ) -> Result<Value, VaultClientError> {
        self.get(
            &format!("/v1/vault/{vault_id}/generation/{n}"),
            Some(authorization),
        )
        .await
    }

    async fn put_record(
        &self,
        identity_id: &str,
        container: &scomm_vault::VaultContainer,
        signer: &MskSigner,
        license_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError> {
        let mut body = json!({
            "identity_id": identity_id,
            "container": container.to_json(),
            "msk_signature": Value::Object(signer.record_signature(identity_id, container)?),
        });
        if let Some(id) = license_device_id {
            body.as_object_mut()
                .unwrap()
                .insert("license_device_id".into(), Value::String(id.into()));
        }
        self.post(
            &format!("/v1/vault/{}/records", container.vault_id),
            body,
            None,
        )
        .await
    }

    async fn mutate(&self, envelope: Value) -> Result<Value, VaultClientError> {
        self.post("/v1/mutate", envelope, None).await
    }

    async fn pending_mutations(
        &self,
        vault_id: &str,
        authorization: &VaultAuthorization,
    ) -> Result<Vec<Value>, VaultClientError> {
        let body = self
            .get(
                &format!("/v1/vault/{vault_id}/pending-mutations"),
                Some(authorization),
            )
            .await?;
        Ok(body
            .get("mutations")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default())
    }

    async fn create_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError> {
        let enc = urlencoding_encode(session_id);
        self.post(&format!("/v1/pairing/{enc}"), body, None).await
    }

    async fn get_pairing(
        &self,
        session_id: &str,
        retriever_device_id: Option<&str>,
    ) -> Result<Value, VaultClientError> {
        let enc = urlencoding_encode(session_id);
        let path = if let Some(id) = retriever_device_id {
            format!(
                "/v1/pairing/{enc}?retriever_device_id={}",
                urlencoding_encode(id)
            )
        } else {
            format!("/v1/pairing/{enc}")
        };
        self.get(&path, None).await
    }

    async fn respond_pairing(
        &self,
        session_id: &str,
        body: Value,
    ) -> Result<Value, VaultClientError> {
        let enc = urlencoding_encode(session_id);
        self.put(&format!("/v1/pairing/{enc}/response"), body, None)
            .await
    }

    async fn open_vault(
        &self,
        identity_id: &str,
        vault_id: &str,
        otp_grant: &str,
        msk: Value,
        msk_proof: Value,
    ) -> Result<Value, VaultClientError> {
        self.post(
            "/v1/vault/open",
            json!({
                "identity_id": identity_id,
                "vault_id": vault_id,
                "otp_grant": otp_grant,
                "msk": msk,
                "msk_proof": msk_proof,
            }),
            None,
        )
        .await
    }

    async fn rebind_msk(
        &self,
        identity_id: &str,
        vault_id: &str,
        otp_grant: &str,
        msk: Value,
        msk_proof: Value,
    ) -> Result<Value, VaultClientError> {
        self.post(
            &format!("/v1/vault/{vault_id}/msk"),
            json!({
                "identity_id": identity_id,
                "otp_grant": otp_grant,
                "msk": msk,
                "msk_proof": msk_proof,
            }),
            None,
        )
        .await
    }
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
