//! Browser bindings for the same discovery client (`--features wasm`).
//!
//! Methods return JSON text. MSK arguments are raw 32-byte seeds.

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use crate::document::DiscoveryDocument;
use crate::mailer::MailerClient;
use crate::pubkey_client::{DiscoveryClient, PubkeyClient, PubkeyClientBuilder};
use crate::select::select_best_artifact;
use crate::signer::Ed25519Signer;

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn json_string(value: &Value) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(js_err)
}

fn parse_json(text: &str) -> Result<Value, JsValue> {
    serde_json::from_str(text).map_err(js_err)
}

fn document_json(doc: &DiscoveryDocument) -> Result<String, JsValue> {
    json_string(&Value::Object(doc.raw.clone()))
}

fn seed_signer(seed: &[u8]) -> Result<Ed25519Signer, JsValue> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| JsValue::from_str("MSK seed must be 32 bytes"))?;
    Ok(Ed25519Signer::from_seed(seed))
}

/// Lowercase hex SHA-256 of an already-canonical mailbox.
#[wasm_bindgen]
pub fn mailbox_sha256_hex(canonical_mailbox: &str) -> String {
    crate::mailbox_sha256_hex(canonical_mailbox)
}

/// `GET /v1/mailboxes/{sha256}`.
#[wasm_bindgen]
pub fn mailbox_path(sha256_hex: &str) -> String {
    crate::mailbox_path(sha256_hex)
}

/// `GET /v1/keys` query.
#[wasm_bindgen]
pub fn keys_path(sha256_hex: &str, purpose: &str, key_id: Option<String>) -> String {
    crate::keys_path(sha256_hex, purpose, key_id.as_deref())
}

/// Rank artifacts the same way the native client does. Returns JSON or `null`.
#[wasm_bindgen]
pub fn select_best_artifact_json(
    artifacts_json: &str,
    capabilities_json: &str,
    purpose: &str,
) -> Result<Option<String>, JsValue> {
    let artifacts: Vec<Value> = serde_json::from_str(artifacts_json).map_err(js_err)?;
    let capabilities: Value = serde_json::from_str(capabilities_json).map_err(js_err)?;
    let purpose = if purpose.is_empty() { None } else { Some(purpose) };
    match select_best_artifact(&artifacts, Some(&capabilities), None, purpose) {
        Some(artifact) => Ok(Some(json_string(&Value::Object(artifact))?)),
        None => Ok(None),
    }
}

/// Track A client: public Discovery Document fetch.
#[wasm_bindgen]
pub struct WasmDiscoveryClient {
    inner: DiscoveryClient,
}

#[wasm_bindgen]
impl WasmDiscoveryClient {
    /// `read_base_url` is required. There is no production fallback.
    #[wasm_bindgen(constructor)]
    pub fn new(read_base_url: String) -> Result<WasmDiscoveryClient, JsValue> {
        Ok(Self {
            inner: DiscoveryClient::new(read_base_url).map_err(js_err)?,
        })
    }

    /// `GET /v1/mailboxes/{mailboxSha256}`.
    pub async fn discover_mailbox(&self, mailbox: String) -> Result<String, JsValue> {
        let doc = self.inner.discover_mailbox(&mailbox).await.map_err(js_err)?;
        document_json(&doc)
    }
}

/// Track B directory client: keys, challenges, and MSK arming.
#[wasm_bindgen]
pub struct WasmPubkeyClient {
    inner: PubkeyClient,
}

#[wasm_bindgen]
impl WasmPubkeyClient {
    /// Both read and write origins are required.
    #[wasm_bindgen(constructor)]
    pub fn new(read_base_url: String, write_base_url: String) -> Result<WasmPubkeyClient, JsValue> {
        let inner = PubkeyClientBuilder::new()
            .read_base_url(read_base_url)
            .write_base_url(write_base_url)
            .build()
            .map_err(js_err)?;
        Ok(Self { inner })
    }

    /// Public discovery document.
    pub async fn discover_mailbox(&self, mailbox: String) -> Result<String, JsValue> {
        let doc = self.inner.discover_mailbox(&mailbox).await.map_err(js_err)?;
        document_json(&doc)
    }

    /// `GET /v1/keys`. `capabilities_json` may be empty.
    pub async fn get_best_key(
        &self,
        email: String,
        purpose: String,
        key_id: String,
        capabilities_json: String,
    ) -> Result<String, JsValue> {
        let capabilities = if capabilities_json.is_empty() {
            None
        } else {
            Some(parse_json(&capabilities_json)?)
        };
        let purpose = if purpose.is_empty() { None } else { Some(purpose.as_str()) };
        let key_id = if key_id.is_empty() { None } else { Some(key_id.as_str()) };
        let value = self
            .inner
            .get_best_key(Some(&email), None, purpose, key_id, capabilities)
            .await
            .map_err(js_err)?;
        json_string(&value)
    }

    /// Create a challenge. `input_json` is optional and may be empty.
    pub async fn create_challenge(
        &self,
        mailbox: String,
        challenge_type: String,
        purpose: String,
        input_json: String,
    ) -> Result<String, JsValue> {
        let input = if input_json.is_empty() {
            None
        } else {
            Some(parse_json(&input_json)?)
        };
        let challenge = self
            .inner
            .create_challenge(&mailbox, &challenge_type, &purpose, input.as_ref())
            .await
            .map_err(js_err)?;
        json_string(&Value::Object(challenge.raw.clone()))
    }

    /// Respond to a challenge. `response_json` is the `response` object.
    pub async fn respond_to_challenge(
        &self,
        mailbox: String,
        challenge_id: String,
        response_json: String,
    ) -> Result<String, JsValue> {
        let response = parse_json(&response_json)?;
        let challenge = self
            .inner
            .respond_to_challenge(&mailbox, &challenge_id, &response)
            .await
            .map_err(js_err)?;
        json_string(&Value::Object(challenge.raw.clone()))
    }

    /// Signed directory mutation. `msk_seed` is 32 bytes.
    pub async fn mutate(
        &self,
        email: String,
        operation: String,
        payload_json: String,
        msk_seed: &[u8],
    ) -> Result<String, JsValue> {
        let payload = parse_json(&payload_json)?;
        let signer = seed_signer(msk_seed)?;
        let value = self
            .inner
            .mutate(&email, &operation, &payload, &signer)
            .await
            .map_err(js_err)?;
        json_string(&value)
    }

    /// `POST /v1/msk/arm` using a 32-byte MSK seed.
    pub async fn verify_enroll(
        &self,
        email: String,
        otp_grant: String,
        msk_seed: &[u8],
        device_json: String,
    ) -> Result<String, JsValue> {
        let signer = seed_signer(msk_seed)?;
        let device = if device_json.is_empty() {
            None
        } else {
            Some(parse_json(&device_json)?)
        };
        let value = self
            .inner
            .verify_enroll_for_identity(
                Some(&email),
                None,
                None,
                &otp_grant,
                &signer,
                device.as_ref(),
            )
            .await
            .map_err(js_err)?;
        json_string(&value)
    }
}

/// Mailer OTP client.
#[wasm_bindgen]
pub struct WasmMailerClient {
    inner: MailerClient,
}

#[wasm_bindgen]
impl WasmMailerClient {
    /// Mailer origin. Required.
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: String) -> Result<WasmMailerClient, JsValue> {
        Ok(Self {
            inner: MailerClient::new(base_url).map_err(js_err)?,
        })
    }

    /// Request a mailbox OTP. `msk_public_key` is optional raw 32 bytes.
    pub async fn request_otp(
        &mut self,
        email: String,
        purpose: String,
        msk_public_key: Option<Vec<u8>>,
    ) -> Result<(), JsValue> {
        self.inner
            .request_otp(&email, &purpose, msk_public_key.as_deref())
            .await
            .map_err(js_err)
    }

    /// Verify the OTP requested by [`Self::request_otp`].
    pub async fn verify_otp(
        &mut self,
        email: String,
        otp: String,
        purpose: String,
    ) -> Result<String, JsValue> {
        let grant = self
            .inner
            .verify_otp(&email, &otp, &purpose)
            .await
            .map_err(js_err)?;
        json_string(&json!({
            "identity_id": grant.identity_id,
            "otp_grant": grant.otp_grant,
            "vault_grant": grant.vault_grant,
        }))
    }
}
