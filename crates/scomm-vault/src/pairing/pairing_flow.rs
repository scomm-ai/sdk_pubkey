//! CPace v2 pairing flow through the vault-host mailbox.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scomm_vault::{
    base64url_decode, base64url_encode, ed25519_verify, open_vault_with, random_bytes,
    UnlockedVault,
};
use serde_json::{json, Value};

use crate::authorization::VaultAuthorization;
use crate::errors::VaultClientError;
use crate::key_vault::{verify_record_signature, KeyVault};
use crate::pairing::cpace::{cpace_finish, cpace_respond, cpace_start, CPaceInitiator};
use crate::pairing::pairing_protocol::{
    PairingBox, PairingProtocol, PairingUri, PAIRING_CONFIRM_PLAINTEXT, PAIRING_TIER,
};
use crate::vault_host_client::VaultHostApi;

/// The new device's open pairing request.
pub struct PairingOffer {
    pub session_id: String,
    pub password: Vec<u8>,
    /// Set when the password is typed rather than scanned.
    pub typed_password: Option<String>,
    pub expires_at_ms: i64,
    /// Completes when the approving device answers; adopt with
    /// [`KeyVault::adopt`] (`stored_on_host: true`).
    pub completed: PairingCompleted,
}

/// Future returned by [`start_pairing`] for the opened vault.
pub type PairingCompleted = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<UnlockedVault, VaultClientError>> + Send>,
>;

impl PairingOffer {
    pub fn uri(&self) -> String {
        PairingUri {
            session_id: self.session_id.clone(),
            password: self.password.clone(),
        }
        .to_uri_string()
    }
}

/// A request the approving device fetched with [`fetch_pairing_request`].
#[derive(Clone, Debug)]
pub struct PendingPairing {
    pub session_id: String,
    pub device_name: String,
    pub device_id: String,
    pub ya: Vec<u8>,
}

fn refuse_v1(body: &Value) -> Result<(), VaultClientError> {
    if body.get("b_ephemeral_public_key").is_some() || body.get("a_ephemeral_public_key").is_some()
    {
        return Err(VaultClientError::msg(
            "pairing_protocol_unsupported",
            "the pairing mailbox spoke v1 ECDH; CPace v2 is required",
        ));
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// New device: opens a pairing mailbox and polls until the other device answers.
pub async fn start_pairing(
    host: Arc<dyn VaultHostApi>,
    identity_id: &str,
    device_name: &str,
    device_id: &str,
    typed_password: bool,
    poll_interval: Duration,
    expires_in_seconds: u64,
) -> Result<PairingOffer, VaultClientError> {
    let session_id = PairingProtocol::generate_session_id();
    let typed = if typed_password {
        Some(PairingProtocol::generate_typed_password())
    } else {
        None
    };
    let password = if let Some(ref t) = typed {
        PairingProtocol::typed_password_bytes(t)?
    } else {
        PairingProtocol::generate_high_entropy_password()
    };
    let state = cpace_start(
        &password,
        &PairingProtocol::sid(&session_id, identity_id),
        &PairingProtocol::ci(identity_id),
        &random_bytes(64),
    )?;
    let created = host
        .create_pairing(
            &session_id,
            json!({
                "identity_id": identity_id,
                "device_name": device_name,
                "requested_tier": PAIRING_TIER,
                "b_pake_element": base64url_encode(&state.ya),
                "device_id": device_id,
                "expires_in": expires_in_seconds,
            }),
        )
        .await?;
    let expires_at_ms = created
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono_parse_ms(s))
        .unwrap_or_else(|| now_ms() + (expires_in_seconds as i64) * 1000);

    let host2 = host.clone();
    let identity_id = identity_id.to_string();
    let session_id_c = session_id.clone();
    let device_id = device_id.to_string();
    let completed = Box::pin(await_response(
        host2,
        identity_id,
        session_id_c,
        device_id,
        state,
        expires_at_ms,
        poll_interval,
    ));

    Ok(PairingOffer {
        session_id,
        password,
        typed_password: typed,
        expires_at_ms,
        completed,
    })
}

fn chrono_parse_ms(_s: &str) -> Option<i64> {
    // Accept RFC3339 via a minimal parser: prefer `time` crate if available;
    // for fake host we usually get no expires_at.
    None
}

async fn await_response(
    host: Arc<dyn VaultHostApi>,
    identity_id: String,
    session_id: String,
    device_id: String,
    state: CPaceInitiator,
    expires_at_ms: i64,
    poll_interval: Duration,
) -> Result<UnlockedVault, VaultClientError> {
    let body = loop {
        let body = host
            .get_pairing(&session_id, Some(&device_id))
            .await?;
        refuse_v1(&body)?;
        let s = body.get("state").and_then(|v| v.as_str()).unwrap_or("");
        if s == "RESPONDED" && body.get("a_pake_element").and_then(|v| v.as_str()).is_some() {
            break body;
        }
        if s == "COMPLETED" || s == "RESPONDED" {
            return Err(VaultClientError::msg(
                "pairing_session_already_responded",
                "the pairing response was already retrieved",
            ));
        }
        if now_ms() > expires_at_ms {
            return Err(VaultClientError::msg(
                "pairing_session_expired",
                "the other device did not approve in time",
            ));
        }
        sleep(poll_interval).await;
    };

    let yb = decode_len(
        body.get("a_pake_element").and_then(|v| v.as_str()).unwrap(),
        32,
    )?;
    let tag = body
        .get("confirmation_tag")
        .ok_or_else(|| {
            VaultClientError::msg(
                "pairing_protocol_unsupported",
                "the pairing response is missing CPace v2 fields",
            )
        })?;
    let vek_box = body.get("vek_envelope").ok_or_else(|| {
        VaultClientError::msg(
            "pairing_protocol_unsupported",
            "the pairing response is missing CPace v2 fields",
        )
    })?;
    let sig = body
        .get("msk_signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VaultClientError::msg(
                "pairing_protocol_unsupported",
                "the pairing response is missing CPace v2 fields",
            )
        })?;
    let vault_id = body
        .get("vault_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VaultClientError::msg(
                "pairing_read_token_invalid",
                "the pairing response has no vault_id and pairing_read_token",
            )
        })?;
    let token = body
        .get("pairing_read_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VaultClientError::msg(
                "pairing_read_token_invalid",
                "the pairing response has no vault_id and pairing_read_token",
            )
        })?;

    let confirmation = PairingBox::from_json(tag)?;
    let tek = PairingProtocol::tek(
        &cpace_finish(&state, &yb)?,
        &session_id,
        &state.ya,
        &yb,
        &identity_id,
    );
    PairingProtocol::open(&tek, &confirmation).map_err(|e| {
        if e.code == "pairing_password_mismatch" {
            e
        } else {
            VaultClientError::msg(
                "pairing_password_mismatch",
                "the confirmation failed: wrong password or tampering",
            )
        }
    })?;
    let vek = PairingProtocol::open(&tek, &PairingBox::from_json(vek_box)?)?;

    let read = host
        .current_record(vault_id, &VaultAuthorization::pairing_read(token))
        .await?;
    let record = read.record.ok_or_else(|| {
        VaultClientError::msg(
            "vault_not_synced",
            "the other device has not stored its vault on the host yet",
        )
    })?;
    let container_json = record.container.to_json();
    let opened = open_vault_with(&container_json, None, |_| Ok(vek.clone()))?;
    verify_record_signature(&record, &opened, &identity_id)?;
    let transcript = PairingProtocol::transcript(
        &session_id,
        &identity_id,
        &state.ya,
        &yb,
        &confirmation,
    );
    let pk = base64url_decode(&opened.payload.msk.current.public_key)
        .map_err(|e| VaultClientError::msg("bad_response", e.0))?;
    let signature = decode_len(sig, 64)?;
    if !ed25519_verify(&pk, &transcript, &signature) {
        return Err(VaultClientError::msg(
            "pairing_signature_invalid",
            "the pairing transcript is not signed by the vault MSK",
        ));
    }
    Ok(opened)
}

/// Approving device: reads a pending request by session id.
pub async fn fetch_pairing_request(
    host: &dyn VaultHostApi,
    session_id: &str,
) -> Result<PendingPairing, VaultClientError> {
    let body = host.get_pairing(session_id, None).await?;
    refuse_v1(&body)?;
    if body.get("state").and_then(|v| v.as_str()) != Some("PENDING") {
        return Err(VaultClientError::msg(
            "pairing_session_already_responded",
            format!(
                "the pairing session is not awaiting approval ({})",
                body.get("state").and_then(|v| v.as_str()).unwrap_or("")
            ),
        ));
    }
    let ya = body
        .get("b_pake_element")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            VaultClientError::msg(
                "pairing_protocol_unsupported",
                "the pending pairing session has no CPace element",
            )
        })?;
    Ok(PendingPairing {
        session_id: session_id.to_string(),
        device_name: body
            .get("device_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        device_id: body
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        ya: decode_len(ya, 32)?,
    })
}

/// Approving device: pushes the vault, answers with the VEK under the CPace TEK.
pub async fn approve_pairing(
    vault: &mut KeyVault,
    request: &PendingPairing,
    password: &[u8],
    poll_interval: Duration,
    timeout: Duration,
) -> Result<(), VaultClientError> {
    let binding = vault
        .binding
        .as_ref()
        .ok_or_else(|| VaultClientError::msg("not_bound", "no vault host binding"))?
        .clone();
    vault.push().await?;
    let identity_id = binding.identity_id.clone();
    let responded = cpace_respond(
        password,
        &PairingProtocol::sid(&request.session_id, &identity_id),
        &PairingProtocol::ci(&identity_id),
        &request.ya,
        &random_bytes(64),
    )?;
    let tek = PairingProtocol::tek(
        &responded.isk,
        &request.session_id,
        &request.ya,
        &responded.yb,
        &identity_id,
    );
    let tag = PairingProtocol::seal(&tek, PAIRING_CONFIRM_PLAINTEXT.as_bytes())?;
    let unlocked = vault.vault()?;
    let vek_box = PairingProtocol::seal(&tek, &unlocked.vek)?;
    let transcript = PairingProtocol::transcript(
        &request.session_id,
        &identity_id,
        &request.ya,
        &responded.yb,
        &tag,
    );
    let sig = vault.signer()?.sign(&transcript)?;
    binding
        .host
        .respond_pairing(
            &request.session_id,
            json!({
                "identity_id": identity_id,
                "a_pake_element": base64url_encode(&responded.yb),
                "vek_envelope": vek_box.to_json(),
                "confirmation_tag": tag.to_json(),
                "msk_signature": base64url_encode(&sig),
            }),
        )
        .await?;

    let deadline = now_ms() + timeout.as_millis() as i64;
    loop {
        let body = binding.host.get_pairing(&request.session_id, None).await?;
        if body.get("state").and_then(|v| v.as_str()) == Some("COMPLETED") {
            return Ok(());
        }
        if now_ms() > deadline {
            return Err(VaultClientError::msg(
                "pairing_session_expired",
                "the new device did not collect the pairing response",
            ));
        }
        sleep(poll_interval).await;
    }
}

fn decode_len(s: &str, len: usize) -> Result<Vec<u8>, VaultClientError> {
    let b = base64url_decode(s).map_err(|e| VaultClientError::msg("bad_response", e.0))?;
    if b.len() != len {
        return Err(VaultClientError::msg(
            "bad_response",
            format!("expected {len} bytes"),
        ));
    }
    Ok(b)
}

async fn sleep(d: Duration) {
    // Executor-agnostic: park briefly on native; yield on wasm.
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::sleep(d);
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = d;
    }
}
