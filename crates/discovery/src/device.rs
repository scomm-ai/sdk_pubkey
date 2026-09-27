//! Device authorization payload and identity UX helpers.

use serde_json::{json, Map, Value};

use crate::constants::{identity_ux_states, DEVICE_AUTHORIZATION_VERSION, DEVICE_KEY_ALGORITHM};
use crate::errors::{ErrorCodes, PubkeyError};
use crate::jcs::canonicalize_json;

/// Build a device authorization payload map.
pub fn device_authorization_payload(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    created_at: i64,
    nonce: &str,
    device_name: Option<&str>,
) -> Result<Value, PubkeyError> {
    device_authorization_payload_versioned(
        DEVICE_AUTHORIZATION_VERSION,
        principal_id,
        device_id,
        device_public_key,
        DEVICE_KEY_ALGORITHM,
        created_at,
        nonce,
        device_name,
    )
}

/// Versioned device authorization payload.
pub fn device_authorization_payload_versioned(
    version: i64,
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    algorithm: &str,
    created_at: i64,
    nonce: &str,
    device_name: Option<&str>,
) -> Result<Value, PubkeyError> {
    if version != DEVICE_AUTHORIZATION_VERSION {
        return Err(PubkeyError::new(
            ErrorCodes::UNSUPPORTED_STRUCTURE_VERSION,
            "Unsupported DeviceAuthorization version",
        ));
    }
    let mut payload = Map::new();
    payload.insert("version".into(), json!(version));
    payload.insert("principal_id".into(), json!(principal_id));
    payload.insert("device_id".into(), json!(device_id));
    payload.insert("device_public_key".into(), json!(device_public_key));
    payload.insert("device_key_algorithm".into(), json!(algorithm));
    payload.insert("created_at".into(), json!(created_at));
    payload.insert("nonce".into(), json!(nonce));
    if let Some(name) = device_name {
        payload.insert("device_name".into(), json!(name));
    }
    Ok(Value::Object(payload))
}

/// JCS of a device authorization (accepts camelCase or snake_case keys).
pub fn canonicalize_device_authorization(authorization: &Value) -> Result<String, String> {
    let obj = authorization
        .as_object()
        .ok_or_else(|| "device authorization must be an object".to_string())?;
    let get_str = |snake: &str, camel: &str| -> Result<String, String> {
        obj.get(snake)
            .or_else(|| obj.get(camel))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("missing {snake}"))
    };
    let get_i64 = |snake: &str, camel: &str| -> Result<i64, String> {
        obj.get(snake)
            .or_else(|| obj.get(camel))
            .and_then(|v| v.as_i64())
            .ok_or_else(|| format!("missing {snake}"))
    };
    let version = obj
        .get("version")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEVICE_AUTHORIZATION_VERSION);
    let algorithm = obj
        .get("device_key_algorithm")
        .or_else(|| obj.get("deviceKeyAlgorithm"))
        .and_then(|v| v.as_str())
        .unwrap_or(DEVICE_KEY_ALGORITHM);
    let device_name = obj
        .get("device_name")
        .or_else(|| obj.get("deviceName"))
        .and_then(|v| v.as_str());
    let payload = device_authorization_payload_versioned(
        version,
        &get_str("principal_id", "principalId")?,
        &get_str("device_id", "deviceId")?,
        &get_str("device_public_key", "devicePublicKey")?,
        algorithm,
        get_i64("created_at", "createdAt")?,
        &get_str("nonce", "nonce")?,
        device_name,
    )
    .map_err(|e| e.message)?;
    canonicalize_json(&payload)
}

/// True when generating an MSK would be silent replacement.
pub fn must_not_generate_msk(
    principal_exists: bool,
    local_msk: bool,
    explicit_recovery: bool,
) -> bool {
    principal_exists && !local_msk && !explicit_recovery
}

/// Resolve identity UX state string.
pub fn resolve_identity_ux_state(
    principal_exists: bool,
    local_msk: bool,
    device_authorized: Option<bool>,
    enrollment_state: Option<&str>,
    recovery_state: Option<&str>,
    vault_syncing: bool,
    historical_keys_available: Option<bool>,
) -> &'static str {
    if matches!(recovery_state, Some("OTP_SENT") | Some("RECOVERY_REQUESTED")) {
        return identity_ux_states::OTP_REQUIRED;
    }
    if matches!(
        recovery_state,
        Some("OTP_VERIFIED") | Some("NEW_MSK_SUBMITTED")
    ) {
        return identity_ux_states::NEW_MSK_CREATING;
    }
    if recovery_state == Some("COMPLETE") {
        return if historical_keys_available == Some(false) {
            identity_ux_states::HISTORICAL_KEYS_UNAVAILABLE
        } else {
            identity_ux_states::IDENTITY_RECOVERED
        };
    }
    if enrollment_state == Some("EXPIRED") {
        return identity_ux_states::ENROLLMENT_EXPIRED;
    }
    if enrollment_state == Some("REJECTED") {
        return identity_ux_states::ENROLLMENT_REJECTED;
    }
    if matches!(
        enrollment_state,
        Some("WAITING_FOR_APPROVAL") | Some("QR_CREATED")
    ) {
        return identity_ux_states::WAITING_FOR_APPROVAL;
    }
    if let Some(state) = enrollment_state {
        if state != "ACTIVE" {
            return identity_ux_states::ENROLLMENT_PENDING;
        }
    }
    if !principal_exists {
        return identity_ux_states::NO_IDENTITY;
    }
    if !local_msk && device_authorized != Some(true) {
        return identity_ux_states::UNAUTHORIZED;
    }
    if device_authorized == Some(false) {
        return identity_ux_states::UNAUTHORIZED;
    }
    if vault_syncing {
        return identity_ux_states::VAULT_SYNCING;
    }
    identity_ux_states::AUTHORIZED
}
