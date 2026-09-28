//! Protocol constants matching Dart `constants.dart` (discovery-relevant subset).

/// Canonical principal is the 64-character identity_id hex.
pub const PROTOCOL_VERSION: i64 = 1;
/// Protocol domain name.
pub const PROTOCOL_NAME: &str = "SComm/Pubkey";
/// Timestamp window (ms).
pub const TIMESTAMP_WINDOW_MS: i64 = 5 * 60 * 1000;
/// Nonce replay TTL (ms).
pub const NONCE_REPLAY_TTL_MS: i64 = TIMESTAMP_WINDOW_MS + 60 * 1000;
/// MSK algorithm wire name for enrollment.
pub const MSK_ALGORITHM: &str = "ed25519";
/// Hybrid MSK: ML-DSA-65 public key concatenated with Ed25519.
pub const MSK_HYBRID: &str = "mldsa65-ed25519";
/// Artifact proof-of-possession operation.
pub const ARTIFACT_POP_OPERATION: &str = "artifact_pop";
/// Device authorization structure version.
pub const DEVICE_AUTHORIZATION_VERSION: i64 = 1;
/// Device key algorithm.
pub const DEVICE_KEY_ALGORITHM: &str = "ed25519";

/// MSK-signed operation names.
pub mod operations {
    /// Enroll MSK (legacy pending).
    pub const ENROLL_MSK: &str = "enroll_msk";
    /// Arm MSK.
    pub const ARM_MSK: &str = "arm_msk";
    /// Replace MSK.
    pub const REPLACE_MSK: &str = "replace_msk";
    /// Arm replacement MSK.
    pub const ARM_REPLACEMENT_MSK: &str = "arm_replacement_msk";
    /// Set keys.
    pub const SET_KEYS: &str = "set_keys";
    /// Set signing key.
    pub const SET_SIGNING_KEY: &str = "set_signing_key";
    /// Request encryption key challenge.
    pub const REQUEST_KEY_CHALLENGE: &str = "request_key_challenge";
    /// Set encryption key.
    pub const SET_ENCRYPTION_KEY: &str = "set_encryption_key";
    /// Retire key.
    pub const RETIRE_KEY: &str = "retire_key";
    /// Update preferences.
    pub const UPDATE_PREFERENCES: &str = "update_preferences";
    /// Authorize device.
    pub const AUTHORIZE_DEVICE: &str = "authorize_device";
}

/// Wire families.
pub mod families {
    /// OpenPGP family on the wire.
    pub const PGP: &str = "pgp";
    /// S/MIME family on the wire.
    pub const SMIME: &str = "smime";
}

/// Discovery / artifact purposes.
pub mod purposes {
    /// Master signing (local).
    pub const MASTER_SIGNING: &str = "master-signing";
    /// Signing (local; not served by discovery).
    pub const SIGNING: &str = "signing";
    /// Verify (gated public key).
    pub const VERIFY: &str = "verify";
    /// Encryption.
    pub const ENCRYPTION: &str = "encryption";
    /// Key agreement.
    pub const KEY_AGREEMENT: &str = "key-agreement";
}

/// Identity UX state strings.
pub mod identity_ux_states {
    /// No existing identity.
    pub const NO_IDENTITY: &str = "no_existing_identity";
    /// Authorized.
    pub const AUTHORIZED: &str = "existing_identity_authorized";
    /// Unauthorized.
    pub const UNAUTHORIZED: &str = "existing_identity_unauthorized";
    /// Enrollment pending.
    pub const ENROLLMENT_PENDING: &str = "enrollment_pending";
    /// Waiting for approval.
    pub const WAITING_FOR_APPROVAL: &str = "waiting_for_previous_device_approval";
    /// Enrollment expired.
    pub const ENROLLMENT_EXPIRED: &str = "enrollment_expired";
    /// Enrollment rejected.
    pub const ENROLLMENT_REJECTED: &str = "enrollment_rejected";
    /// Vault syncing.
    pub const VAULT_SYNCING: &str = "vault_synchronization_in_progress";
    /// OTP required.
    pub const OTP_REQUIRED: &str = "otp_required";
    /// New MSK creating.
    pub const NEW_MSK_CREATING: &str = "new_msk_being_created";
    /// Identity recovered.
    pub const IDENTITY_RECOVERED: &str = "identity_successfully_recovered";
    /// Historical keys unavailable.
    pub const HISTORICAL_KEYS_UNAVAILABLE: &str = "historical_vault_keys_unavailable";
}

/// Mailbox OTP: 64-bit random value as 11 Base62 characters.
pub mod mailbox_otp {
    /// Bit length.
    pub const BITS: u32 = 64;
    /// Character length.
    pub const LENGTH: usize = 11;
    /// Alphabet.
    pub const ALPHABET: &str =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    /// Public product name.
    pub const PUBLIC_PRODUCT_NAME: &str = "Scomm.AI";
    /// From display name.
    pub const FROM_DISPLAY_NAME: &str = "SComm.AI NoReply OTP";

    /// Normalize input: strip `-` / whitespace; empty if invalid.
    pub fn normalize(input: &str) -> String {
        let compact: String = input
            .chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect();
        if compact.len() != LENGTH {
            return String::new();
        }
        if compact.chars().any(|ch| !ALPHABET.contains(ch)) {
            return String::new();
        }
        compact
    }
}
