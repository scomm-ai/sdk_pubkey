//! SComm.AI vault-host client: local-first [`KeyVault`], pairing, identity OPRF,
//! pepper POPRF, and vault-host HTTP routes. Container format and slots live in
//! the `ckvf` crate (`scomm_vault` library).

mod authorization;
mod errors;
mod host_pepper_oprf;
mod key_vault;
mod local_vault_store;
mod oprf;
mod pairing;
mod signing;
mod vault_host_client;

pub use authorization::{parse_grant_v1, GrantV1Claims, VaultAuthorization};
pub use errors::VaultClientError;
pub use host_pepper_oprf::{AsyncPepperOprf, HostPepperOprf, LocalPepperOprf, PrecomputedPepperOprf};
pub use key_vault::{
    key_meta_extension_id, open_export, open_host_vault_with_host_pepper,
    open_host_vault_with_secret, recommended_argon2id, verify_record_signature, KeyVault,
    StaticAuthorizer, VaultAuthorizer, VaultDevice, VaultHostBinding, DEVICES_EXTENSION_ID,
    KEY_META_EXTENSION_PREFIX,
};
pub use local_vault_store::{local_vault_keys, LocalVaultStore, MemoryLocalVaultStore};
pub use oprf::{
    identity_blind, identity_blind_evaluate_for_tests, identity_finalize, identity_id_from_output,
    oprf_public_key, pepper_info, poprf_blind, poprf_blind_evaluate, poprf_finalize,
    IdentityBlindState, PoprfBlindState, MODE_OPRF, MODE_POPRF, MODE_VOPRF, OPRF_SUITE,
};
pub use pairing::{
    approve_pairing, cpace_finish, cpace_respond, cpace_start, fetch_pairing_request, hkdf_sha256,
    start_pairing, CPaceInitiator, CPaceResponse, PairingBox, PairingCompleted, PairingOffer,
    PairingProtocol, PairingUri, PendingPairing, PAIRING_TIER, PAIRING_TYPED_PASSWORD_LENGTH,
    PAIRING_URI_SCHEME, PAIRING_URI_VERSION,
};
pub use signing::{
    device_read_authorization, domain_separator, payload_sha256_hex, vault_operations,
    vault_records_signing_text, MskSigner, PROTOCOL_VERSION,
};
pub use vault_host_client::{
    PepperEvaluation, PepperKeyInfo, PepperKeySet, VaultHostApi, VaultHostClient, VaultRead,
    VaultRecord,
};

// Re-export CKVF types apps commonly need alongside this client.
pub use ckvf::{
    PepperKey, PepperOprf, UnlockedVault, VaultContainer, DEVICE_WRAP_METHOD, PASSWORD_OPRF_METHOD,
    RECOVERY_CODE_OPRF_METHOD,
};
