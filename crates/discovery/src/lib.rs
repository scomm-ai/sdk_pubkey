//! SComm discovery locator, document helpers, and HTTP clients.
//!
//! The mailbox key is SHA-256 of the canonical mailbox UTF-8, lowercase hex.
//! This crate does not evaluate a vault OPRF and does not take a salt.

#![deny(missing_docs)]

mod canonical;
mod config;
mod constants;
mod device;
mod document;
mod errors;
mod grant_v1;
mod http;
mod identity;
mod identity_wire;
mod jcs;
mod locator;
mod mailer;
mod pubkey_client;
mod select;
mod scomm_key_id;
mod signer;
mod types;

#[cfg(feature = "wasm")]
mod wasm_api;

pub use canonical::{
    canonical_signed_bytes, canonical_signed_utf8, decode_base64url, domain_separator,
    encode_base64url, payload_sha256_hex,
};
pub use config::PubkeyConfig;
pub use constants::*;
pub use device::{
    canonicalize_device_authorization, device_authorization_payload, must_not_generate_msk,
    resolve_identity_ux_state,
};
pub use document::{DiscoveryChallenge, DiscoveryDocument, DiscoveryResource};
pub use errors::{is_pubkey_replay_rejection, ErrorCodes, PubkeyError};
pub use grant_v1::{
    parse_grant_v1, parse_grant_v1_text, GrantV1Claims, GRANT_V1_FIELDS, GRANT_V1_HEADER,
};
pub use http::{join_url, pubkey_request, reconciled_from_replay_response, HttpClient};
pub use identity::{
    bytes_to_hex, email_sha256_hex, hex_to_bytes, is_valid_email, normalize_email,
    require_canonical_email, sha256_bytes, sha256_to_uuid_v8, text_to_uuid_v8, uuid_last_16_bits,
};
pub use identity_wire::{
    assert_discovery_wire, assert_no_mailbox_address, assert_pubkey_wire_has_no_mailbox,
    assert_vault_wire, require_identity_id, require_mailbox_sha256, IdentityBinding,
};
pub use jcs::canonicalize_json;
pub use locator::{keys_path, mailbox_path, mailbox_sha256_hex};
pub use mailer::{
    mailer_msk_jkt, MailerClient, MailerIdTokenChallenge, MailerIdTokenConfig,
    MailerIdTokenProvider, MailerIdTokenProviderConfig, MailerOtpGrant, MailerOtpPurpose,
};
pub use pubkey_client::{DiscoveryClient, PubkeyClient, PubkeyClientBuilder, SharedPubkeyClient};
pub use select::{
    algorithm_preference_rank, family_preference_rank, select_best_artifact, Artifact,
    Capabilities, SelectPreferences,
};
pub use scomm_key_id::ScommKeyId;
pub use signer::{require_msk_public_key, Ed25519Signer, MskSigner};
pub use types::{
    AuthorizationProfiles, ChallengeTypes, DiscoveryProtocolContract, DiscoveryTypes,
    OperationTypes,
};
