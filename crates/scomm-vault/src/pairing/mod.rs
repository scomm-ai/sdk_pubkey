//! Pairing mailbox: CPace v2 + protocol helpers + host flow.

pub mod cpace;
pub mod pairing_flow;
pub mod pairing_protocol;

pub use cpace::{cpace_finish, cpace_respond, cpace_start, CPaceInitiator, CPaceResponse};
pub use pairing_flow::{
    approve_pairing, fetch_pairing_request, start_pairing, PairingCompleted, PairingOffer,
    PendingPairing,
};
pub use pairing_protocol::{
    hkdf_sha256, PairingBox, PairingProtocol, PairingUri, PAIRING_TIER,
    PAIRING_TYPED_PASSWORD_LENGTH, PAIRING_URI_SCHEME, PAIRING_URI_VERSION,
};
