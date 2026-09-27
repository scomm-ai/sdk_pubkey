//! Discovery Protocol type / operation / challenge / auth profile URIs.

/// Resource type URIs.
pub struct DiscoveryTypes;

impl DiscoveryTypes {
    /// Encryption key type.
    pub const ENCRYPTION_KEY_V1: &'static str =
        "https://discovery.scomm.ai/types/crypto/encryption-key/v1";
    /// Verification key type.
    pub const VERIFICATION_KEY_V1: &'static str =
        "https://discovery.scomm.ai/types/crypto/verification-key/v1";
    /// Language preferences type.
    pub const PREFERENCES_LANGUAGES_V1: &'static str =
        "https://discovery.scomm.ai/types/preferences/languages/v1";
}

/// Operation type URIs.
pub struct OperationTypes;

impl OperationTypes {
    /// MSK enroll.
    pub const MSK_ENROLL_V1: &'static str =
        "https://discovery.scomm.ai/operations/msk/enroll/v1";
    /// MSK replace.
    pub const MSK_REPLACE_V1: &'static str =
        "https://discovery.scomm.ai/operations/msk/replace/v1";
}

/// Challenge type URIs.
pub struct ChallengeTypes;

impl ChallengeTypes {
    /// Email OTP challenge.
    pub const EMAIL_OTP_V1: &'static str =
        "https://discovery.scomm.ai/challenges/email-otp/v1";
}

/// Authorization profile URIs.
pub struct AuthorizationProfiles;

impl AuthorizationProfiles {
    /// MSK auth.
    pub const MSK_V1: &'static str = "https://discovery.scomm.ai/auth/msk/v1";
    /// Previous MSK auth.
    pub const PREVIOUS_MSK_V1: &'static str =
        "https://discovery.scomm.ai/auth/previous-msk/v1";
    /// Challenge auth.
    pub const CHALLENGE_V1: &'static str = "https://discovery.scomm.ai/auth/challenge/v1";
}

/// Contract pin for the Discovery Protocol this SDK implements.
pub struct DiscoveryProtocolContract;

impl DiscoveryProtocolContract {
    /// Protocol version string.
    pub const PROTOCOL_VERSION: &'static str = "0.2-draft";
    /// Schema version.
    pub const SCHEMA_VERSION: &'static str = "1.0";
    /// API version.
    pub const API_VERSION: &'static str = "1";
}
