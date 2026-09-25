/// Discovery Protocol type / operation / challenge / auth profile URIs.
///
/// Provisional identifiers for protocol `0.2-draft`. Prefer these constants
/// over scattering raw URI strings in application code.
abstract final class DiscoveryTypes {
  static const encryptionKeyV1 =
      'https://discovery.scomm.ai/types/crypto/encryption-key/v1';
  static const signingKeyV1 =
      'https://discovery.scomm.ai/types/crypto/signing-key/v1';
  static const verificationKeyV1 =
      'https://discovery.scomm.ai/types/crypto/verification-key/v1';
  static const preferencesLanguagesV1 =
      'https://discovery.scomm.ai/types/preferences/languages/v1';
}

abstract final class OperationTypes {
  static const mskEnrollV1 =
      'https://discovery.scomm.ai/operations/msk/enroll/v1';
  static const mskReplaceV1 =
      'https://discovery.scomm.ai/operations/msk/replace/v1';
}

abstract final class ChallengeTypes {
  static const emailOtpV1 =
      'https://discovery.scomm.ai/challenges/email-otp/v1';
}

abstract final class AuthorizationProfiles {
  static const mskV1 = 'https://discovery.scomm.ai/auth/msk/v1';
  static const previousMskV1 =
      'https://discovery.scomm.ai/auth/previous-msk/v1';
  static const challengeV1 = 'https://discovery.scomm.ai/auth/challenge/v1';
}

/// Contract pin for the Discovery Protocol this SDK implements.
abstract final class DiscoveryProtocolContract {
  static const protocolVersion = '0.2-draft';
  static const schemaVersion = '1.0';
  static const apiVersion = '1';
}
