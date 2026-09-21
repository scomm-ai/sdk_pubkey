/// Stable machine-readable pubkey protocol error codes.
abstract final class ErrorCodes {
  static const invalidSignature = 'invalid_signature';
  static const unknownPrincipal = 'unknown_principal';
  static const masterKeyNotArmed = 'master_key_not_armed';
  static const masterKeyReplacementRequiresOtp =
      'master_key_replacement_requires_otp';
  static const timestampOutOfWindow = 'timestamp_out_of_window';
  static const nonceReplayed = 'nonce_replayed';
  static const unsupportedProtocolVersion = 'unsupported_protocol_version';
  static const unsupportedAlgorithm = 'unsupported_algorithm';
  static const invalidPublicKey = 'invalid_public_key';
  static const invalidProofOfPossession = 'invalid_proof_of_possession';
  static const keyIdConflict = 'key_id_conflict';
  static const capabilityMismatch = 'capability_mismatch';
  static const otpInvalid = 'otp_invalid';
  static const otpExpired = 'otp_expired';
  static const principalMismatch = 'principal_mismatch';
  static const emailNotCanonical = 'email_not_canonical';
  static const invalidEmail = 'invalid_email';
  static const vaultConflict = 'vault_conflict';
  static const vaultIntegrity = 'vault_integrity';
  static const providerUnavailable = 'provider_unavailable';
  static const hardwareProtectionUnavailable =
      'hardware_protection_unavailable';
  static const keyNotFound = 'key_not_found';
  static const keyNotExportable = 'key_not_exportable';
  static const keyImportFailure = 'key_import_failure';
  static const vaultLocked = 'vault_locked';
  static const vaultCorrupt = 'vault_corrupt';
  static const vaultAuthenticationFailure = 'vault_authentication_failure';
  static const vaultRevisionConflict = 'vault_revision_conflict';
  static const signatureFailure = 'signature_failure';
  static const serverSignatureRejection = 'server_signature_rejection';
  static const replayRejection = 'replay_rejection';
  static const clockSkew = 'clock_skew';
  static const protocolVersionMismatch = 'protocol_version_mismatch';
  static const deviceNotAuthorized = 'device_not_authorized';
  static const deviceRevoked = 'device_revoked';
  static const enrollmentExpired = 'enrollment_expired';
  static const enrollmentReplayed = 'enrollment_replayed';
  static const enrollmentRejected = 'enrollment_rejected';
  static const enrollmentCommitmentMismatch = 'enrollment_commitment_mismatch';
  static const otpNotDeviceEnrollment = 'otp_not_device_enrollment';
  static const mskEnvelopeMissing = 'msk_envelope_missing';
  static const unsupportedStructureVersion = 'unsupported_structure_version';
  static const envelopeAuthenticationFailure =
      'envelope_authentication_failure';
  static const passphraseRecoveryUnsupported =
      'passphrase_recovery_unsupported';

  // Device pairing — server-side pairing mailbox error codes.
  static const pairingSessionNotFound = 'pairing_session_not_found';
  static const pairingSessionExpired = 'pairing_session_expired';
  static const pairingSessionAlreadyResponded =
      'pairing_session_already_responded';
  static const pairingTierMismatch = 'pairing_tier_mismatch';
  static const pairingIdentityMismatch = 'pairing_identity_mismatch';
  static const pairingProtocolUnsupported = 'pairing_protocol_unsupported';
  static const pairingPasswordMismatch = 'pairing_password_mismatch';
  static const pairingSignatureInvalid = 'pairing_signature_invalid';

  // Active-encryption-key promotion.
  static const encryptionKeyAdvertisementFailed =
      'encryption_key_advertisement_failed';

  // Offline vault export/import file format.
  static const vaultExportFormatUnsupported = 'vault_export_format_unsupported';

  // Recovery code setup/recovery.
  static const recoveryEnvelopeNotFound = 'recovery_envelope_not_found';

  // Historical key retention & re-import.
  static const vaultGenerationNotFound = 'vault_generation_not_found';

  static const List<String> all = [
    invalidSignature,
    unknownPrincipal,
    masterKeyNotArmed,
    masterKeyReplacementRequiresOtp,
    timestampOutOfWindow,
    nonceReplayed,
    unsupportedProtocolVersion,
    unsupportedAlgorithm,
    invalidPublicKey,
    invalidProofOfPossession,
    keyIdConflict,
    capabilityMismatch,
    otpInvalid,
    otpExpired,
    principalMismatch,
    emailNotCanonical,
    invalidEmail,
    vaultConflict,
    vaultIntegrity,
    providerUnavailable,
    hardwareProtectionUnavailable,
    keyNotFound,
    keyNotExportable,
    keyImportFailure,
    vaultLocked,
    vaultCorrupt,
    vaultAuthenticationFailure,
    vaultRevisionConflict,
    signatureFailure,
    serverSignatureRejection,
    replayRejection,
    clockSkew,
    protocolVersionMismatch,
    envelopeAuthenticationFailure,
    passphraseRecoveryUnsupported,
    pairingSessionNotFound,
    pairingSessionExpired,
    pairingSessionAlreadyResponded,
    pairingTierMismatch,
    pairingIdentityMismatch,
    pairingProtocolUnsupported,
    pairingPasswordMismatch,
    pairingSignatureInvalid,
    encryptionKeyAdvertisementFailed,
    vaultExportFormatUnsupported,
    recoveryEnvelopeNotFound,
    vaultGenerationNotFound,
  ];
}

/// True for server codes that mean this exact signed envelope was already
/// accepted within the nonce replay TTL ([nonceReplayTtlMs]).
bool isPubkeyReplayRejection(String code) =>
    code == ErrorCodes.nonceReplayed || code == ErrorCodes.replayRejection;

/// Typed SDK / protocol failure with a machine-readable [code].
class PubkeyException implements Exception {
  PubkeyException(
    this.code,
    this.message, {
    this.status,
    this.serverTime,
  });

  final String code;
  final String message;
  final int? status;
  final Object? serverTime;

  bool get isReplayRejection => isPubkeyReplayRejection(code);

  factory PubkeyException.fromResponse(int status, Object? body) {
    if (body is Map) {
      final nested = body['error'];
      if (nested is Map) {
        return PubkeyException(
          nested['code']?.toString() ??
              body['code']?.toString() ??
              'server_error',
          nested['message']?.toString() ??
              body['message']?.toString() ??
              'Pubkey request failed ($status)',
          status: status,
          serverTime: nested['details'] is Map
              ? (nested['details'] as Map)['server_time'] ?? body['server_time']
              : body['server_time'],
        );
      }
      return PubkeyException(
        body['error']?.toString() ??
            body['code']?.toString() ??
            'server_error',
        body['message']?.toString() ?? 'Pubkey request failed ($status)',
        status: status,
        serverTime: body['server_time'],
      );
    }
    return PubkeyException(
      'server_error',
      'Pubkey request failed ($status)',
      status: status,
    );
  }

  @override
  String toString() => 'PubkeyException($code): $message';
}
