/// Canonical `principal` is the 64-character `identity_id` hex.
const int protocolVersion = 1;
const String protocolName = 'SComm/Pubkey';
const int timestampWindowMs = 5 * 60 * 1000;
const int nonceReplayTtlMs = timestampWindowMs + 60 * 1000;
const String mskAlgorithm = 'ed25519';
const int firstKeyId = 1;

/// The `operation` a signing artifact's `self_signature` is computed over
/// (see [PubkeyClient.setSigningKeyWithProof]) — distinct from the outer
/// MSK-signed envelope's own `operation`, but bound to the same
/// timestamp/nonce so the two can't be mixed and matched.
const String artifactPopOperation = 'artifact_pop';

abstract final class Operations {
  static const enrollMsk = 'enroll_msk';
  static const armMsk = 'arm_msk';
  static const replaceMsk = 'replace_msk';
  static const armReplacementMsk = 'arm_replacement_msk';
  static const setKeys = 'set_keys';
  static const setSigningKey = 'set_signing_key';
  static const requestKeyChallenge = 'request_key_challenge';
  static const setEncryptionKey = 'set_encryption_key';
  static const retireKey = 'retire_key';
  static const updatePreferences = 'update_preferences';
  static const getBestKey = 'get_best_key';
  static const getMe = 'get_me';
  static const reportVaultCoverage = 'report_vault_coverage';
  static const authorizeDevice = 'authorize_device';
  static const revokeDevice = 'revoke_device';
  static const listDevices = 'list_devices';
  static const completeDeviceEnrollment = 'complete_device_enrollment';
  static const vaultUpload = 'vault_upload';
  static const vaultGetCurrent = 'vault_get_current';
  static const vaultGetGeneration = 'vault_get_generation';
  static const vaultGetPendingMutations = 'vault_get_pending_mutations';
  static const cancelHighRiskMutation = 'cancel_high_risk_mutation';
  static const setRecoveryEnvelope = 'set_recovery_envelope';
  static const setVaultBackup = 'set_vault_backup';
  static const deleteVaultBackup = 'delete_vault_backup';
}

/// SComm: the user's choice of recovery-code format at setup
/// time (Owner decision).
abstract final class RecoveryCodeFormats {
  static const bip39 = 'bip39';
  static const random = 'random';
}

/// SComm: the user's choice of recovery-envelope scope at
/// setup time (Owner decision). `full` wraps both
/// VEK and AEK; `readOnly` wraps VEK only, so a device recovered with this
/// code can never sign a device-add mutation (no AEK to unwrap MSK with) —
/// same structural read-only rule already enforced for
/// limited-tier devices.
abstract final class RecoveryScopes {
  static const full = 'full';
  static const readOnly = 'read-only';
}

/// SComm: the three mutation kinds a client may honestly
/// declare on a [PubkeyClient.uploadVault] call, so the server can start a
/// grace-period bookkeeping row for it. Omitted entirely for routine content
/// mutations.
abstract final class HighRiskMutationKinds {
  static const deviceAdd = 'device_add';
  static const signingKeyRotation = 'signing_key_rotation';
  static const authorityGrant = 'authority_grant';
}

abstract final class Families {
  static const pgp = 'pgp';
  static const smime = 'smime';

  /// Legacy third envelope. Not accepted on the wire; ignored in capabilities.
  static const pq = 'pq';
}

/// Primitive class inside a family (RSA / ECC / PQC). Not a wire family.
abstract final class AlgorithmClasses {
  static const rsa = 'rsa';
  static const ecc = 'ecc';
  static const pqc = 'pqc';

  /// DSA / ElGamal / classic DH catalog rows.
  static const ffc = 'ffc';
}

/// Engine flags passed into [protocolFamiliesFromPrimitives].
abstract final class EngineFlags {
  static const pgp = 'pgp';
  static const pgpPqc = 'pgp_pqc';
  static const smime = 'smime';
}

/// Directory catalog names for OpenPGP (RFC 4880 classical + RFC 9980 PQC).
abstract final class OpenPgpAlgorithms {
  static const ed25519 = 'openpgp-ed25519';
  static const cv25519 = 'openpgp-cv25519';
  static const mldsa65Ed25519 = 'openpgp-mldsa65-ed25519';
  static const mlkem768X25519 = 'openpgp-mlkem768-x25519';

  /// RFC 9980 public-key algorithm IDs.
  static const rfc9980MlDsa65Ed25519Id = 30;
  static const rfc9980MlKem768X25519Id = 35;

  /// LibrePGP experimental Kyber (incompatible with RFC 9980).
  static const librePgpKyber768X25519Id = 105;
  static const librePgpKyber1024X448Id = 106;

  static const classicalAdvertised = [cv25519, ed25519];

  static bool isRfc9980Id(int id) =>
      id == rfc9980MlDsa65Ed25519Id || id == rfc9980MlKem768X25519Id;

  static bool isLibrePgpKyberId(int id) =>
      id == librePgpKyber768X25519Id || id == librePgpKyber1024X448Id;

  static bool isPqcCatalogName(String? name) {
    if (name == null || name.isEmpty) return false;
    final n = name.trim().toLowerCase();
    return n == mldsa65Ed25519 || n == mlkem768X25519;
  }

  /// Discovery list. RFC 9980 names ship in every build; pass
  /// [rfc9980Ready]: false only for tests that simulate a classical-only client.
  static List<String> advertised({required bool rfc9980Ready}) {
    if (!rfc9980Ready) {
      return List<String>.from(classicalAdvertised);
    }
    return [
      ...classicalAdvertised,
      mldsa65Ed25519,
      mlkem768X25519,
    ];
  }
}

/// Directory catalog names for S/MIME CMS (classical RSA/X25519 + hybrid PQC).
abstract final class SmimeAlgorithms {
  static const rsaOaepSha256 = 'smime-rsa-oaep-sha256';
  static const x25519 = 'smime-x25519';
  static const rsaPssSha256 = 'smime-rsa-pss-sha256';
  static const mlkem768X25519 = 'smime-mlkem768-x25519';
  static const mldsa65 = 'pqc-mldsa65';

  static const classicalAdvertised = [
    rsaOaepSha256,
    x25519,
    rsaPssSha256,
  ];

  static bool isPqcCatalogName(String? name) {
    if (name == null || name.isEmpty) return false;
    final n = name.trim().toLowerCase();
    return n == mlkem768X25519 ||
        n == mldsa65 ||
        n.contains('mlkem') ||
        n.contains('mldsa');
  }

  static List<String> advertised({required bool pqcReady}) {
    if (!pqcReady) {
      return List<String>.from(classicalAdvertised);
    }
    return [
      ...classicalAdvertised,
      mlkem768X25519,
      mldsa65,
    ];
  }
}

abstract final class Purposes {
  static const masterSigning = 'master-signing';
  static const signing = 'signing';
  static const verification = 'verification';
  static const encryption = 'encryption';
  static const keyAgreement = 'key-agreement';
  static const kem = 'kem';
  static const certificate = 'certificate';
  static const authentication = 'authentication';
  static const vaultWrapping = 'vault-wrapping';
  static const deviceSigning = 'device-signing';
}

abstract final class CryptoOperations {
  static const random = 'random';
  static const hash = 'hash';
  static const generateKey = 'generateKey';
  static const importKey = 'importKey';
  static const exportKey = 'exportKey';
  static const sign = 'sign';
  static const verify = 'verify';
  static const deriveSecret = 'deriveSecret';
  static const encrypt = 'encrypt';
  static const decrypt = 'decrypt';
  static const wrapKey = 'wrapKey';
  static const unwrapKey = 'unwrapKey';
}

abstract final class KeyProtection {
  static const software = 'software';
  static const osProtected = 'os-protected';
  static const hardwareBacked = 'hardware-backed';
  static const portableVault = 'portable-vault';
}

abstract final class RequirementLevels {
  static const required = 'required';
  static const preferred = 'preferred';
  static const supported = 'supported';
  static const unavailable = 'unavailable';
}

abstract final class KeyGenerationStatus {
  static const active = 'active';
  static const retired = 'retired';
  static const revoked = 'revoked';
}

abstract final class MskStatus {
  static const pending = 'pending';
  static const armed = 'armed';
  static const replaced = 'replaced';
  static const revoked = 'revoked';
}

const int vaultFormatVersion = 1;
const String vaultKdf = 'pbkdf2-sha256';
const String vaultAead = 'aes-256-gcm';
const int vaultPbkdf2Iterations = 210000;
const int vaultSaltBytes = 16;
const int vaultIvBytes = 12;
const int vaultPepperBytes = 32;

/// SComm: EEK (Export Encryption Key, and REK when that
/// gets there) must be derived via Argon2id — unlike [vaultKdf] (PBKDF2),
/// which is only used by the unrelated, pre-existing single-key
/// `Vault.exportKeyPackage`/`importKeyPackage` feature. Parameters follow
/// OWASP's Argon2id minimum recommendation (>=19 MiB memory, >=2 iterations,
/// parallelism 1) for a device-class (not server-class) target. `memory` is
/// in KiB, matching `package:cryptography`'s `Argon2id.memory` unit.
const String eekKdf = 'argon2id';
const int argon2idDefaultMemoryKib = 19456; // ~19 MiB
const int argon2idDefaultIterations = 3;
const int argon2idDefaultParallelism = 1;
const int eekSaltBytes = 16;

/// SComm: the offline vault export/import file format.
/// [vaultExportKind] is deliberately distinct from `package:ckvf`'s own
/// `format` field value (that package is a separate, pre-existing,
/// unrelated container format also used by this app — see
/// `key_manager_controller.dart`'s `exportLocalVault`/`importLocalVault` —
/// this name exists so the two are never confused if a user has both kinds
/// of file).
const String vaultExportKind = 'scomm-vault-export';
const int vaultExportFormatVersion = 1;
const int deviceAuthorizationVersion = 1;
const int enrollmentQrVersion = 1;
const int enrollmentHandshakeVersion = 1;
const int mskEnvelopeVersion = 1;
const int vaultRecordVersion = 1;
const int enrollmentTtlMs = 5 * 60 * 1000;
const String deviceKeyAlgorithm = 'ed25519';
const String enrollmentKem = 'x25519';
const String enrollmentKemFallback = 'p-256';
const String enrollmentHkdfInfo = 'scomm-enrollment-v1';
const String mskWrapInfo = 'scomm-msk-wrap-v1';
const String vrkWrapInfo = 'scomm-vrk-wrap-v1';

abstract final class EnrollmentState {
  static const created = 'QR_CREATED';
  static const waitingForApproval = 'WAITING_FOR_APPROVAL';
  static const active = 'ACTIVE';
  static const expired = 'EXPIRED';
  static const rejected = 'REJECTED';
}

abstract final class IdentityUxStates {
  static const noIdentity = 'no_existing_identity';
  static const authorized = 'existing_identity_authorized';
  static const unauthorized = 'existing_identity_unauthorized';
  static const enrollmentPending = 'enrollment_pending';
  static const waitingForApproval = 'waiting_for_previous_device_approval';
  static const enrollmentExpired = 'enrollment_expired';
  static const enrollmentRejected = 'enrollment_rejected';
  static const vaultSyncing = 'vault_synchronization_in_progress';
  static const vaultSynchronized = 'vault_synchronized';
  static const deviceRevoked = 'device_revoked';
  static const noPreviousDevice = 'no_authorized_previous_device_available';
  static const recoveryStarted = 'identity_recovery_started';
  static const otpRequired = 'otp_required';
  static const otpInvalid = 'otp_invalid_or_expired';
  static const newMskCreating = 'new_msk_being_created';
  static const identityRecovered = 'identity_successfully_recovered';
  static const historicalKeysUnavailable = 'historical_vault_keys_unavailable';
}

/// Mailbox OTP: 64-bit random value as 11 Base62 characters. Not TOTP.
abstract final class MailboxOtp {
  static const bits = 64;
  static const length = 11;
  static const alphabet =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  static const publicProductName = 'Scomm.AI';
  static const fromDisplayName = 'SComm.AI NoReply OTP';

  static String normalize(String input) {
    final compact = input.replaceAll(RegExp(r'[-\s]'), '');
    if (compact.length != length) return '';
    for (final ch in compact.split('')) {
      if (!alphabet.contains(ch)) return '';
    }
    return compact;
  }
}
