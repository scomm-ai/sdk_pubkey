import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:dio/dio.dart';

import '../canonical.dart';
import '../config/pubkey_config.dart';
import '../constants.dart';
import '../crypto/capabilities.dart';
import '../crypto/provider.dart';
import '../device.dart';
import '../discovery/document.dart';
import '../discovery/types.dart';
import '../engines/pgp.dart';
import '../engines/smime.dart';
import '../errors.dart';
import '../http/http.dart';
import '../identity.dart';
import '../oprf/identity_oprf.dart';
import 'identity_wire.dart';
import '../vault/device_pairing.dart';
import '../vault/key_hierarchy.dart';
import '../vault/vault.dart';
import '../vault/vault_export.dart';
import '../vault/vault_plaintext.dart';

/// Internal, verified-but-not-yet-decrypted vault record. See
/// [PubkeyClient._fetchAndVerifyVaultRecord].
class _VerifiedVaultRecord {
  const _VerifiedVaultRecord({
    required this.generation,
    required this.ciphertext,
    required this.ciphertextHash,
    required this.nonce,
    required this.previousGenerationHash,
    required this.timestamp,
  });

  final int generation;
  final Uint8List ciphertext;
  final Uint8List ciphertextHash;
  final Uint8List nonce;
  final Uint8List? previousGenerationHash;
  final int timestamp;
}

/// One row from [PubkeyClient.fetchPendingHighRiskMutations]
/// — a high-risk mutation still inside its grace window, before it's either
/// confirmed (window elapsed) or cancelled by some device.
class PendingHighRiskMutation {
  const PendingHighRiskMutation({
    required this.mutationId,
    required this.mutationKind,
    required this.targetDeviceId,
    required this.generation,
    required this.state,
    required this.createdAt,
    required this.confirmAt,
  });

  final String mutationId;

  /// One of [HighRiskMutationKinds]'s values.
  final String mutationKind;

  /// Populated only for [HighRiskMutationKinds.deviceAdd].
  final String? targetDeviceId;
  final int generation;

  /// `"pending"`, `"confirmed"`, or `"cancelled"` — expected to always be
  /// `"pending"` in a list returned by [PubkeyClient.fetchPendingHighRiskMutations],
  /// since that call already filters to still-cancellable rows.
  final String state;
  final String createdAt;
  final String confirmAt;

  factory PendingHighRiskMutation.fromJson(Map<String, dynamic> json) =>
      PendingHighRiskMutation(
        mutationId: json['mutation_id'] as String? ?? '',
        mutationKind: json['mutation_kind'] as String? ?? '',
        targetDeviceId: json['target_device_id'] as String?,
        generation: json['generation'] as int? ?? 0,
        state: json['state'] as String? ?? 'pending',
        createdAt: json['created_at']?.toString() ?? '',
        confirmAt: json['confirm_at']?.toString() ?? '',
      );
}

/// The result of [PubkeyClient.fetchRecoveryEnvelope] —
/// the REK-wrapped VEK (and, for a full-scope setup, AEK) envelope for this
/// identity, plus the KDF params needed to re-derive REK from the user's
/// recovery code. The recovery code itself never travels over the wire in
/// either direction.
class RecoveryEnvelopeBundle {
  const RecoveryEnvelopeBundle({
    required this.vekEnvelope,
    this.aekEnvelope,
    this.vaultId,
    this.vaultReadToken,
  });

  final ExportEnvelope vekEnvelope;
  final ExportEnvelope? aekEnvelope;
  final String? vaultId;
  final String? vaultReadToken;

  bool get isFullScope => aekEnvelope != null;

  factory RecoveryEnvelopeBundle.fromJson(Map<String, dynamic> json) {
    final vekRaw = json['vek_envelope'];
    if (vekRaw is! Map) {
      throw PubkeyException(
        ErrorCodes.recoveryEnvelopeNotFound,
        'Recovery envelope response is missing vek_envelope',
      );
    }
    final aekRaw = json['aek_envelope'];
    return RecoveryEnvelopeBundle(
      vekEnvelope: ExportEnvelope.fromJson(Map<String, dynamic>.from(vekRaw)),
      aekEnvelope: aekRaw is Map
          ? ExportEnvelope.fromJson(Map<String, dynamic>.from(aekRaw))
          : null,
      vaultId: json['vault_id'] as String?,
      vaultReadToken: json['pairing_read_token'] as String?,
    );
  }
}

/// The result of
/// [PubkeyClient.fetchCurrentVaultGenerationInfo] — metadata-only, never
/// decrypted content. See that method's doc comment for why this
/// deliberately carries no signature-verified guarantee.
class VaultGenerationInfo {
  const VaultGenerationInfo({
    required this.generation,
    required this.ciphertextHash,
  });

  final int generation;
  final Uint8List ciphertextHash;
}

/// Headless Pubkey SDK client. Reconstruct from Vault + CryptoProvider per event.
class PubkeyClient {
  PubkeyClient({
    required this.crypto,
    this.vault,
    this.pgpEngine = const UnsupportedPgpEngine(),
    this.smimeEngine = const UnsupportedSmimeEngine(),
    String? readBaseUrl,
    String? writeBaseUrl,
    String? vaultBaseUrl,
    Dio? dio,
    this.sdkName = 'scomm-pubkey-dart',
    this.sdkVersion = '1.2.0',
  })  : readBaseUrl = PubkeyConfig.requireUrl(
          'PUBKEY_READ_BASE_URL',
          readBaseUrl ?? PubkeyConfig.readBaseUrl,
        ),
        writeBaseUrl = PubkeyConfig.requireUrl(
          'PUBKEY_WRITE_BASE_URL',
          writeBaseUrl ?? PubkeyConfig.writeBaseUrl,
        ),
        vaultBaseUrl = _vaultOrigin(
          vaultBaseUrl,
          writeBaseUrl ?? PubkeyConfig.writeBaseUrl,
        ),
        dio = dio ?? createPubkeyDio();

  final CryptoProvider crypto;
  final Vault? vault;
  final PgpEngine pgpEngine;
  final SmimeEngine smimeEngine;
  final String readBaseUrl;
  final String writeBaseUrl;
  final String vaultBaseUrl;

  static String _vaultOrigin(String? explicit, String writeFallback) {
    final configured = (explicit ?? PubkeyConfig.vaultBaseUrl).trim();
    if (configured.isNotEmpty) return configured;
    return writeFallback.trim();
  }

  final Dio dio;

  /// This machine's license-device SKI. Vault upload includes it so the host
  /// can start the per-machine evaluation and enforce the mailbox cap.
  /// Download does not use it.
  static Future<String?> Function()? licenseDeviceIdProvider;
  final String sdkName;
  final String sdkVersion;

  /// Loads `identity_id` / `vault_id` from device storage.
  Future<IdentityBinding?> Function()? loadIdentityBinding;

  /// Loads the persisted device signing key for vault reads.
  Future<KeyRef?> Function()? loadDeviceSigningKey;

  /// One-shot vault read capability. Consumed by the next v2 vault GET.
  String? pendingPairingReadToken;
  String? pendingOtpGrant;

  /// Registered device signing key for steady-state vault reads.
  KeyRef? deviceSigningKey;

  /// Body of an authorized `/current` read, reused by the following
  /// [downloadCurrentVault] so a one-shot pairing token is not spent twice.
  Map<String, dynamic>? _cachedCurrentVaultResponse;

  final Random _random = Random.secure();

  void bindIdentity({String? identityId, String? vaultId}) {
    final id = identityId ?? ('ab' * 32);
    final vault = vaultId ?? ('cd' * 32);
    requireIdentityId(id);
    requireIdentityId(vault);
    loadIdentityBinding = () async => IdentityBinding(
          identityId: id,
          vaultId: vault,
        );
    pendingPairingReadToken ??= 'test-pairing-read';
  }

  Future<IdentityBinding> _requireBinding() async {
    final binding = await loadIdentityBinding?.call();
    if (binding == null || !binding.hasIdentity) {
      throw PubkeyException(
        ErrorCodes.identityRebindRequired,
        'This device has no identity_id yet',
      );
    }
    return binding;
  }

  String _randomNonce() {
    final bytes = Uint8List.fromList(
      List<int>.generate(16, (_) => _random.nextInt(256)),
    );
    return encodeBase64Url(bytes);
  }

  Future<String> _accountPrincipal(String email) async {
    if (email.trim().isEmpty) {
      throw PubkeyException(
        ErrorCodes.invalidEmail,
        'A local mailbox label is required',
      );
    }
    final binding = await _requireBinding();
    return binding.identityId!;
  }

  Future<dynamic> mutate({
    required String email,
    required String operation,
    required Object payload,
    required KeyRef mskKey,
    String? baseUrl,
  }) async {
    final target = (baseUrl ?? writeBaseUrl).trim();
    final principal = await _accountPrincipal(email);
    final envelope = await _signOperation(
      operation: operation,
      principal: principal,
      payload: payload,
      key: mskKey,
      version: protocolVersion,
    );
    return pubkeyRequest(
      dio,
      joinUrl(target, '/v1/mutate'),
      method: 'POST',
      body: envelope,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<dynamic> setKeys({
    required String email,
    required List<dynamic> artifacts,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      operation: Operations.setKeys,
      payload: {'artifacts': artifacts},
      mskKey: mskKey,
    );
  }

  /// Uploads a signing artifact with per-artifact proof-of-possession.
  ///
  /// The server (see openspec `add-artifact-proof-of-possession`) requires a
  /// `self_signature` over `artifact_pop` canonical bytes, signed with the
  /// artifact's *own* private key — separate from the MSK signature that
  /// authorizes the request. [contentSigningKey] must already be imported
  /// into [crypto] (e.g. via `crypto.importPrivateKey`) and match
  /// [artifact]'s `public_material`.
  ///
  /// [artifact] must contain `family`, `purpose` ('signing'), `algorithm`,
  /// and `public_material` (base64url); this method adds `self_signature`.
  Future<dynamic> setSigningKeyWithProof({
    required String email,
    required Map<String, dynamic> artifact,
    required KeyRef mskKey,
    KeyRef? contentSigningKey,
    ({List<int> mldsa, List<int> ed25519}) Function(Uint8List popBytes)?
        compositePopSigner,
  }) async {
    if (contentSigningKey == null && compositePopSigner == null) {
      throw ArgumentError(
        'contentSigningKey or compositePopSigner is required',
      );
    }
    final principal = await _accountPrincipal(email);
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final nonce = _randomNonce();

    final material = decodeBase64Url(artifact['public_material'] as String);
    final popBytes = canonicalSignedBytes(
      protocolVersion: protocolVersion,
      operation: artifactPopOperation,
      principal: principal,
      timestamp: timestamp,
      nonce: nonce,
      payload: {
        'algorithm': artifact['algorithm'],
        'family': artifact['family'],
        'purpose': artifact['purpose'],
        'public_material_sha256': bytesToHex(sha256Bytes(material)),
      },
    );

    late final Map<String, dynamic> selfSignature;
    if (compositePopSigner != null) {
      final dual = compositePopSigner(popBytes);
      selfSignature = {
        'algorithm': artifact['algorithm'],
        'value': encodeBase64Url(dual.mldsa),
        'ed25519_value': encodeBase64Url(dual.ed25519),
      };
    } else {
      final sig = await crypto.sign(contentSigningKey!, popBytes);
      selfSignature = {
        'algorithm': artifact['algorithm'],
        'value': encodeBase64Url(sig),
      };
    }

    final artifactWithProof = {
      ...artifact,
      'self_signature': selfSignature,
    };

    final envelope = await _signOperation(
      operation: Operations.setSigningKey,
      principal: principal,
      payload: {
        'artifacts': [artifactWithProof],
      },
      key: mskKey,
      timestamp: timestamp,
      nonce: nonce,
    );
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/keys/signing'),
      method: 'POST',
      body: envelope,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  /// Requests a decrypt challenge for an encryption/key_agreement artifact
  /// (see openspec `add-artifact-proof-of-possession`'s decrypt-proof
  /// flow): the server wraps a nonce to [publicMaterial] and returns it
  /// for the caller to decrypt with the matching private key.
  ///
  /// Must be followed by [setEncryptionKeyWithProof] over the *same*
  /// underlying HTTP connection — the server pins the challenge to the
  /// HTTP/1.1 keep-alive session (or HTTP/2 session) it was issued on, so
  /// both calls must go through this same [dio] instance without an
  /// intervening reconnect.
  Future<Map<String, dynamic>> requestEncryptionKeyChallenge({
    required String email,
    required String family,
    required String algorithm,
    required String publicMaterial,
    required KeyRef mskKey,
  }) async {
    final principal = await _accountPrincipal(email);
    final envelope = await _signOperation(
      operation: Operations.requestKeyChallenge,
      principal: principal,
      payload: {
        'family': family,
        'algorithm': algorithm,
        'public_material': publicMaterial,
      },
      key: mskKey,
    );
    final result = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/keys/encryption/challenge'),
      method: 'POST',
      body: envelope,
    );
    return Map<String, dynamic>.from(result as Map);
  }

  /// Uploads an encryption/key_agreement artifact with decrypt
  /// proof-of-possession, completing the challenge started by
  /// [requestEncryptionKeyChallenge].
  ///
  /// [artifact] must contain `family`, `purpose` ('encryption' or
  /// 'key_agreement'), `algorithm`, and `public_material` (base64url).
  /// [decryptProof] is `{challenge_id, plaintext}` — the challenge id from
  /// the challenge response, and the base64url-encoded plaintext recovered
  /// by decrypting its `ciphertext`.
  Future<dynamic> setEncryptionKeyWithProof({
    required String email,
    required Map<String, dynamic> artifact,
    required Map<String, dynamic> decryptProof,
    required KeyRef mskKey,
  }) async {
    final principal = await _accountPrincipal(email);
    final envelope = await _signOperation(
      operation: Operations.setEncryptionKey,
      principal: principal,
      payload: {
        'artifacts': [
          {...artifact, 'decrypt_proof': decryptProof},
        ],
      },
      key: mskKey,
    );
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/keys/encryption'),
      method: 'POST',
      body: envelope,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<dynamic> retireKey({
    required String email,
    required int keyId,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      operation: Operations.retireKey,
      payload: {'key_id': keyId},
      mskKey: mskKey,
    );
  }

  Future<dynamic> updatePreferences({
    required String email,
    required Map<String, dynamic> preferences,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      operation: Operations.updatePreferences,
      payload: preferences,
      mskKey: mskKey,
    );
  }

  Future<Map<String, dynamic>> discoveryCapabilities([
    Map<String, String> policy = const {},
  ]) async {
    final mapped = await protocolCapabilitiesFromProvider(crypto, policy, {
      EngineFlags.pgp: pgpEngine.available,
      EngineFlags.pgpPqc: pgpEngine.advertisedAlgorithms.any(
        OpenPgpAlgorithms.isPqcCatalogName,
      ),
      EngineFlags.smime: smimeEngine.available,
      'smime_pqc': smimeEngine.advertisedAlgorithms.any(
        SmimeAlgorithms.isPqcCatalogName,
      ),
    });
    final families = Map<String, List<String>>.from(
      (mapped['families'] as Map).map(
        (key, value) => MapEntry(
          key.toString(),
          [for (final item in value as List) item.toString()],
        ),
      ),
    );
    if (pgpEngine.available && pgpEngine.advertisedAlgorithms.isNotEmpty) {
      families[Families.pgp] = pgpEngine.advertisedAlgorithms;
    }
    if (smimeEngine.available && smimeEngine.advertisedAlgorithms.isNotEmpty) {
      families[Families.smime] = smimeEngine.advertisedAlgorithms;
    }
    return applyCapabilityPolicy({'families': families}, policy);
  }

  Future<dynamic> getBestKey({
    String? email,
    String? identityId,
    String? purpose,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    final sha256 = (identityId != null && identityId.isNotEmpty)
        ? identityId
        : emailSha256Hex(email ?? '');
    return getBestKeyForIdentity(
      identityId: sha256,
      purpose: purpose,
      keyId: keyId,
      capabilities: capabilities,
      capabilityPolicy: capabilityPolicy,
    );
  }

  /// Signing keys are private. Discovery does not store or return them.
  Future<Map<String, dynamic>> getSigningKey({
    String? email,
    String? identityId,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'Signing keys are not served by Discovery',
    );
  }

  /// Gated verification-key fetch. [keyId] is the id of the key that signed.
  Future<Map<String, dynamic>> getVerificationKey({
    String? email,
    String? identityId,
    required String keyId,
  }) async {
    final selected = await getBestKey(
      email: email,
      identityId: identityId,
      purpose: Purposes.verification,
      keyId: keyId,
      capabilities: const {'families': {}},
    );
    if (selected is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Verification key response was not a JSON object',
      );
    }
    return Map<String, dynamic>.from(selected);
  }

  String encodeMailboxSha256Path(String mailboxOrSha256) {
    final sha = _discoveryLocator(mailboxOrSha256);
    requireMailboxSha256(sha);
    return sha;
  }

  String encodeIdentityPath(String identityId) =>
      encodeMailboxSha256Path(identityId);

  String _discoveryLocator(String mailboxOrSha256) {
    if (RegExp(r'^[0-9a-f]{64}$').hasMatch(mailboxOrSha256)) {
      return mailboxOrSha256;
    }
    return emailSha256Hex(mailboxOrSha256);
  }

  /// Public discovery document. The path is `/v1/mailboxes/{locator}`.
  /// The locator is the OPRF identity when the vault can evaluate it, because
  /// published keys are stored under that identity. Otherwise the unsalted
  /// mailbox hash.
  Future<DiscoveryDocument> discoverMailbox(String mailbox) async {
    final sha256 = await _publishedKeyLocator(mailbox);
    final path = '/v1/mailboxes/${encodeMailboxSha256Path(sha256)}';
    final data = await pubkeyRequest(dio, joinUrl(readBaseUrl, path));
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Discovery document response was not a JSON object',
      );
    }
    return DiscoveryDocument.fromJson(Map<String, dynamic>.from(data));
  }

  /// List resources for an identity (read host).
  Future<List<DiscoveryResource>> listResources(String identityId) async {
    final path =
        '/v1/mailboxes/${encodeMailboxSha256Path(identityId)}/resources';
    final data = await pubkeyRequest(dio, joinUrl(readBaseUrl, path));
    if (data is! Map) return const [];
    final list = data['resources'];
    if (list is! List) return const [];
    return [
      for (final item in list)
        if (item is Map)
          DiscoveryResource.fromJson(Map<String, dynamic>.from(item)),
    ];
  }

  /// Create a managed resource (write host). [envelope] is an MSK-signed body
  /// that may also carry `type` / `value` for Discovery resource creates.
  Future<dynamic> createResource({
    required String mailbox,
    required Map<String, dynamic> envelope,
  }) {
    final path = '/v1/mailboxes/${encodeMailboxSha256Path(mailbox)}/resources';
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, path),
      method: 'POST',
      body: envelope,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  /// Execute an MSK-signed operation on the generic operations endpoint.
  Future<dynamic> executeOperation({
    required String mailbox,
    required Map<String, dynamic> envelope,
  }) {
    final path = '/v1/mailboxes/${encodeMailboxSha256Path(mailbox)}/operations';
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, path),
      method: 'POST',
      body: envelope,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  /// Create an email-OTP (or other) challenge.
  Future<DiscoveryChallenge> createChallenge({
    required String mailbox,
    required String type,
    required String purpose,
    Map<String, dynamic>? input,
    String? idempotencyKey,
  }) async {
    final path = '/v1/mailboxes/${encodeMailboxSha256Path(mailbox)}/challenges';
    final body = <String, dynamic>{
      'type': type,
      'purpose': purpose,
      'schemaVersion': DiscoveryProtocolContract.schemaVersion,
      if (input != null) 'input': input,
    };
    final data = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, path),
      method: 'POST',
      body: body,
    );
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Challenge create response was not a JSON object',
      );
    }
    return DiscoveryChallenge.fromJson(Map<String, dynamic>.from(data));
  }

  /// Respond to a challenge (e.g. email OTP code).
  Future<DiscoveryChallenge> respondToChallenge({
    required String mailbox,
    required String challengeId,
    required Map<String, dynamic> response,
  }) async {
    final path =
        '/v1/mailboxes/${encodeMailboxSha256Path(mailbox)}/challenges/${Uri.encodeComponent(challengeId)}/responses';
    final data = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, path),
      method: 'POST',
      body: {'response': response},
    );
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Challenge response was not a JSON object',
      );
    }
    return DiscoveryChallenge.fromJson(Map<String, dynamic>.from(data));
  }

  Future<DiscoveryChallenge> getChallenge({
    required String mailbox,
    required String challengeId,
  }) async {
    final path =
        '/v1/mailboxes/${encodeMailboxSha256Path(mailbox)}/challenges/${Uri.encodeComponent(challengeId)}';
    final data = await pubkeyRequest(dio, joinUrl(writeBaseUrl, path));
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Challenge status response was not a JSON object',
      );
    }
    return DiscoveryChallenge.fromJson(Map<String, dynamic>.from(data));
  }

  /// Compatibility: send mailbox OTP for first-device enroll via challenges API
  /// when [useGenericChallenges] is true; otherwise legacy `/v1/msk/enroll`.
  Future<dynamic> sendOtp({
    required String email,
    required List<int> mskPublicKey,
    bool useGenericChallenges = false,
  }) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'Mailbox OTP is requested from the mailer, not the pubkey host',
    );
  }

  /// Compatibility: verify mailbox OTP. Prefer [verifyEnroll] for full arming.
  Future<DiscoveryChallenge> verifyOtp({
    required String email,
    required String challengeId,
    required String otp,
  }) {
    return respondToChallenge(
      mailbox: email,
      challengeId: challengeId,
      response: {'code': otp},
    );
  }

  Future<dynamic> reportVaultCoverage({
    required String email,
    required KeyRef mskKey,
    required String deviceId,
    required List<String> locators,
    List<String>? fingerprints,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.reportVaultCoverage,
      payload: {
        'device_id': deviceId,
        'locators': locators,
        if (fingerprints != null) 'fingerprints': fingerprints,
      },
      mskKey: mskKey,
    );
  }

  Future<dynamic> requestVaultRecover({required String email}) {
    throw PubkeyException(
      ErrorCodes.otpNotDeviceEnrollment,
      'OTP cannot recover a vault or enroll a device',
    );
  }

  Future<dynamic> verifyVaultRecover({
    required String email,
    required String otp,
  }) {
    return requestVaultRecover(email: email);
  }

  String identityState({
    required bool principalExists,
    bool localMsk = false,
    bool? deviceAuthorized,
    String? enrollmentState,
    String? recoveryState,
    bool vaultSyncing = false,
    bool? historicalKeysAvailable,
  }) {
    return resolveIdentityUxState(
      principalExists: principalExists,
      localMsk: localMsk,
      deviceAuthorized: deviceAuthorized,
      enrollmentState: enrollmentState,
      recoveryState: recoveryState,
      vaultSyncing: vaultSyncing,
      historicalKeysAvailable: historicalKeysAvailable,
    );
  }

  void assertNoSilentMsk({
    required bool principalExists,
    required bool localMsk,
    required bool explicitRecovery,
  }) {
    if (mustNotGenerateMsk(
      principalExists: principalExists,
      localMsk: localMsk,
      explicitRecovery: explicitRecovery,
    )) {
      throw PubkeyException(
        ErrorCodes.masterKeyReplacementRequiresOtp,
        'Existing identity requires device transfer or explicit recovery',
      );
    }
  }

  /// Device B creates a pairing mailbox. [sessionId] is a high-entropy
  /// locator (see `DevicePairing.generateSessionId`) — a path param, not
  /// the CPace password and not part of the body. [deviceId] is B's own
  /// locally-generated device id (from
  /// `SecureVaultStore.ensureDeviceId()`), threaded through purely so A can
  /// later write `DeviceMetadata.deviceId` correctly — B has no
  /// server-issued id of its own. The server stores and echoes this field
  /// back on every subsequent `GET`.
  Future<Map<String, dynamic>> createPairingSession({
    required String sessionId,
    required String identityId,
    required String deviceName,
    required String requestedTier,
    required Uint8List bPakeElement,
    required String deviceId,
    int expiresIn = 300,
  }) {
    return createPairingSessionForIdentity(
      sessionId: sessionId,
      identityId: identityId,
      deviceName: deviceName,
      requestedTier: requestedTier,
      bPakeElement: bPakeElement,
      deviceId: deviceId,
      expiresIn: expiresIn,
    );
  }

  /// Polls a pairing session. No mailbox hash. [retrieverDeviceId] is set
  /// only by device B so device A's status poll cannot consume the envelope.
  Future<PairingSessionStatus> getPairingSession({
    required String sessionId,
    String? retrieverDeviceId,
  }) {
    return getPairingSessionForIdentity(
      sessionId: sessionId,
      retrieverDeviceId: retrieverDeviceId,
    );
  }

  Future<Map<String, dynamic>> respondToPairingSession({
    required String sessionId,
    required String identityId,
    required Uint8List aPakeElement,
    required WrappedKey vekEnvelope,
    WrappedKey? aekEnvelope,
    required WrappedKey confirmationTag,
    required Uint8List mskSignature,
  }) {
    return respondToPairingSessionForIdentity(
      sessionId: sessionId,
      identityId: identityId,
      aPakeElement: aPakeElement,
      vekEnvelope: vekEnvelope,
      aekEnvelope: aekEnvelope,
      confirmationTag: confirmationTag,
      mskSignature: mskSignature,
    );
  }

  /// Authorized `GET /v1/vault/{vault_id}/current`. Caches the body so the
  /// following [downloadCurrentVault] does not spend a one-shot token again.
  Future<Uint8List> fetchArmedMskPublicKey({required String email}) async {
    if (email.trim().isEmpty) {
      throw PubkeyException(
          ErrorCodes.invalidEmail, 'A local mailbox label is required');
    }
    final body =
        await _authorizedVaultGet(operation: Operations.vaultGetCurrent);
    _cachedCurrentVaultResponse = body;
    final raw = body['msk_public_key'] ??
        (body['vault'] is Map
            ? (body['vault'] as Map)['msk_public_key']
            : null);
    if (raw is! String) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'Server did not return an armed MSK public key for this identity',
      );
    }
    return decodeBase64Url(raw);
  }

  Future<dynamic> listDevices({
    required String email,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.listDevices,
      payload: const {},
      mskKey: mskKey,
    );
  }

  Future<dynamic> revokeDevice({
    required String email,
    required String deviceId,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.revokeDevice,
      payload: {'device_id': deviceId},
      mskKey: mskKey,
    );
  }

  Future<dynamic> beginIdentityRecovery({
    required String identityId,
    required List<int> mskPublicKey,
  }) {
    return replaceMskForIdentity(
      identityId: identityId,
      mskPublicKey: mskPublicKey,
    );
  }

  Future<dynamic> replaceMasterSigningKey({
    required String identityId,
    required String otpGrant,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) {
    return verifyReplaceForIdentity(
      identityId: identityId,
      otpGrant: otpGrant,
      mskKey: mskKey,
      device: device,
    );
  }

  /// Uploads the current in-memory vault state as a new,
  /// immutable generation. [vault] must already be unlocked with [vek].
  /// Increments `vault.generation` and chains from `vault.lastCiphertextHash`
  /// (`null` only for the very first upload — genesis). On success, updates
  /// `vault.lastCiphertextHash` to the newly uploaded generation and persists
  /// the vault locally (VEK-wrapped, same as any other local persist).
  ///
  /// Conflict handling (re-fetch, reapply, retry) is not
  /// implemented here; a `vault_revision_conflict` from the server is
  /// surfaced as-is via [PubkeyException].
  ///
  /// [mutationKind]/[targetDeviceId] are optional,
  /// plaintext, client-declared fields: when this upload is a high-risk
  /// mutation (device-add, signing-key rotation, authority grant), the
  /// server cannot infer that itself (the opaque-vault boundary — it
  /// never inspects vault plaintext), so the client honestly declares it
  /// here. This is the same trust level as `device_name`/`requested_tier`
  /// already being client-declared, unverified, in the pairing
  /// flow — a known property of the opaque-vault architecture, not a bug.
  /// [targetDeviceId] is required when [mutationKind] is
  /// [HighRiskMutationKinds.deviceAdd]; omit both for a routine content
  /// mutation.
  Future<Map<String, dynamic>> uploadVault({
    required String email,
    required KeyRef mskKey,
    required Vault vault,
    required Uint8List vek,
    String? uploadingDevice,
    String? mutationKind,
    String? targetDeviceId,
  }) async {
    if (!vault.unlocked) {
      throw PubkeyException(
          ErrorCodes.vaultLocked, 'Vault must be unlocked to upload');
    }
    final binding = await _requireBinding();
    final principal = binding.identityId!;
    final vaultId = binding.vaultId;
    // Genesis already sets vault.generation = 1 locally,
    // before any upload — so the very first upload (lastCiphertextHash still
    // null) sends that generation as-is. Every later upload is a real
    // mutation on top of an already-confirmed generation, so it increments.
    final nextGeneration = vault.lastCiphertextHash == null
        ? vault.generation
        : vault.generation + 1;
    final previousGeneration = vault.generation;
    // The exported plaintext embeds `vault.generation` — it
    // must already be `nextGeneration` before export, or the ciphertext's
    // own internal generation field would be stale by one relative to what
    // this upload signs and claims in the outer envelope. Rolled back below
    // if anything fails before the server actually accepts the upload.
    vault.generation = nextGeneration;
    Map<String, dynamic> exported;
    try {
      exported = await vault.exportVault(vek);
    } catch (_) {
      vault.generation = previousGeneration;
      rethrow;
    }
    final encryption = exported['encryption'] as Map;
    final iv = decodeBase64Url(encryption['iv'] as String);
    final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
    final ciphertextHash = sha256Bytes(ciphertext);
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final previousGenerationHash = vault.lastCiphertextHash;

    final recordSignature = await crypto.sign(
      mskKey,
      canonicalVaultRecordBytes(
        protocolVersion: protocolVersion,
        identityId: principal,
        generation: nextGeneration,
        ciphertextHash: ciphertextHash,
        previousGenerationHash: previousGenerationHash,
        timestamp: timestamp,
        nonce: iv,
      ),
    );

    Map<String, dynamic> result;
    try {
      final licenseDeviceId = (await licenseDeviceIdProvider?.call())?.trim();
      final response = await mutate(
        email: email,
        baseUrl: vaultBaseUrl,
        operation: Operations.vaultUpload,
        payload: {
          'generation': nextGeneration,
          'previous_generation_hash': previousGenerationHash == null
              ? null
              : encodeBase64Url(previousGenerationHash),
          'ciphertext_hash': encodeBase64Url(ciphertextHash),
          'ciphertext': encodeBase64Url(ciphertext),
          'nonce': encodeBase64Url(iv),
          if (vaultId != null) 'vault_id': vaultId,
          'uploading_device': uploadingDevice,
          'msk_signature': encodeBase64Url(recordSignature),
          'timestamp': timestamp,
          if (mutationKind != null) 'mutation_kind': mutationKind,
          if (targetDeviceId != null) 'target_device_id': targetDeviceId,
          if (licenseDeviceId != null && licenseDeviceId.isNotEmpty)
            'license_device_id': licenseDeviceId,
        },
        mskKey: mskKey,
      );
      result = Map<String, dynamic>.from(response as Map);
      // Transport may return [reconciledFromReplayResponse] when the server
      // already accepted this envelope after a dropped connection. Confirm
      // the current vault record matches what we uploaded before committing
      // lastCiphertextHash; if the read path is unreachable, still commit —
      // the replay rejection itself is evidence the write landed.
      if (result['reconciled_from_replay'] == true) {
        try {
          final info = await fetchCurrentVaultGenerationInfo(email: email);
          if (info == null ||
              info.generation != nextGeneration ||
              !_bytesEqual(info.ciphertextHash, ciphertextHash)) {
            vault.generation = previousGeneration;
            throw PubkeyException(
              ErrorCodes.nonceReplayed,
              'Vault upload appeared applied (nonce replay) but the server '
              'record does not match this upload',
            );
          }
        } on PubkeyException catch (e) {
          if (e.code == ErrorCodes.nonceReplayed) rethrow;
          // Leave result as reconciled success; local commit proceeds below.
        }
        result = {
          'generation': nextGeneration,
          'reconciled_from_replay': true,
        };
      }
    } catch (_) {
      vault.generation = previousGeneration;
      rethrow;
    }

    vault.lastCiphertextHash = ciphertextHash;
    await vault.persist(vek);
    return result;
  }

  /// Fetches and applies the server's latest vault generation.
  /// Verifies the record's own `msk_signature` and
  /// integrity-checks `ciphertext_hash` before ever decrypting — a failed
  /// check throws rather than falling back to a weaker path. Returns `null`
  /// if no generation exists yet (nothing uploaded for this identity).
  ///
  /// v1 is unauthenticated: a device that just finished pairing holds VEK
  /// but the MSK lives inside the vault this call fetches, so the old
  /// protocol treated knowledge of the email hash as the capability.
  /// v2 replaces that with a pairing read token, an OTP grant, or a device
  /// signature, and the path is `/v1/vault/{vault_id}/current`.
  ///
  /// Freshness, not single-step chain continuity: a plain pull applies
  /// whichever generation the server reports as current wholesale (it's a
  /// full snapshot, not a diff), and that record's authenticity is already
  /// fully established above — `ciphertext_hash` is checked and
  /// `msk_signature` is verified against the server-supplied
  /// `msk_public_key`, independent of the ciphertext itself. Requiring
  /// `previous_generation_hash` to match this device's own last-known hash
  /// *exactly* (single-step) used to reject this every time a device was
  /// more than one generation behind — the common case whenever another
  /// device made several related vault changes (e.g. publish a key, then
  /// promote it) between two syncs, each a legitimate separate generation.
  /// The only thing actually worth rejecting here is a genuine rollback:
  /// the server offering a generation *older* than one this device already
  /// applied, which should never happen since this endpoint always returns
  /// the latest row (`ORDER BY generation DESC LIMIT 1`) — if it ever does,
  /// something is wrong enough to refuse rather than silently regress.
  /// `GET /v1/vault/{vault_id}/current` with a pairing token, OTP grant,
  /// or device signature. Knowing the mailbox is not a read capability.
  Future<int?> downloadCurrentVault({
    required String email,
    required Vault vault,
    required Uint8List vek,
  }) async {
    final binding = await _requireBinding();
    final vaultId = binding.vaultId;
    if (vaultId == null || vaultId.isEmpty) {
      throw PubkeyException(
        ErrorCodes.identityRebindRequired,
        'This device has no vault_id yet',
      );
    }
    requireIdentityId(binding.identityId!);
    final path = '/v1/vault/$vaultId/current';
    final principal = binding.identityId!;
    final headers = _cachedCurrentVaultResponse == null
        ? await _vaultReadAuthorization(
            identityId: principal,
            vaultId: vaultId,
          )
        : null;
    final recordVersion = protocolVersion;
    final record = await _fetchAndVerifyVaultRecord(
      path: path,
      principal: principal,
      headers: headers,
      recordProtocolVersion: recordVersion,
      acceptedPublicKeys: (Map result) {
        final mskPublicKeyRaw = result['msk_public_key'];
        if (mskPublicKeyRaw is! String) {
          throw PubkeyException(
            ErrorCodes.masterKeyNotArmed,
            'Server did not return an armed MSK public key for this identity',
          );
        }
        return [decodeBase64Url(mskPublicKeyRaw)];
      },
    );
    if (record == null) {
      return null;
    }

    final knownHash = vault.lastCiphertextHash;
    if (knownHash != null && _bytesEqual(knownHash, record.ciphertextHash)) {
      // This device already holds this exact generation — most commonly
      // because it just created it itself (mutateAndUpload sets
      // lastCiphertextHash to the generation it uploaded), so a chain
      // check against its own hash as if it were the *previous* generation
      // would always spuriously fail. Nothing to apply; already in sync.
      return record.generation;
    }
    if (knownHash != null && record.generation < vault.generation) {
      throw PubkeyException(
        ErrorCodes.vaultRevisionConflict,
        'Server reported generation ${record.generation}, older than this '
        'device\'s already-applied generation ${vault.generation}',
      );
    }

    await vault.applyDownloadedGeneration(
      vek: vek,
      iv: record.nonce,
      ciphertext: record.ciphertext,
      ciphertextHash: record.ciphertextHash,
    );
    await vault.persist(vek);
    return record.generation;
  }

  /// Fetches one specific, immutable
  /// historical vault generation by number and decrypts it with [vek] — the
  /// *old* VEK a re-importing device already holds locally, never derived
  /// or fetched here. Returns the decrypted
  /// generation's [VaultEntry] list, or `null` if that generation was never
  /// uploaded (mirrors [downloadCurrentVault]'s "nothing uploaded yet"
  /// convention).
  ///
  /// This method never touches [Vault] state — unlike [downloadCurrentVault],
  /// it does not mutate/persist any `Vault` object, since the caller
  /// (`PubkeyRuntime.reimportHistoricalGeneration`) merges the results into
  /// the *current* generation's vault via a normal, current-MSK-signed
  /// mutation, not by replacing this device's live vault
  /// state with old content (the old MSK/VEK/AEK never
  /// regain authority, they're used only to decrypt old ciphertext locally).
  ///
  /// Signature verification: see `vaultService.getVaultGenerationForEmailHash`'s
  /// doc comment (server side) for the full reasoning. In short, the MSK
  /// that signed this old generation may since have been replaced, and
  /// there is no data linking a `vault_generations` row to a
  /// specific `master_signing_keys` epoch to look one up precisely. The
  /// server instead returns `msk_public_keys` — every public key this
  /// principal has ever legitimately armed (current + all archived) — and
  /// this method accepts the signature if it verifies against ANY of them.
  /// This is intentionally weaker than pinpointing the exact signing epoch,
  /// but it is still a real check: it fails closed for any generation not
  /// actually signed by an MSK this identity once held.
  Future<List<VaultEntry>?> downloadVaultGeneration({
    required String email,
    required int generation,
    required Uint8List vek,
  }) async {
    final located = await _vaultLocation();
    final path = '/v1/vault/${located.vaultId}/generation/$generation';
    final principal = located.identityId;
    final headers = await _vaultReadAuthorization(
      identityId: located.identityId,
      vaultId: located.vaultId,
      operation: Operations.vaultGetGeneration,
      payload: {'generation': generation},
    );
    final recordVersion = protocolVersion;
    final record = await _fetchAndVerifyVaultRecord(
      path: path,
      principal: principal,
      headers: headers,
      recordProtocolVersion: recordVersion,
      acceptedPublicKeys: (Map result) {
        final raw = result['msk_public_keys'];
        final keys = <Uint8List>[
          if (raw is List)
            for (final entry in raw)
              if (entry is String) decodeBase64Url(entry),
        ];
        if (keys.isEmpty) {
          throw PubkeyException(
            ErrorCodes.masterKeyNotArmed,
            'Server did not return any MSK public key to verify this historical generation against',
          );
        }
        return keys;
      },
    );
    if (record == null) {
      return null;
    }

    final plaintext = await KeyHierarchy.decryptVaultCiphertextWithVek(
      crypto,
      vek,
      WrappedKey(iv: record.nonce, ciphertext: record.ciphertext),
    );
    final parsed = jsonDecode(utf8.decode(plaintext));
    if (parsed is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Invalid vault plaintext in historical generation',
      );
    }
    return vaultEntriesFromPlaintextArrays(Map<String, dynamic>.from(parsed));
  }

  /// Shared by [downloadCurrentVault] and [downloadVaultGeneration]: fetches
  /// [path], validates the ciphertext hash, and verifies `msk_signature`
  /// against whichever public key(s) [acceptedPublicKeys] extracts from the
  /// raw response `Map` (a single current key for the former, the
  /// "any key ever armed" list for the latter — see each caller's doc
  /// comment). Returns `null` if the server has no record at [path] at all.
  /// Deliberately does not decrypt — the two callers hold different VEKs and
  /// do different things with the result (mutate `Vault` state in place vs.
  /// return a standalone entry list), so decryption stays their own
  /// responsibility.
  Future<_VerifiedVaultRecord?> _fetchAndVerifyVaultRecord({
    required String path,
    required String principal,
    required List<Uint8List> Function(Map result) acceptedPublicKeys,
    Map<String, String>? headers,
    int recordProtocolVersion = protocolVersion,
  }) async {
    final Map result;
    if (_cachedCurrentVaultResponse != null && path.endsWith('/current')) {
      result = _cachedCurrentVaultResponse!;
      _cachedCurrentVaultResponse = null;
    } else {
      final resultUrl = joinUrl(vaultBaseUrl, path);
      assertPubkeyWireHasNoMailbox(url: resultUrl, body: null);
      result = Map<String, dynamic>.from(
        await pubkeyRequest(dio, resultUrl, headers: headers) as Map,
      );
    }
    final record = result['vault'];
    if (record is! Map) {
      return null;
    }

    final generation = record['generation'] as int;
    final ciphertext = decodeBase64Url(record['ciphertext'] as String);
    final ciphertextHash = decodeBase64Url(record['ciphertext_hash'] as String);
    final actualHash = sha256Bytes(ciphertext);
    if (!_bytesEqual(actualHash, ciphertextHash)) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Downloaded vault ciphertext does not match its claimed hash',
      );
    }
    final candidateKeys = acceptedPublicKeys(record);
    final previousGenerationHashRaw = record['previous_generation_hash'];
    final previousGenerationHash = previousGenerationHashRaw is String
        ? decodeBase64Url(previousGenerationHashRaw)
        : null;
    final nonce = decodeBase64Url(record['nonce'] as String);
    final timestamp = (record['timestamp'] as num).toInt();
    final signature = decodeBase64Url(record['msk_signature'] as String);
    final canonicalBytes = canonicalVaultRecordBytes(
      protocolVersion: recordProtocolVersion,
      identityId: principal,
      generation: generation,
      ciphertextHash: ciphertextHash,
      previousGenerationHash: previousGenerationHash,
      timestamp: timestamp,
      nonce: nonce,
    );
    var verified = false;
    for (final candidate in candidateKeys) {
      if (await crypto.verify(candidate, canonicalBytes, signature)) {
        verified = true;
        break;
      }
    }
    if (!verified) {
      throw PubkeyException(
        ErrorCodes.invalidSignature,
        'Vault record signature is invalid',
      );
    }
    return _VerifiedVaultRecord(
      generation: generation,
      ciphertext: ciphertext,
      ciphertextHash: ciphertextHash,
      nonce: nonce,
      previousGenerationHash: previousGenerationHash,
      timestamp: timestamp,
    );
  }

  /// "Any device fetches this list on its next sync"
  /// — the Owner's no-push-infra decision. Same unauthenticated-by-email
  /// pattern as [downloadCurrentVault]. Returns only mutations still
  /// meaningfully pending (not past their grace window, not cancelled).
  /// v1 lists these with the unsalted mailbox hash and no credential.
  /// v2 requires the same vault-read capability as [downloadCurrentVault].
  Future<List<PendingHighRiskMutation>> fetchPendingHighRiskMutations({
    required String email,
  }) async {
    final located = await _vaultLocation();
    final url = joinUrl(
      vaultBaseUrl,
      '/v1/vault/${located.vaultId}/pending-mutations',
    );
    final headers = await _vaultReadAuthorization(
      identityId: located.identityId,
      vaultId: located.vaultId,
      operation: Operations.vaultGetPendingMutations,
    );
    assertPubkeyWireHasNoMailbox(url: url, body: null);
    final result = await pubkeyRequest(dio, url, headers: headers) as Map;
    final mutations = result['mutations'];
    if (mutations is! List) return const [];
    return mutations
        .map((m) => PendingHighRiskMutation.fromJson(
            Map<String, dynamic>.from(m as Map)))
        .toList();
  }

  /// Cancel endpoint (implemented
  /// as a generic MSK-signed mutate op, same dispatch pattern as
  /// [revokeDevice]/[listDevices] — any currently-registered device may
  /// cancel, not just the device that made the original mutation).
  ///
  /// For a `device_add`-kind mutation, the server also revokes the target
  /// device as part of the same call (its own carve-out: device
  /// revocation itself must never be delayed).
  Future<Map<String, dynamic>> cancelHighRiskMutation({
    required String email,
    required String mutationId,
    required KeyRef mskKey,
  }) async {
    final result = await mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.cancelHighRiskMutation,
      payload: {'mutation_id': mutationId},
      mskKey: mskKey,
    );
    return Map<String, dynamic>.from(result as Map);
  }

  /// This fills a legitimate gap the
  /// Owner directed be filled consistently with the rest of the API surface
  /// — only the *fetch* side, `GET
  /// /recovery/envelope/{identity_id}`, existed before. MSK-signed, dispatched through the
  /// generic `/v1/mutate` operation switch (same pattern as
  /// `uploadVault`/`cancelHighRiskMutation`) — only an already-authorized
  /// device can set/replace a recovery envelope. Setting a new envelope
  /// supersedes any prior one for this identity (server-side upsert): an old
  /// recovery code the user has since discarded shouldn't linger as a valid
  /// attack surface.
  ///
  /// [vekEnvelope]/[aekEnvelope] are [ExportEnvelope]s produced by
  /// [RecoveryCode.wrapForRecovery] — opaque to the server (Boundary B2):
  /// only ciphertext and public KDF params are ever sent, never the
  /// recovery code or the raw VEK/AEK it wraps.
  Future<dynamic> setRecoveryEnvelope({
    required String email,
    required KeyRef mskKey,
    required ExportEnvelope vekEnvelope,
    ExportEnvelope? aekEnvelope,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.setRecoveryEnvelope,
      payload: {
        'vek_envelope': vekEnvelope.toJson(),
        if (aekEnvelope != null) 'aek_envelope': aekEnvelope.toJson(),
      },
      mskKey: mskKey,
    );
  }

  /// MSK-signed upload of a password-wrapped `scomm-vault-export`. The
  /// server stores the JSON opaquely and never unwraps EEK.
  Future<dynamic> setVaultBackup({
    required String email,
    required KeyRef mskKey,
    required String backupJson,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.setVaultBackup,
      payload: {'backup_json': backupJson},
      mskKey: mskKey,
    );
  }

  Future<dynamic> deleteVaultBackup({
    required String email,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      baseUrl: vaultBaseUrl,
      operation: Operations.deleteVaultBackup,
      payload: const {},
      mskKey: mskKey,
    );
  }

  /// OTP-only identity recovery: current generation number and ciphertext
  /// hash, without decrypting. Authorized vault read.
  Future<VaultGenerationInfo?> fetchCurrentVaultGenerationInfo({
    required String email,
  }) async {
    final body = await _authorizedVaultGet(
      operation: Operations.vaultGetCurrent,
    );
    final record = body['vault'];
    if (record is! Map) return null;
    return VaultGenerationInfo(
      generation: record['generation'] as int,
      ciphertextHash: decodeBase64Url(record['ciphertext_hash'] as String),
    );
  }

  Future<Map<String, dynamic>> fetchVaultBackupWithGrant({
    required String identityId,
    required String otpGrant,
  }) async {
    requireIdentityId(identityId);
    final url = joinUrl(vaultBaseUrl, '/v1/vault/backup/fetch');
    final body = {
      'identity_id': identityId,
      'otp_grant': otpGrant,
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    final result = await pubkeyRequest(dio, url, method: 'POST', body: body);
    final map = Map<String, dynamic>.from(result as Map);
    final backup = map['backup'];
    if (backup is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultBackupNotFound,
        'No password backup has been stored for this identity',
      );
    }
    return Map<String, dynamic>.from(backup);
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  Future<({String identityId, String vaultId})> _vaultLocation() async {
    final binding = await _requireBinding();
    final vaultId = binding.vaultId;
    if (vaultId == null || vaultId.isEmpty) {
      throw PubkeyException(
        ErrorCodes.identityRebindRequired,
        'This device has no vault_id yet',
      );
    }
    requireIdentityId(binding.identityId!);
    requireIdentityId(vaultId);
    return (identityId: binding.identityId!, vaultId: vaultId);
  }

  Future<Map<String, dynamic>> _authorizedVaultGet({
    required String operation,
    Object? payload,
    String? pathSuffix,
  }) async {
    final located = await _vaultLocation();
    final suffix = pathSuffix ?? '/current';
    final url = joinUrl(vaultBaseUrl, '/v1/vault/${located.vaultId}$suffix');
    final headers = await _vaultReadAuthorization(
      identityId: located.identityId,
      vaultId: located.vaultId,
      operation: operation,
      payload: payload,
    );
    assertPubkeyWireHasNoMailbox(url: url, body: null);
    return Map<String, dynamic>.from(
      await pubkeyRequest(dio, url, headers: headers) as Map,
    );
  }

  Future<Map<String, String>> _vaultReadAuthorization({
    required String identityId,
    required String vaultId,
    String operation = Operations.vaultGetCurrent,
    Object? payload,
  }) async {
    final pairing = pendingPairingReadToken;
    if (pairing != null && pairing.isNotEmpty) {
      pendingPairingReadToken = null;
      return {'Authorization': 'PairingRead $pairing'};
    }
    final grant = pendingOtpGrant;
    if (grant != null && grant.isNotEmpty) {
      pendingOtpGrant = null;
      return {'Authorization': 'OtpGrant $grant'};
    }
    final deviceKey = deviceSigningKey ?? await loadDeviceSigningKey?.call();
    if (deviceKey != null) deviceSigningKey = deviceKey;
    if (deviceKey == null) {
      throw PubkeyException(
        ErrorCodes.pairingReadTokenInvalid,
        'Vault read needs a pairing token, recovery grant, or device key',
      );
    }
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final nonce = _randomNonce();
    final signedPayload = payload ?? const <String, Object?>{};
    final payloadHash = payloadSha256Hex(signedPayload);
    final canonical = '${domainSeparator(protocolVersion, operation)}\n'
        'principal=$identityId\n'
        'vault_id=$vaultId\n'
        'timestamp=$timestamp\n'
        'nonce=$nonce\n'
        'payload_sha256=$payloadHash\n';
    final signature = await crypto.sign(deviceKey, utf8.encode(canonical));
    final envelope = encodeBase64Url(
      utf8.encode(
        jsonEncode({
          'protocol_version': protocolVersion,
          'principal': identityId,
          'vault_id': vaultId,
          'operation': operation,
          'timestamp': timestamp,
          'nonce': nonce,
          'payload_sha256': payloadHash,
          'signature': encodeBase64Url(signature),
        }),
      ),
    );
    return {'Authorization': 'Device $envelope'};
  }

  Future<String> directoryIdentityId(String email) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final input = utf8.encode(canonical);
    final blinded = oprfBlind(input, random: _random);
    final url = joinUrl(vaultBaseUrl, '/v1/id/oprf/evaluate');
    final body = {'blind': encodeBase64Url(blinded.blindedElement)};
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    final result = await pubkeyRequest(
      dio,
      url,
      method: 'POST',
      body: body,
    );
    if (result is! Map || result['evaluation'] is! String) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'OPRF evaluate response was missing evaluation',
      );
    }
    final output = oprfFinalize(
      input: input,
      blind: blinded.blind,
      evaluatedElement: decodeBase64Url(result['evaluation'] as String),
    );
    return identityIdFromOprfFinalize(output);
  }

  /// Directory lookup. Published keys are stored under the OPRF identity, so
  /// the query uses that identity as `sha256` when the vault can evaluate it.
  Future<dynamic> selectDirectoryKey({
    required String email,
    String? purpose,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    return getBestKeyForIdentity(
      identityId: await _publishedKeyLocator(email),
      purpose: purpose,
      keyId: keyId,
      capabilities: capabilities,
      capabilityPolicy: capabilityPolicy,
    );
  }

  /// OPRF identity for a published key. Falls back to the unsalted mailbox
  /// hash when the vault evaluate endpoint is unreachable.
  Future<String> _publishedKeyLocator(String email) async {
    try {
      return await directoryIdentityId(email);
    } catch (_) {
      return emailSha256Hex(email);
    }
  }

  Future<dynamic> getBestKeyForIdentity({
    required String identityId,
    String? purpose,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    requireMailboxSha256(identityId);
    if (purpose == Purposes.signing) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Signing keys are not served by Discovery',
      );
    }
    final isVerification = purpose == Purposes.verification;
    final hasKeyId = keyId != null && keyId.trim().isNotEmpty;
    if (isVerification && !hasKeyId) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'key_id is required to fetch a verification public key',
      );
    }
    final exact = hasKeyId && isVerification;
    final resolved = exact
        ? (capabilities ?? const <String, dynamic>{'families': {}})
        : (capabilities ?? await discoveryCapabilities(capabilityPolicy));
    final params = <String, String>{
      'sha256': identityId,
      if (!exact || resolved.isNotEmpty)
        'capabilities': jsonEncode(resolved),
      if (purpose != null && purpose.isNotEmpty) 'purpose': purpose,
      if (keyId != null && keyId.trim().isNotEmpty) 'key_id': keyId.trim(),
    };
    final query = params.entries
        .map(
          (e) =>
              '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}',
        )
        .join('&');
    final url = joinUrl(readBaseUrl, '/v1/keys?$query');
    assertPubkeyWireHasNoMailbox(url: url, body: null);
    return pubkeyRequest(dio, url);
  }

  Future<dynamic> enrollMskForIdentity({
    String? email,
    String? identityId,
    String? vaultId,
    required List<int> mskPublicKey,
  }) {
    final directory = email != null && email.trim().isNotEmpty;
    if (!directory) {
      requireIdentityId(identityId ?? '');
      requireIdentityId(vaultId ?? '');
    }
    final url = joinUrl(writeBaseUrl, '/v1/msk/enroll');
    final body = directory
        ? {
            'sha256': emailSha256Hex(email),
            'msk': {
              'algorithm': mskAlgorithm,
              'public_key': encodeBase64Url(mskPublicKey),
            },
          }
        : {
            'identity_id': identityId,
            'vault_id': vaultId,
            'msk': {
              'algorithm': mskAlgorithm,
              'public_key': encodeBase64Url(mskPublicKey),
            },
          };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    return pubkeyRequest(dio, url, method: 'POST', body: body);
  }

  Future<dynamic> verifyEnrollForIdentity({
    String? email,
    String? identityId,
    String? vaultId,
    required String otpGrant,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) async {
    final directorySha =
        email != null && email.trim().isNotEmpty ? emailSha256Hex(email) : null;
    if (directorySha == null) {
      requireIdentityId(identityId ?? '');
      requireIdentityId(vaultId ?? '');
    }
    if (otpGrant.trim().isEmpty) {
      throw PubkeyException(
          ErrorCodes.otpGrantInvalid, 'otp_grant is required');
    }
    final proof = await _signOperation(
      operation: Operations.armMsk,
      principal: directorySha ?? identityId!,
      payload: const {},
      key: mskKey,
      version: protocolVersion,
    );
    Map<String, dynamic>? firstDevice;
    if (device != null && directorySha == null) {
      firstDevice = await _signDeviceAuthorization(
        email: identityId!,
        mskKey: mskKey,
        device: device,
        principalOverride: identityId,
        version: protocolVersion,
      );
    }
    final url = joinUrl(writeBaseUrl, '/v1/msk/enroll/verify');
    final body = directorySha == null
        ? {
            'identity_id': identityId,
            'vault_id': vaultId,
            'otp_grant': otpGrant,
            'msk_proof': proof,
            if (firstDevice != null) 'first_device': firstDevice,
          }
        : {
            'sha256': directorySha,
            'otp_grant': otpGrant,
            'msk_proof': proof,
          };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    // Discovery arms the MSK. The vault host only evaluates the mailbox
    // identity; it does not accept a principal registration. Posting there
    // failed the OTP page after enroll/verify had already returned 200, so
    // the device never stored the key or published a public key.
    return pubkeyRequest(
      dio,
      url,
      method: 'POST',
      body: body,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<dynamic> replaceMskForIdentity({
    required String identityId,
    required List<int> mskPublicKey,
  }) {
    requireIdentityId(identityId);
    final url = joinUrl(writeBaseUrl, '/v1/msk/replace');
    final body = {
      'identity_id': identityId,
      'msk': {
        'algorithm': mskAlgorithm,
        'public_key': encodeBase64Url(mskPublicKey),
      },
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    return pubkeyRequest(dio, url, method: 'POST', body: body);
  }

  Future<dynamic> verifyReplaceForIdentity({
    required String identityId,
    required String otpGrant,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) async {
    requireIdentityId(identityId);
    final proof = await _signOperation(
      operation: Operations.armReplacementMsk,
      principal: identityId,
      payload: const {},
      key: mskKey,
      version: protocolVersion,
    );
    Map<String, dynamic>? recoveryDevice;
    if (device != null) {
      recoveryDevice = await _signDeviceAuthorization(
        email: identityId,
        mskKey: mskKey,
        device: device,
        principalOverride: identityId,
        version: protocolVersion,
      );
    }
    final url = joinUrl(writeBaseUrl, '/v1/msk/replace/verify');
    final body = {
      'identity_id': identityId,
      'otp_grant': otpGrant,
      'msk_proof': proof,
      if (recoveryDevice != null) 'recovery_device': recoveryDevice,
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    return pubkeyRequest(
      dio,
      url,
      method: 'POST',
      body: body,
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<Map<String, dynamic>> createPairingSessionForIdentity({
    required String sessionId,
    required String identityId,
    required String deviceName,
    required String requestedTier,
    required Uint8List bPakeElement,
    required String deviceId,
    int expiresIn = 300,
  }) async {
    requireIdentityId(identityId);
    final url = joinUrl(vaultBaseUrl, '/v1/pairing/$sessionId');
    final body = {
      'identity_id': identityId,
      'device_name': deviceName,
      'requested_tier': requestedTier,
      'b_pake_element': encodeBase64Url(bPakeElement),
      'device_id': deviceId,
      'expires_in': expiresIn,
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    final result = await pubkeyRequest(dio, url, method: 'POST', body: body);
    return Map<String, dynamic>.from(result as Map);
  }

  Future<PairingSessionStatus> getPairingSessionForIdentity({
    required String sessionId,
    String? retrieverDeviceId,
  }) async {
    final query = retrieverDeviceId == null
        ? ''
        : '?retriever_device_id=${Uri.encodeQueryComponent(retrieverDeviceId)}';
    final url = joinUrl(vaultBaseUrl, '/v1/pairing/$sessionId$query');
    assertPubkeyWireHasNoMailbox(url: url, body: null);
    final result = await pubkeyRequest(dio, url);
    return PairingSessionStatus.fromJson(
      Map<String, dynamic>.from(result as Map),
    );
  }

  Future<Map<String, dynamic>> respondToPairingSessionForIdentity({
    required String sessionId,
    required String identityId,
    required Uint8List aPakeElement,
    required WrappedKey vekEnvelope,
    WrappedKey? aekEnvelope,
    required WrappedKey confirmationTag,
    required Uint8List mskSignature,
  }) async {
    requireIdentityId(identityId);
    final url = joinUrl(vaultBaseUrl, '/v1/pairing/$sessionId/response');
    final body = {
      'identity_id': identityId,
      'a_pake_element': encodeBase64Url(aPakeElement),
      'vek_envelope': vekEnvelope.toJson(),
      if (aekEnvelope != null) 'aek_envelope': aekEnvelope.toJson(),
      'confirmation_tag': confirmationTag.toJson(),
      'msk_signature': encodeBase64Url(mskSignature),
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    final result = await pubkeyRequest(dio, url, method: 'PUT', body: body);
    return Map<String, dynamic>.from(result as Map);
  }

  Future<RecoveryEnvelopeBundle> fetchRecoveryEnvelopeWithGrant({
    required String identityId,
    required String otpGrant,
  }) async {
    requireIdentityId(identityId);
    final url = joinUrl(vaultBaseUrl, '/v1/recovery/envelope/fetch');
    final body = {
      'identity_id': identityId,
      'otp_grant': otpGrant,
    };
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    final result = await pubkeyRequest(dio, url, method: 'POST', body: body);
    return RecoveryEnvelopeBundle.fromJson(
      Map<String, dynamic>.from(result as Map),
    );
  }

  String mintVaultId() {
    final bytes = Uint8List.fromList(
      List<int>.generate(32, (_) => _random.nextInt(256)),
    );
    return bytesToHex(bytes);
  }

  Future<Map<String, dynamic>> _signDeviceAuthorization({
    required String email,
    required KeyRef mskKey,
    required Map<String, dynamic> device,
    String? principalOverride,
    int? version,
  }) async {
    final principal = principalOverride ?? (await _accountPrincipal(email));
    final devicePublicKey = device['devicePublicKey'] is String
        ? decodeBase64Url(device['devicePublicKey'] as String)
        : Uint8List.fromList((device['publicKey'] as List<int>?) ?? const []);
    final payload = deviceAuthorizationPayload(
      principalId: principal,
      deviceId: sha256ToUuidV8(sha256Bytes(devicePublicKey)),
      devicePublicKey: encodeBase64Url(devicePublicKey),
      createdAt: DateTime.now().millisecondsSinceEpoch,
      nonce: _randomNonce(),
      deviceName: device['name'] as String?,
    );
    final envelope = await _signOperation(
      operation: Operations.authorizeDevice,
      principal: principal,
      payload: payload,
      key: mskKey,
      version: version,
    );
    return {...envelope, 'payload': payload};
  }

  Future<dynamic> getMe({
    required String email,
    required KeyRef mskKey,
  }) async {
    final principal = await _accountPrincipal(email);
    final envelope = await _signOperation(
      operation: Operations.getMe,
      principal: principal,
      payload: const {},
      key: mskKey,
    );
    // Vault holds MSK + authorized devices after the discovery/vault split.
    return pubkeyRequest(
      dio,
      joinUrl(vaultBaseUrl, '/v1/me'),
      method: 'POST',
      body: envelope,
    );
  }

  Future<Map<String, dynamic>> _signOperation({
    required String operation,
    required String principal,
    required Object payload,
    required KeyRef? key,
    int? timestamp,
    String? nonce,
    int? version,
  }) async {
    if (key == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'MSK KeyRef is required to sign this request',
      );
    }
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    nonce ??= _randomNonce();
    final resolvedVersion = version ?? protocolVersion;
    final bytes = canonicalSignedBytes(
      protocolVersion: resolvedVersion,
      operation: operation,
      principal: principal,
      timestamp: timestamp,
      nonce: nonce,
      payload: payload,
    );
    final signature = await crypto.sign(key, bytes);
    return {
      'protocol_version': resolvedVersion,
      'sdk': {'name': sdkName, 'version': sdkVersion},
      'principal': principal,
      'operation': operation,
      'timestamp': timestamp,
      'nonce': nonce,
      'payload': payload,
      'signature': {
        'algorithm': mskAlgorithm,
        'value': encodeBase64Url(signature),
      },
    };
  }
}
