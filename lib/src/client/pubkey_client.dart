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
  const RecoveryEnvelopeBundle({required this.vekEnvelope, this.aekEnvelope});

  final ExportEnvelope vekEnvelope;

  /// Present only when the recovery code was set up with
  /// [RecoveryScopes.full] scope.
  final ExportEnvelope? aekEnvelope;

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
        dio = dio ?? createPubkeyDio();

  final CryptoProvider crypto;
  final Vault? vault;
  final PgpEngine pgpEngine;
  final SmimeEngine smimeEngine;
  final String readBaseUrl;
  final String writeBaseUrl;
  final Dio dio;
  final String sdkName;
  final String sdkVersion;

  final Random _random = Random.secure();

  String _randomNonce() {
    final bytes = Uint8List.fromList(
      List<int>.generate(16, (_) => _random.nextInt(256)),
    );
    return encodeBase64Url(bytes);
  }

  Future<dynamic> enrollMsk({
    required String email,
    required List<int> mskPublicKey,
  }) {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/msk/enroll'),
      method: 'POST',
      body: {
        'email': canonical,
        'msk': {
          'algorithm': mskAlgorithm,
          'public_key': encodeBase64Url(mskPublicKey),
        },
      },
    );
  }

  Future<dynamic> verifyEnroll({
    required String email,
    required String otp,
    Object? captcha,
    String? sha256,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final emailHash = sha256 ?? emailSha256Hex(canonical);
    final proof = await _signOperation(
      operation: Operations.armMsk,
      principal: principal,
      payload: const {},
      key: mskKey,
    );
    Map<String, dynamic>? firstDevice;
    if (device != null) {
      firstDevice = await _signDeviceAuthorization(
        email: email,
        mskKey: mskKey,
        device: device,
      );
    }
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/msk/enroll/verify'),
      method: 'POST',
      body: {
        'sha256': emailHash,
        'otp': otp,
        if (captcha != null) 'captcha': captcha,
        'msk_proof': proof,
        if (firstDevice != null) 'first_device': firstDevice,
      },
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<dynamic> replaceMsk({
    required String email,
    required List<int> mskPublicKey,
  }) {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/msk/replace'),
      method: 'POST',
      body: {
        'email': canonical,
        'msk': {
          'algorithm': mskAlgorithm,
          'public_key': encodeBase64Url(mskPublicKey),
        },
      },
    );
  }

  Future<dynamic> verifyReplace({
    required String email,
    required String otp,
    Object? captcha,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final proof = await _signOperation(
      operation: Operations.armReplacementMsk,
      principal: principal,
      payload: const {},
      key: mskKey,
    );
    Map<String, dynamic>? recoveryDevice;
    if (device != null) {
      recoveryDevice = await _signDeviceAuthorization(
        email: email,
        mskKey: mskKey,
        device: device,
      );
    }
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/msk/replace/verify'),
      method: 'POST',
      body: {
        'sha256': emailSha256Hex(canonical),
        'otp': otp,
        'captcha': captcha,
        'msk_proof': proof,
        if (recoveryDevice != null) 'recovery_device': recoveryDevice,
      },
      reconcileReplayAfterConnectionFailure: true,
    );
  }

  Future<dynamic> mutate({
    required String email,
    required String operation,
    required Object payload,
    required KeyRef mskKey,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final envelope = await _signOperation(
      operation: operation,
      principal: principal,
      payload: payload,
      key: mskKey,
    );
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/mutate'),
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
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
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
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
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
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
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
    String? sha256,
    String? purpose,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    final resolved =
        capabilities ?? await discoveryCapabilities(capabilityPolicy);
    final hash = sha256 ??
        (email == null
            ? null
            : emailSha256Hex(requireCanonicalEmail(normalizeEmail(email))));
    if (hash == null || hash.isEmpty) {
      throw PubkeyException(
        ErrorCodes.principalMismatch,
        'sha256 of the canonical email is required',
      );
    }
    final params = <String, dynamic>{
      'sha256': hash,
      'capabilities': jsonEncode(resolved),
    };
    if (purpose != null && purpose.isNotEmpty) params['purpose'] = purpose;
    final query = params.entries
        .map(
          (e) =>
              '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent('${e.value}')}',
        )
        .join('&');
    return pubkeyRequest(dio, joinUrl(readBaseUrl, '/v1/keys?$query'));
  }

  /// Percent-encoded mailbox path segment for `/v1/mailboxes/{mailbox}/…`.
  String encodeMailboxPath(String mailbox) =>
      Uri.encodeComponent(requireCanonicalEmail(normalizeEmail(mailbox)));

  /// Public Discovery Document for [mailbox] (read host).
  Future<DiscoveryDocument> discoverMailbox(String mailbox) async {
    final path = '/v1/mailboxes/${encodeMailboxPath(mailbox)}';
    final data = await pubkeyRequest(dio, joinUrl(readBaseUrl, path));
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
        'Discovery document response was not a JSON object',
      );
    }
    return DiscoveryDocument.fromJson(Map<String, dynamic>.from(data));
  }

  /// List public resources for [mailbox] (read host).
  Future<List<DiscoveryResource>> listResources(String mailbox) async {
    final path = '/v1/mailboxes/${encodeMailboxPath(mailbox)}/resources';
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
    final path = '/v1/mailboxes/${encodeMailboxPath(mailbox)}/resources';
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
    final path = '/v1/mailboxes/${encodeMailboxPath(mailbox)}/operations';
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
    final path = '/v1/mailboxes/${encodeMailboxPath(mailbox)}/challenges';
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
        '/v1/mailboxes/${encodeMailboxPath(mailbox)}/challenges/${Uri.encodeComponent(challengeId)}/responses';
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
        '/v1/mailboxes/${encodeMailboxPath(mailbox)}/challenges/${Uri.encodeComponent(challengeId)}';
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
    if (!useGenericChallenges) {
      return enrollMsk(email: email, mskPublicKey: mskPublicKey);
    }
    return createChallenge(
      mailbox: email,
      type: ChallengeTypes.emailOtpV1,
      purpose: OperationTypes.mskEnrollV1,
      input: {
        'msk': {
          'algorithm': mskAlgorithm,
          'publicKey': encodeBase64Url(mskPublicKey),
        },
      },
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
    required String email,
    required String deviceName,
    required String requestedTier,
    required Uint8List bPakeElement,
    required String deviceId,
    int expiresIn = 300,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/pairing/$sessionId'),
      method: 'POST',
      body: {
        'email': canonical,
        'device_name': deviceName,
        'requested_tier': requestedTier,
        'b_pake_element': encodeBase64Url(bPakeElement),
        'device_id': deviceId,
        'expires_in': expiresIn,
      },
    );
    return Map<String, dynamic>.from(result as Map);
  }

  /// Polls a pairing mailbox. Used by both A
  /// (fetching the pending request, and afterward just checking for
  /// COMPLETED) and B (polling for A's response).
  ///
  /// [retrieverDeviceId] is what lets the server tell these two callers
  /// apart — the request otherwise carries no such field, since both
  /// devices authenticate with the same identity's email hash. Only B's own
  /// poll should ever pass this (its own device id, matching what it
  /// registered at session creation): doing so is what allows it to
  /// consume the one-time RESPONDED envelope. A's poll must leave this
  /// `null` — passing it (or B's id) here would let A's routine status
  /// check accidentally steal B's one-time retrieval before B ever sees it,
  /// which is exactly the race this parameter exists to prevent.
  Future<PairingSessionStatus> getPairingSession({
    required String sessionId,
    required String emailSha256Hex,
    String? retrieverDeviceId,
  }) async {
    final query = StringBuffer(
      'email_sha256=${Uri.encodeQueryComponent(emailSha256Hex)}',
    );
    if (retrieverDeviceId != null) {
      query.write(
        '&retriever_device_id=${Uri.encodeQueryComponent(retrieverDeviceId)}',
      );
    }
    final result = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/pairing/$sessionId?$query'),
    );
    return PairingSessionStatus.fromJson(
        Map<String, dynamic>.from(result as Map));
  }

  /// Device A delivers the wrapped envelope(s). Envelope
  /// contents are opaque to the server ("does not validate or
  /// inspect the envelope contents") — this call only relays ciphertext and
  /// public keys, never raw VEK/AEK (Boundary B2).
  Future<Map<String, dynamic>> respondToPairingSession({
    required String sessionId,
    required String emailSha256Hex,
    required Uint8List aPakeElement,
    required WrappedKey vekEnvelope,
    WrappedKey? aekEnvelope,
    required WrappedKey confirmationTag,
    required Uint8List mskSignature,
  }) async {
    final result = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/pairing/$sessionId/response'),
      method: 'PUT',
      body: {
        'email_sha256': emailSha256Hex,
        'a_pake_element': encodeBase64Url(aPakeElement),
        'vek_envelope': vekEnvelope.toJson(),
        if (aekEnvelope != null) 'aek_envelope': aekEnvelope.toJson(),
        'confirmation_tag': confirmationTag.toJson(),
        'msk_signature': encodeBase64Url(mskSignature),
      },
    );
    return Map<String, dynamic>.from(result as Map);
  }

  Future<Uint8List> fetchArmedMskPublicKey({required String email}) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(readBaseUrl, '/v1/vault/${emailSha256Hex(canonical)}/current'),
    ) as Map;
    final record = result['vault'];
    final raw = record is Map
        ? record['msk_public_key']
        : result['msk_public_key'];
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
      operation: Operations.revokeDevice,
      payload: {'device_id': deviceId},
      mskKey: mskKey,
    );
  }

  Future<dynamic> beginIdentityRecovery({
    required String email,
    required List<int> mskPublicKey,
  }) {
    return replaceMsk(email: email, mskPublicKey: mskPublicKey);
  }

  Future<dynamic> replaceMasterSigningKey({
    required String email,
    required String otp,
    Object? captcha,
    required KeyRef mskKey,
    Map<String, dynamic>? device,
  }) {
    return verifyReplace(
      email: email,
      otp: otp,
      captcha: captcha,
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
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
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
      final response = await mutate(
        email: email,
        operation: Operations.vaultUpload,
        payload: {
          'generation': nextGeneration,
          'previous_generation_hash': previousGenerationHash == null
              ? null
              : encodeBase64Url(previousGenerationHash),
          'ciphertext_hash': encodeBase64Url(ciphertextHash),
          'ciphertext': encodeBase64Url(ciphertext),
          'nonce': encodeBase64Url(iv),
          'uploading_device': uploadingDevice,
          'msk_signature': encodeBase64Url(recordSignature),
          'timestamp': timestamp,
          if (mutationKind != null) 'mutation_kind': mutationKind,
          if (targetDeviceId != null) 'target_device_id': targetDeviceId,
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
  /// Deliberately unauthenticated (no MSK-signed request envelope, unlike
  /// every other client call): a device that just finished
  /// pairing holds VEK (and maybe AEK) but has no live MSK signing
  /// capability yet — MSK only exists *inside* the vault content this call
  /// fetches, so requiring a signed request here would be circular. Instead
  /// the server returns `msk_public_key` (the identity's current armed
  /// public key, independent of this ciphertext) alongside the record, and
  /// this method verifies `msk_signature` against *that* — never against
  /// anything derived from the ciphertext being verified.
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
  Future<int?> downloadCurrentVault({
    required String email,
    required Vault vault,
    required Uint8List vek,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final record = await _fetchAndVerifyVaultRecord(
      path: '/v1/vault/${emailSha256Hex(canonical)}/current',
      principal: principal,
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
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final record = await _fetchAndVerifyVaultRecord(
      path: '/v1/vault/${emailSha256Hex(canonical)}/generation/$generation',
      principal: principal,
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
  }) async {
    final result = await pubkeyRequest(dio, joinUrl(readBaseUrl, path)) as Map;
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
      protocolVersion: protocolVersion,
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
  Future<List<PendingHighRiskMutation>> fetchPendingHighRiskMutations({
    required String email,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(
        readBaseUrl,
        '/v1/vault/${emailSha256Hex(canonical)}/pending-mutations',
      ),
    ) as Map;
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
      operation: Operations.setRecoveryEnvelope,
      payload: {
        'vek_envelope': vekEnvelope.toJson(),
        if (aekEnvelope != null) 'aek_envelope': aekEnvelope.toJson(),
      },
      mskKey: mskKey,
    );
  }

  /// The OTP request half — mirrors
  /// [enrollMsk]/[replaceMsk]'s "create pending state, then email an OTP"
  /// shape, but this OTP only gates a *read* ([fetchRecoveryEnvelope]), it
  /// never arms anything by itself.
  Future<dynamic> requestRecoveryEnvelopeOtp({required String email}) {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/recovery/envelope/otp'),
      method: 'POST',
      body: {'email': canonical},
    );
  }

  /// Verifies [otp] (fresh, single-use — same
  /// gate `verifyEnroll`/`verifyReplace` already use, see
  /// `mskService.ts`/`otpService.ts`) and, only if it's valid, returns the
  /// REK-wrapped envelope(s) for this identity. **OTP alone is not
  /// sufficient to decrypt anything** — the caller still needs the actual
  /// recovery code to derive REK and unwrap what this returns (deliberate
  /// defense-in-depth: "this is intentional... not a mistake").
  /// Throws [ErrorCodes.recoveryEnvelopeNotFound] if no recovery code was
  /// ever set up for this identity.
  Future<RecoveryEnvelopeBundle> fetchRecoveryEnvelope({
    required String email,
    required String otp,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/recovery/envelope/fetch'),
      method: 'POST',
      body: {
        'sha256': emailSha256Hex(canonical),
        'otp': otp,
      },
    );
    return RecoveryEnvelopeBundle.fromJson(
        Map<String, dynamic>.from(result as Map));
  }

  /// OTP-only identity recovery:
  /// fetches only the current generation number + ciphertext hash for
  /// hash-chain continuation ("continuing the identity's generation
  /// counter, not resetting to 1") — deliberately does **not** decrypt,
  /// verify the record's `msk_signature`, or otherwise trust/use its
  /// content. By the time OTP-only recovery reaches this call, the
  /// identity's currently-armed MSK is already the *new* post-recovery key
  /// (`verifyReplace` already ran) — the old record still on the server was
  /// signed by whichever MSK generation was active when it was originally
  /// uploaded, so verifying its signature against the *new* armed key here
  /// would incorrectly fail, and would be pointless regardless, since
  /// nothing about this call's purpose needs to trust or access old vault
  /// content (the invariant: OTP proof must never unlock a previous
  /// generation). Returns `null` if no generation exists yet for this
  /// identity (recovery still proceeds — see [PubkeyClient.uploadVault]'s
  /// own "first upload" branch).
  Future<VaultGenerationInfo?> fetchCurrentVaultGenerationInfo({
    required String email,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(
        readBaseUrl,
        '/v1/vault/${emailSha256Hex(canonical)}/current',
      ),
    ) as Map;
    final record = result['vault'];
    if (record is! Map) {
      return null;
    }
    return VaultGenerationInfo(
      generation: record['generation'] as int,
      ciphertextHash: decodeBase64Url(record['ciphertext_hash'] as String),
    );
  }

  /// Before generating anything,
  /// client checks: does a recoverable VEK/AEK exist via a recovery-code
  /// path? — this is that check. Deliberately unauthenticated
  /// (a device attempting OTP-only recovery has no live authorized session
  /// yet to sign this with) and reveals only existence, never envelope
  /// contents (Boundary B2/B5).
  Future<bool> hasRecoveryEnvelope({required String email}) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final result = await pubkeyRequest(
      dio,
      joinUrl(
        readBaseUrl,
        '/v1/recovery/envelope-exists/${emailSha256Hex(canonical)}',
      ),
    ) as Map;
    return result['exists'] == true;
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  Future<Map<String, dynamic>> _signDeviceAuthorization({
    required String email,
    required KeyRef mskKey,
    required Map<String, dynamic> device,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
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
    );
    return {...envelope, 'payload': payload};
  }

  Future<dynamic> getMe({
    required String email,
    required KeyRef mskKey,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);
    final envelope = await _signOperation(
      operation: Operations.getMe,
      principal: principal,
      payload: const {},
      key: mskKey,
    );
    return pubkeyRequest(
      dio,
      joinUrl(writeBaseUrl, '/v1/me'),
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
  }) async {
    if (key == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'MSK KeyRef is required to sign this request',
      );
    }
    timestamp ??= DateTime.now().millisecondsSinceEpoch;
    nonce ??= _randomNonce();
    final bytes = canonicalSignedBytes(
      protocolVersion: protocolVersion,
      operation: operation,
      principal: principal,
      timestamp: timestamp,
      nonce: nonce,
      payload: payload,
    );
    final signature = await crypto.sign(key, bytes);
    return {
      'protocol_version': protocolVersion,
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
