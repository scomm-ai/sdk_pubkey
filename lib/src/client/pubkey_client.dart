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
import 'identity_wire.dart';

/// Headless discovery-directory client: key publishing, lookups, OTP
/// challenges, and MSK arming. Vault-host routes live in
/// `scomm_vault_client`.
class PubkeyClient {
  PubkeyClient({
    required this.crypto,
    this.pgpEngine = const UnsupportedPgpEngine(),
    this.smimeEngine = const UnsupportedSmimeEngine(),
    String? readBaseUrl,
    String? writeBaseUrl,
    Dio? dio,
    this.sdkName = 'scomm-pubkey-dart',
    this.sdkVersion = '2.0.0',
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

  /// Directory principal. Unsalted SHA-256 of the canonical mailbox.
  Future<String> _accountPrincipal(String email) async {
    if (email.trim().isEmpty) {
      throw PubkeyException(
        ErrorCodes.invalidEmail,
        'A local mailbox label is required',
      );
    }
    return emailSha256Hex(email);
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
  /// artifact's *own* private key â€” separate from the MSK signature that
  /// authorizes the request. [contentSigningKey] must already be imported
  /// into [crypto] (e.g. via `crypto.importPrivateKey`) and match
  /// [artifact]'s `public_material`.
  ///
  /// [artifact] must contain `family`, `purpose` ('verify'), `algorithm`,
  /// and `public_material` (base64url); this method adds `self_signature`.
  /// A local `signing` purpose is rewritten to `verify` before the proof
  /// is signed.
  Future<dynamic> setSigningKeyWithProof({
    required String email,
    required Map<String, dynamic> artifact,
    required KeyRef mskKey,
    KeyRef? contentSigningKey,
    Uint8List Function(Uint8List popBytes)? openpgpPopSigner,
    ({List<int> mldsa, List<int> ed25519}) Function(Uint8List popBytes)?
        compositePopSigner,
  }) async {
    if (contentSigningKey == null &&
        openpgpPopSigner == null &&
        compositePopSigner == null) {
      throw ArgumentError(
        'contentSigningKey, openpgpPopSigner, or compositePopSigner is required',
      );
    }
    final wirePurpose = artifact['purpose'];
    if (wirePurpose == Purposes.signing ||
        wirePurpose == 'signing' ||
        wirePurpose == 'verification') {
      artifact = {...artifact, 'purpose': Purposes.verify};
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
    if (openpgpPopSigner != null) {
      selfSignature = {
        'format': 'openpgp-signature',
        'value': encodeBase64Url(openpgpPopSigner(popBytes)),
      };
    } else if (compositePopSigner != null) {
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
  /// underlying HTTP connection â€” the server pins the challenge to the
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
  /// [decryptProof] is `{challenge_id, plaintext}` â€” the challenge id from
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
    required String keyId,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      operation: Operations.retireKey,
      payload: {'key_id': keyId},
      mskKey: mskKey,
    );
  }

  /// Sets lifecycle `revoked`. Does not withdraw public bytes or destroy
  /// private material.
  Future<dynamic> revokeKey({
    required String email,
    required String keyId,
    required KeyRef mskKey,
    String reason = RevocationReason.unspecified,
  }) {
    return mutate(
      email: email,
      operation: Operations.revokeKey,
      payload: {'key_id': keyId, 'revocation_reason': reason},
      mskKey: mskKey,
    );
  }

  /// Sets publication `withdrawn` and clears directory public bytes.
  /// Lifecycle is unchanged.
  Future<dynamic> withdrawKey({
    required String email,
    required String keyId,
    required KeyRef mskKey,
  }) {
    return mutate(
      email: email,
      operation: Operations.withdrawKey,
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

  /// Gated verify-key fetch. [keyId] is the id of the key that signed.
  /// The locator is the unsalted mailbox hash. The vault OPRF identity is
  /// not a discovery locator.
  Future<Map<String, dynamic>> getVerificationKey({
    String? email,
    String? identityId,
    required String keyId,
  }) async {
    final unsalted = (email != null && email.trim().isNotEmpty)
        ? emailSha256Hex(email)
        : identityId;
    final selected = await getBestKey(
      identityId: unsalted,
      purpose: Purposes.verify,
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

  /// Public discovery document. The path is `/v1/mailboxes/{mailboxSha256}`
  /// where `mailboxSha256` is the unsalted hash of the canonical mailbox.
  Future<DiscoveryDocument> discoverMailbox(String mailbox) async {
    final sha256 = _discoveryLocator(mailbox);
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
      headers: idempotencyKey == null || idempotencyKey.trim().isEmpty
          ? null
          : {'Idempotency-Key': idempotencyKey.trim()},
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
      'Mailbox OTP is requested from the mailer, not the Discovery host',
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

  /// Directory lookup. `sha256` is the unsalted mailbox hash for every purpose.
  Future<dynamic> selectDirectoryKey({
    required String email,
    String? purpose,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    return getBestKeyForIdentity(
      identityId: emailSha256Hex(email),
      purpose: purpose,
      keyId: keyId,
      capabilities: capabilities,
      capabilityPolicy: capabilityPolicy,
    );
  }

  Future<dynamic> getBestKeyForIdentity({
    required String identityId,
    String? purpose,
    String? keyId,
    Map<String, dynamic>? capabilities,
    Map<String, String> capabilityPolicy = const {},
  }) async {
    requireMailboxSha256(identityId);
    if (purpose == Purposes.signing || purpose == 'verification') {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'purpose must be verify',
      );
    }
    final isVerify = purpose == Purposes.verify;
    final hasKeyId = keyId != null && keyId.trim().isNotEmpty;
    if (isVerify && !hasKeyId) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'key_id is required to fetch a verify key',
      );
    }
    final exact = hasKeyId && isVerify;
    final resolved = exact
        ? (capabilities ?? const <String, dynamic>{'families': {}})
        : (capabilities ?? await discoveryCapabilities(capabilityPolicy));
    final params = <String, String>{
      'sha256': identityId,
      if (!exact || resolved.isNotEmpty) 'capabilities': jsonEncode(resolved),
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

  /// The directory no longer stores a pending MSK. This only validates
  /// input; the key is sent with [verifyEnrollForIdentity]. Request the OTP
  /// with the same key so the grant names it (`msk_jkt`).
  @Deprecated('Pass mskPublicKey to MailerClient.requestOtp and verify instead')
  Future<dynamic> enrollMskForIdentity({
    String? email,
    String? identityId,
    String? vaultId,
    required List<int> mskPublicKey,
  }) async {
    final directory = email != null && email.trim().isNotEmpty;
    if (!directory) {
      requireIdentityId(identityId ?? '');
      requireIdentityId(vaultId ?? '');
    }
    _requireMskPublicKey(mskPublicKey);
    return const {'status': 'deferred'};
  }

  static Uint8List _requireMskPublicKey(List<int>? key) {
    if (key == null || (key.length != 32 && key.length != 1984)) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'MSK public key must be 32 bytes (ed25519) or 1984 bytes (mldsa65-ed25519)',
      );
    }
    return Uint8List.fromList(key);
  }

  Map<String, dynamic> _armPayload(KeyRef key, List<int> publicKey) {
    if (key.algorithm != mskHybridAlgorithm) return const {};
    return {
      'algorithm': mskHybridAlgorithm,
      'public_key': encodeBase64Url(publicKey),
    };
  }

  /// Posts a single-call arm. A directory without `/v1/msk/arm` answers 404
  /// for the route; surface that as an upgrade error, not an unknown mailbox.
  Future<dynamic> _postArm(String url, Map<String, dynamic> body) async {
    assertPubkeyWireHasNoMailbox(url: url, body: body);
    try {
      return await pubkeyRequest(
        dio,
        url,
        method: 'POST',
        body: body,
        reconcileReplayAfterConnectionFailure: true,
      );
    } on PubkeyException catch (error) {
      if (error.status == 404 && error.code != ErrorCodes.unknownPrincipal) {
        throw PubkeyException(
          ErrorCodes.directoryUpgradeRequired,
          'The directory host does not support single-call MSK arming',
          status: 404,
        );
      }
      rethrow;
    }
  }

  /// `POST /v1/msk/arm`: grant, MSK, and a proof by that MSK in one call.
  /// [mskPublicKey] defaults to `mskKey.publicKey`.
  Future<dynamic> verifyEnrollForIdentity({
    String? email,
    String? identityId,
    String? vaultId,
    required String otpGrant,
    required KeyRef mskKey,
    List<int>? mskPublicKey,
    Map<String, dynamic>? device,
  }) async {
    final publicKey = _requireMskPublicKey(mskPublicKey ?? mskKey.publicKey);
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
      payload: _armPayload(mskKey, publicKey),
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
    final msk = {
      'algorithm': mskKey.algorithm,
      'public_key': encodeBase64Url(publicKey),
    };
    // Discovery arms the MSK. The vault host only evaluates the mailbox
    // identity; it does not accept a principal registration.
    return _postArm(joinUrl(writeBaseUrl, '/v1/msk/arm'), {
      'identity_id': directorySha ?? identityId,
      if (directorySha == null) 'vault_id': vaultId,
      'otp_grant': otpGrant,
      'msk': msk,
      'msk_proof': proof,
      if (firstDevice != null) 'first_device': firstDevice,
    });
  }

  /// See [enrollMskForIdentity]: no pending state, input check only.
  @Deprecated('Pass mskPublicKey to MailerClient.requestOtp and verify instead')
  Future<dynamic> replaceMskForIdentity({
    required String identityId,
    required List<int> mskPublicKey,
  }) async {
    requireIdentityId(identityId);
    _requireMskPublicKey(mskPublicKey);
    return const {'status': 'deferred'};
  }

  /// `POST /v1/msk/replace/arm`. [mskPublicKey] defaults to
  /// `mskKey.publicKey`.
  Future<dynamic> verifyReplaceForIdentity({
    required String identityId,
    required String otpGrant,
    required KeyRef mskKey,
    List<int>? mskPublicKey,
    Map<String, dynamic>? device,
  }) async {
    requireIdentityId(identityId);
    final publicKey = _requireMskPublicKey(mskPublicKey ?? mskKey.publicKey);
    final proof = await _signOperation(
      operation: Operations.armReplacementMsk,
      principal: identityId,
      payload: _armPayload(mskKey, publicKey),
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
    return _postArm(joinUrl(writeBaseUrl, '/v1/msk/replace/arm'), {
      'identity_id': identityId,
      'otp_grant': otpGrant,
      'msk': {
        'algorithm': mskKey.algorithm,
        'public_key': encodeBase64Url(publicKey),
      },
      'msk_proof': proof,
      if (recoveryDevice != null) 'recovery_device': recoveryDevice,
    });
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
        'algorithm': key.algorithm,
        'value': encodeBase64Url(signature),
      },
    };
  }
}
