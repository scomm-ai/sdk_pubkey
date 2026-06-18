import 'dart:convert';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:uuid/uuid.dart';

import '../auth/pubkey_session.dart';
import '../auth/pubkey_session_wiring.dart';
import '../auth/signed_request_builder.dart';
import '../models/account_check.dart';
import '../models/key_list_item.dart';
import 'pubkey_read_client.dart';
import 'pubkey_write_client.dart';

/// High-level facade over read/write pubkey HTTP clients.
class PubkeyClient {
  PubkeyClient({
    required this.crypto,
    PubkeyReadClient? readClient,
    PubkeyWriteClient? writeClient,
    SignedRequestBuilder? signedRequestBuilder,
  })  : _payloadSigner = PubkeyPayloadSigner(crypto),
        signedRequests = signedRequestBuilder ??
            SignedRequestBuilder(payloadSigner: PubkeyPayloadSigner(crypto)),
        read = readClient ??
            PubkeyReadClient(
              signedRequestBuilder: signedRequestBuilder ??
                  SignedRequestBuilder(payloadSigner: PubkeyPayloadSigner(crypto)),
            ),
        write = writeClient ??
            PubkeyWriteClient(
              signedRequestBuilder: signedRequestBuilder ??
                  SignedRequestBuilder(payloadSigner: PubkeyPayloadSigner(crypto)),
            );

  final CryptoSdk crypto;
  final PubkeyReadClient read;
  final PubkeyWriteClient write;
  final PubkeyPayloadSigner _payloadSigner;
  final SignedRequestBuilder signedRequests;

  PubkeySession? _session;

  /// Active session (after OTP or set explicitly).
  PubkeySession? get session => _session;

  void setSession(PubkeySession session) => _session = session;

  Future<AccountCheckResult> checkAccount(String email) =>
      read.checkAccount(email);

  Future<void> sendOtp(String email) => write.sendOtp(email);

  Future<PubkeySession> verifyOtp({
    required String email,
    required String otp,
  }) async {
    final s = await write.verifyOtp(email: email, otp: otp);
    _session = s;
    return s;
  }

  /// Lists keys and updates session signing identity when possible.
  Future<List<KeyListItem>> listMyKeys({
    required CryptoKey signingPrivateKey,
    String? passphrase,
    String? preferKeyId,
    String? sigFamily,
  }) async {
    var session = _requireSession();
    if (session.sigFamily == null && sigFamily != null) {
      session = session.copyWith(sigFamily: sigFamily);
    }
    if (session.sigFamily == null) {
      throw StateError(
        'session.sigFamily required — set on session or pass sigFamily',
      );
    }
    final keys = await read.listKeys(
      session: session,
      signingPrivateKey: signingPrivateKey,
      signedRequestBuilder: signedRequests,
      passphrase: passphrase,
    );
    _session = session.withSigningKeyFromList(keys, preferKeyId: preferKeyId);
    return keys;
  }

  Future<Map<String, dynamic>> getBlob({
    required String keyId,
    CryptoKey? signingPrivateKey,
    String? passphrase,
  }) {
    final session = _requireSession();
    return read.getBlob(
      session: session,
      keyId: keyId,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<List<KeyListItem>> listRecoverableKeys() {
    final session = _requireSession();
    if (!session.hasFetchToken) {
      throw StateError('FetchToken required for listRecoverableKeys');
    }
    return read.listRecoverableKeys(session: session);
  }

  /// Builds upload payload map with fresh `timestamp` and `jti`.
  Map<String, Object?> newUploadPayload({
    required String email,
    required String publicKey,
    required String algorithm,
    Map<String, dynamic>? encryptedBlob,
    bool discoverable = true,
    String? label,
    bool hasRecoveryPhrase = false,
    String? challengeId,
  }) {
    return {
      'email': email.trim().toLowerCase(),
      'publicKey': publicKey,
      'algorithm': algorithm,
      if (encryptedBlob != null) 'encryptedBlob': encryptedBlob,
      'discoverable': discoverable,
      if (label != null) 'label': label,
      'hasRecoveryPhrase': hasRecoveryPhrase,
      if (challengeId != null) 'challengeId': challengeId,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };
  }

  /// Full upload orchestration from a [CryptoKeyPair].
  Future<Map<String, dynamic>> uploadKeyPair({
    required CryptoKeyPair keyPair,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? backupPassword,
    String? catalogHint,
    String? label,
    bool discoverable = true,
    bool hasRecoveryPhrase = false,
    String? passphrase,
    bool useSignedAuth = false,
    CryptoKey? httpSigningPrivateKey,
    String? httpPassphrase,
  }) async {
    final session = _requireSession();
    final catalog = await PubkeyKeyMapper.catalogNameForPublicKey(
      crypto,
      keyPair.publicKey,
      catalogHint: catalogHint,
    );

    Map<String, dynamic>? blob;
    if (backupPassword != null && backupPassword.isNotEmpty) {
      blob = await PubkeyUploadSupport.buildEncryptedBlob(
        privateKeyBytes: crypto.exportPrivateKey(key: keyPair.privateKey),
        email: session.email,
        catalogName: catalog,
        backupPassword: backupPassword,
      );
    }

    final publicKey = PubkeyUploadSupport.publicKeyWireString(
      crypto,
      keyPair.publicKey,
    );

    if (PubkeyAlgorithmCatalog.requiresDecryptProof(catalog)) {
      return uploadKeyDecryptChallenge(
        keyPair: keyPair,
        publicKey: publicKey,
        algorithm: catalog,
        encryptedBlob: blob,
        label: label,
        discoverable: discoverable,
        hasRecoveryPhrase: hasRecoveryPhrase,
        passphrase: passphrase,
        useSignedAuth: useSignedAuth,
        httpSigningPrivateKey: httpSigningPrivateKey,
        httpPassphrase: httpPassphrase,
      );
    }

    return uploadKeySelfSigned(
      publicKey: publicKey,
      algorithm: catalog,
      encryptedBlob: blob,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      label: label,
      discoverable: discoverable,
      hasRecoveryPhrase: hasRecoveryPhrase,
      passphrase: passphrase,
      useSignedAuth: useSignedAuth,
      httpSigningPrivateKey: httpSigningPrivateKey,
      httpPassphrase: httpPassphrase,
    );
  }

  /// Upload payload with self-signature proof.
  Future<Map<String, dynamic>> uploadKeySelfSigned({
    required String publicKey,
    required String algorithm,
    Map<String, dynamic>? encryptedBlob,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? label,
    bool discoverable = true,
    bool hasRecoveryPhrase = false,
    String? passphrase,
    bool useSignedAuth = false,
    CryptoKey? httpSigningPrivateKey,
    String? httpPassphrase,
  }) async {
    final session = _requireSession();
    final payload = newUploadPayload(
      email: session.email,
      publicKey: publicKey,
      algorithm: algorithm,
      encryptedBlob: encryptedBlob,
      label: label,
      discoverable: discoverable,
      hasRecoveryPhrase: hasRecoveryPhrase,
    );
    final payloadJson = jsonEncode(payload);
    final signature = await _payloadSigner.signPayloadString(
      payloadString: payloadJson,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );

    final authKey = httpSigningPrivateKey ?? signingPrivateKey;
    final authPassphrase = httpSigningPrivateKey != null
        ? httpPassphrase
        : passphrase;

    final Map<String, dynamic> result;
    if (useSignedAuth || !session.hasFetchToken) {
      final signedSession = session.sigFamily != null
          ? session
          : session.copyWith(sigFamily: sigFamily);
      result = await write.uploadKeySigned(
        session: signedSession,
        payloadJson: payloadJson,
        signatureBase64: signature,
        signingPrivateKey: authKey,
        passphrase: authPassphrase,
      );
    } else {
      result = await write.uploadKeyWithFetchToken(
        session: session,
        payloadJson: payloadJson,
        signatureBase64: signature,
      );
    }

    _session = session
        .copyWith(sigFamily: sigFamily)
        .applyUploadResult(result);
    return result;
  }

  /// Decrypt-challenge upload for encrypt-only keys (cv25519, S/MIME RSA, …).
  Future<Map<String, dynamic>> uploadKeyDecryptChallenge({
    required CryptoKeyPair keyPair,
    required String publicKey,
    required String algorithm,
    Map<String, dynamic>? encryptedBlob,
    String? label,
    bool discoverable = true,
    bool hasRecoveryPhrase = false,
    String? passphrase,
    bool useSignedAuth = false,
    CryptoKey? httpSigningPrivateKey,
    String? httpPassphrase,
  }) async {
    final session = _requireSession();
    final authKey = httpSigningPrivateKey ?? keyPair.privateKey;
    final authPassphrase = httpSigningPrivateKey != null
        ? httpPassphrase
        : passphrase;
    final challengeBody = {
      'email': session.email,
      'algorithm': algorithm,
      'publicKey': publicKey,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };

    final challenge = await write.issueUploadChallenge(
      session: session,
      body: challengeBody,
      signingPrivateKey: useSignedAuth || !session.hasFetchToken
          ? authKey
          : null,
      passphrase: authPassphrase,
    );

    final challengeResponse =
        await PubkeyDecryptChallenge.decryptChallengeResponse(
      sdk: crypto,
      privateKey: keyPair.privateKey,
      ciphertextBase64Url: challenge['ciphertext'] as String,
      passphrase: passphrase,
    );

    final payload = newUploadPayload(
      email: session.email,
      publicKey: publicKey,
      algorithm: algorithm,
      encryptedBlob: encryptedBlob,
      label: label,
      discoverable: discoverable,
      hasRecoveryPhrase: hasRecoveryPhrase,
      challengeId: challenge['challengeId'] as String,
    );
    final payloadJson = jsonEncode(payload);

    final Map<String, dynamic> result;
    if (useSignedAuth || !session.hasFetchToken) {
      result = await write.uploadKeySigned(
        session: session.copyWith(
          sigFamily: PubkeyKeyMapper.sigFamilyForCatalog(algorithm),
        ),
        payloadJson: payloadJson,
        signatureBase64: '',
        proofType: 'decrypt_challenge',
        challengeResponse: challengeResponse,
        signingPrivateKey: authKey,
        passphrase: authPassphrase,
      );
    } else {
      result = await write.uploadKeyWithFetchToken(
        session: session,
        payloadJson: payloadJson,
        proofType: 'decrypt_challenge',
        challengeResponse: challengeResponse,
      );
    }

    _session = session.applyUploadResult(result);
    return result;
  }

  Future<Map<String, dynamic>> rotateKey({
    required String oldKeyId,
    required CryptoKeyPair newKeyPair,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? backupPassword,
    String? catalogHint,
    String? label,
    bool hasRecoveryPhrase = false,
    String? passphrase,
  }) async {
    final session = _requireSignedSession();
    final catalog = await PubkeyKeyMapper.catalogNameForPublicKey(
      crypto,
      newKeyPair.publicKey,
      catalogHint: catalogHint,
    );
    final publicKey = PubkeyUploadSupport.publicKeyWireString(
      crypto,
      newKeyPair.publicKey,
    );

    Map<String, dynamic>? blob;
    if (backupPassword != null && backupPassword.isNotEmpty) {
      blob = await PubkeyUploadSupport.buildEncryptedBlob(
        privateKeyBytes: crypto.exportPrivateKey(key: newKeyPair.privateKey),
        email: session.email,
        catalogName: catalog,
        backupPassword: backupPassword,
      );
    }

    final rotationPayload = {
      'oldKeyId': oldKeyId,
      'newPublicKey': publicKey,
      'algorithm': catalog,
      if (blob != null) 'newEncryptedBlob': blob,
      if (label != null) 'label': label,
      'hasRecoveryPhrase': hasRecoveryPhrase,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };
    final rotationJson = jsonEncode(rotationPayload);
    final signature = await _payloadSigner.signPayloadString(
      payloadString: rotationJson,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );

    return write.rotateKey(
      session: session,
      rotationPayloadJson: rotationJson,
      signatureBase64: signature,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> archiveKey({
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) =>
      write.updateStatus(
        session: _requireSignedSession(),
        keyId: keyId,
        status: 'archived',
        signingPrivateKey: signingPrivateKey,
        passphrase: passphrase,
      );

  Future<Map<String, dynamic>> revokeKey({
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) =>
      write.updateStatus(
        session: _requireSignedSession(),
        keyId: keyId,
        status: 'revoked',
        signingPrivateKey: signingPrivateKey,
        passphrase: passphrase,
      );

  Future<Map<String, dynamic>> cancelRevocation({
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) =>
      write.cancelRevocation(
        session: _requireSignedSession(),
        keyId: keyId,
        signingPrivateKey: signingPrivateKey,
        passphrase: passphrase,
      );

  Future<Map<String, dynamic>> updatePreference({
    required String keyId,
    bool? isPreferred,
    bool? discoverable,
    String? label,
    bool? hasRecoveryPhrase,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    final body = <String, dynamic>{
      if (isPreferred != null) 'isPreferred': isPreferred,
      if (discoverable != null) 'discoverable': discoverable,
      if (label != null) 'label': label,
      if (hasRecoveryPhrase != null) 'hasRecoveryPhrase': hasRecoveryPhrase,
    };
    return write.updatePreference(
      session: _requireSignedSession(),
      keyId: keyId,
      body: body,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> updateBlob({
    required String keyId,
    required Map<String, dynamic> newBlob,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    final session = _requireSignedSession();
    final payload = {
      'keyId': keyId,
      'intent': 'update_blob',
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };
    final payloadJson = jsonEncode(payload);
    final signature = await _payloadSigner.signPayloadString(
      payloadString: payloadJson,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );
    return write.updateBlob(
      session: session,
      keyId: keyId,
      newBlob: newBlob,
      payloadJson: payloadJson,
      signatureBase64: signature,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> confirmRecoveryPhrase({
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) =>
      write.confirmRecoveryPhrase(
        session: _requireSignedSession(),
        keyId: keyId,
        signingPrivateKey: signingPrivateKey,
        passphrase: passphrase,
      );

  Future<Map<String, dynamic>> deleteKey({
    required String keyId,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    final session = _requireSignedSession();
    final payload = {
      'keyId': keyId,
      'intent': 'permanent_delete',
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };
    final payloadJson = jsonEncode(payload);
    final signature = await _payloadSigner.signPayloadString(
      payloadString: payloadJson,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );
    return write.deleteKey(
      session: session,
      keyId: keyId,
      payloadJson: payloadJson,
      signatureBase64: signature,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> recoverKey({
    required String keyId,
    CryptoKey? signingPrivateKey,
    String? passphrase,
  }) =>
      write.recoverKey(
        session: _requireSession(),
        keyId: keyId,
        signingPrivateKey: signingPrivateKey,
        passphrase: passphrase,
      );

  PubkeySession _requireSession() {
    final session = _session;
    if (session == null) {
      throw StateError('Call verifyOtp first or setSession');
    }
    return session;
  }

  PubkeySession _requireSignedSession() {
    final session = _requireSession();
    if (session.sigFamily == null) {
      throw StateError('session.sigFamily required for signed requests');
    }
    return session;
  }
}
