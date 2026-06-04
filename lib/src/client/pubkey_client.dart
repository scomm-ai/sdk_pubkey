import 'dart:convert';

import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:uuid/uuid.dart';

import '../auth/pubkey_session.dart';
import '../auth/signed_request_builder.dart';
import '../models/account_check.dart';
import '../models/key_list_item.dart';
import 'pubkey_read_client.dart';
import 'pubkey_write_client.dart';

/// High-level facade over read/write pubkey HTTP clients.
class PubkeyClient {
  PubkeyClient({
    required CryptoSdk crypto,
    PubkeyReadClient? readClient,
    PubkeyWriteClient? writeClient,
  })  : read = readClient ?? PubkeyReadClient(),
        write = writeClient ?? PubkeyWriteClient(),
        _payloadSigner = PubkeyPayloadSigner(crypto),
        signedRequests = SignedRequestBuilder(
          payloadSigner: PubkeyPayloadSigner(crypto),
        );

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

  Future<void> sendOtp(String email) async {
    await write.sendOtp(email);
  }

  Future<PubkeySession> verifyOtp({
    required String email,
    required String otp,
  }) async {
    final s = await write.verifyOtp(email: email, otp: otp);
    _session = s;
    return s;
  }

  /// Upload payload with self-signature proof using the current FetchToken session.
  Future<Map<String, dynamic>> uploadKeySelfSigned({
    required Map<String, Object?> payload,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    final session = _session;
    if (session == null || !session.hasFetchToken) {
      throw StateError('Call verifyOtp first or setSession with a fetchToken');
    }

    final payloadJson = jsonEncode(payload);
    final signature = await _payloadSigner.signPayloadString(
      payloadString: payloadJson,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );

    return write.uploadKeyWithFetchToken(
      session: session,
      payloadJson: payloadJson,
      signatureBase64: signature,
    );
  }

  Future<List<KeyListItem>> listMyKeys({
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) async {
    final session = _session;
    if (session == null || session.sigFamily == null) {
      throw StateError('session with sigFamily required for signed list');
    }
    return read.listKeys(
      session: session,
      signingPrivateKey: signingPrivateKey,
      signedRequestBuilder: signedRequests,
      passphrase: passphrase,
    );
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
  }) {
    return {
      'email': email.trim().toLowerCase(),
      'publicKey': publicKey,
      'algorithm': algorithm,
      if (encryptedBlob != null) 'encryptedBlob': encryptedBlob,
      'discoverable': discoverable,
      if (label != null) 'label': label,
      'hasRecoveryPhrase': hasRecoveryPhrase,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': const Uuid().v4(),
    };
  }
}
