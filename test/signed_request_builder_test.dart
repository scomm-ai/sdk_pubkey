import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:uuid/uuid.dart';

import 'package:secmail_pubkey_sdk/src/auth/pubkey_session.dart';
import 'package:secmail_pubkey_sdk/src/auth/signed_request_builder.dart';

/// Records the material passed to [PubkeyPayloadSigner.signAuthHeaderPayload].
class _RecordingPayloadSigner extends PubkeyPayloadSigner {
  _RecordingPayloadSigner() : super(CryptoSdk.initialize());

  String? lastPayloadB64;

  @override
  Future<String> signAuthHeaderPayload({
    required String payloadB64,
    required CryptoKey signingPrivateKey,
    required String sigFamily,
    String? passphrase,
  }) async {
    lastPayloadB64 = payloadB64;
    return 'mock-signature';
  }
}

void main() {
  test('buildHeaders signs the base64url X-Auth-Payload header value', () async {
    final recorder = _RecordingPayloadSigner();
    final builder = SignedRequestBuilder(
      payloadSigner: recorder,
      uuid: const Uuid(),
    );

    final headers = await builder.buildHeaders(
      session: const PubkeySession(
        email: 'user@example.com',
        sigFamily: PubkeySigFamily.openPgp,
      ),
      method: 'GET',
      path: '/keys',
      jsonBody: '',
      signingPrivateKey: CryptoKey(
        algorithm: CryptoAlgorithm.openPgp,
        type: KeyType.privateKey,
        rawBytes: Uint8List(0),
      ),
    );

    expect(headers['X-Auth-Payload'], isNotNull);
    expect(headers['X-Auth-Signature'], 'mock-signature');
    expect(recorder.lastPayloadB64, headers['X-Auth-Payload']);
    expect(headers['X-Auth-Payload']!.contains('='), isFalse);
  });
}
