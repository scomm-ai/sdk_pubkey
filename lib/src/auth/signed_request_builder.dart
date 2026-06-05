import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:uuid/uuid.dart';

import '../http/pubkey_http.dart';
import 'pubkey_session.dart';

/// Builds `X-Auth-Payload` and `X-Auth-Signature` for pubkey signed requests.
class SignedRequestBuilder {
  SignedRequestBuilder({
    required PubkeyPayloadSigner payloadSigner,
    Uuid? uuid,
  })  : _payloadSigner = payloadSigner,
        _uuid = uuid ?? const Uuid();

  final PubkeyPayloadSigner _payloadSigner;
  final Uuid _uuid;

  /// Headers to merge into a dio request. [jsonBody] must be the exact bytes sent.
  Future<Map<String, String>> buildHeaders({
    required PubkeySession session,
    required String method,
    required String path,
    required String jsonBody,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) async {
    final sigFamily = session.sigFamily;
    if (sigFamily == null) {
      throw ArgumentError('session.sigFamily is required for signed requests');
    }

    final payloadMap = <String, Object?>{
      'email': session.email,
      'method': method.toUpperCase(),
      'path': path,
      'bodyHash': sha256HexOfUtf8Body(jsonBody),
      'timestamp': DateTime.now().millisecondsSinceEpoch,
      'jti': _uuid.v4(),
      'sigAlgorithm': sigFamily,
    };

    final payloadB64 = encodeJsonBase64Url(payloadMap);
    // Server verifies the signature over the raw X-Auth-Payload header value.
    final signatureB64 = await _payloadSigner.signAuthHeaderPayload(
      payloadB64: payloadB64,
      signingPrivateKey: signingPrivateKey,
      sigFamily: sigFamily,
      passphrase: passphrase,
    );

    return {
      'X-Auth-Payload': payloadB64,
      'X-Auth-Signature': signatureB64,
    };
  }
}
