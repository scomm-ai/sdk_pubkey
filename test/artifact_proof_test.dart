import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

class _ScriptedAdapter implements HttpClientAdapter {
  _ScriptedAdapter(this.handler);

  final Future<ResponseBody> Function(RequestOptions options) handler;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) {
    return handler(options);
  }

  @override
  void close({bool force = false}) {}
}

ResponseBody _jsonOk(Object body) {
  return ResponseBody.fromString(
    jsonEncode(body),
    200,
    headers: {
      Headers.contentTypeHeader: ['application/json'],
    },
  );
}

void main() {
  group('setSigningKeyWithProof', () {
    test('self_signature verifies against the artifact_pop canonical bytes', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final contentKey = await crypto.generateSigningKey('ed25519');

      Map<String, dynamic>? capturedBody;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        capturedBody = (options.data as Map).cast<String, dynamic>();
        return _jsonOk({'key_id': 1, 'status': 'active'});
      });

      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final artifact = {
        'family': 'pgp',
        'purpose': 'signing',
        'algorithm': 'openpgp-ed25519',
        'public_material': encodeBase64Url(contentKey.publicKey!),
      };

      await client.setSigningKeyWithProof(
        email: 'alice@example.com',
        artifact: artifact,
        mskKey: msk,
        contentSigningKey: contentKey,
      );

      final body = capturedBody!;
      expect(body['operation'], Operations.setSigningKey);
      final sentArtifact = (body['payload'] as Map)['artifacts'][0] as Map;
      final selfSignature = sentArtifact['self_signature'] as Map;
      expect(selfSignature['algorithm'], 'openpgp-ed25519');

      // Independently reconstruct what the server checks and verify with the
      // content key's *public* key only (never its private key) — this is
      // exactly the server-side verification shape.
      final popBytes = canonicalSignedBytes(
        protocolVersion: protocolVersion,
        operation: artifactPopOperation,
        principal: body['principal'] as String,
        timestamp: body['timestamp'] as int,
        nonce: body['nonce'] as String,
        payload: {
          'algorithm': artifact['algorithm'],
          'family': artifact['family'],
          'purpose': artifact['purpose'],
          'public_material_sha256': bytesToHex(
            sha256Bytes(decodeBase64Url(artifact['public_material'] as String)),
          ),
        },
      );
      final verified = await crypto.verify(
        contentKey.publicKey!,
        popBytes,
        decodeBase64Url(selfSignature['value'] as String),
        'ed25519',
      );
      expect(verified, isTrue);

      // The self_signature's timestamp/nonce must match the outer MSK
      // envelope's — recompute with a *different* nonce and confirm it no
      // longer verifies, proving the binding is load-bearing.
      final mismatchedBytes = canonicalSignedBytes(
        protocolVersion: protocolVersion,
        operation: artifactPopOperation,
        principal: body['principal'] as String,
        timestamp: body['timestamp'] as int,
        nonce: 'different-nonce',
        payload: {
          'algorithm': artifact['algorithm'],
          'family': artifact['family'],
          'purpose': artifact['purpose'],
          'public_material_sha256': bytesToHex(
            sha256Bytes(decodeBase64Url(artifact['public_material'] as String)),
          ),
        },
      );
      final mismatchedVerified = await crypto.verify(
        contentKey.publicKey!,
        mismatchedBytes,
        decodeBase64Url(selfSignature['value'] as String),
        'ed25519',
      );
      expect(mismatchedVerified, isFalse);
    });

    test('compositePopSigner sends ML-DSA and Ed25519 values', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      Map<String, dynamic>? capturedBody;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        capturedBody = (options.data as Map).cast<String, dynamic>();
        return _jsonOk({'key_id': 1, 'status': 'active'});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      await client.setSigningKeyWithProof(
        email: 'alice@example.com',
        artifact: {
          'family': 'pgp',
          'purpose': 'signing',
          'algorithm': 'openpgp-mldsa65-ed25519',
          'public_material': encodeBase64Url(Uint8List(32)),
        },
        mskKey: msk,
        compositePopSigner: (_) => (
          mldsa: Uint8List.fromList(List.filled(8, 1)),
          ed25519: Uint8List.fromList(List.filled(8, 2)),
        ),
      );
      final sent =
          ((capturedBody!['payload'] as Map)['artifacts'] as List).first as Map;
      final proof = sent['self_signature'] as Map;
      expect(proof['algorithm'], 'openpgp-mldsa65-ed25519');
      expect(proof['value'], isNotEmpty);
      expect(proof['ed25519_value'], isNotEmpty);
    });
  });
}
