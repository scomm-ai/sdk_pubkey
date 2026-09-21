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

ResponseBody _jsonError(String code, {int status = 409}) {
  return ResponseBody.fromString(
    jsonEncode({'error': code, 'message': code}),
    status,
    headers: {
      Headers.contentTypeHeader: ['application/json'],
    },
  );
}

void main() {
  group('PubkeyClient', () {
    test('initializes headlessly and signs a mutation envelope', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final calls = <RequestOptions>[];
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        calls.add(options);
        return _jsonOk({'key_id': 1});
      });

      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final result = await client.setKeys(
        email: 'alice@example.com',
        artifacts: [
          {
            'family': 'pgp',
            'purpose': 'encryption',
            'algorithm': 'openpgp-cv25519',
            'public_material': 'dGVzdA',
          },
        ],
        mskKey: msk,
      );

      expect(result['key_id'], 1);
      expect(calls, hasLength(1));
      expect(calls.single.uri.toString(), 'https://api.pubkey.test/v1/mutate');
      final body = calls.single.data as Map;
      expect(body['operation'], Operations.setKeys);
      expect(body['principal'], '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      expect(body['signature']['algorithm'], 'ed25519');
      expect(body['signature']['value'], isA<String>());
      expect(body['nonce'], isA<String>());
      expect(body['timestamp'], isA<int>());
    });

    test('sends capability negotiation on GET', () async {
      final crypto = DartCryptoProvider();
      late String seen;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        seen = options.uri.toString();
        return _jsonOk({
          'family': 'smime',
          'key_id': 3,
          'algorithm': 'smime-mlkem-768',
        });
      });

      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final selected = await client.getBestKey(
        email: 'alice@example.com',
        purpose: 'encryption',
        capabilities: {
          'families': {
            'smime': ['smime-mlkem-768'],
          },
        },
      );
      expect(selected['key_id'], 3);
      expect(seen, contains('/v1/keys?'));
      expect(seen, contains('sha256='));
      expect(seen, contains('capabilities='));
      expect(seen, contains('purpose=encryption'));
      expect(seen, isNot(contains('principal=')));
      expect(seen, isNot(contains('email=')));
    });

    test('does not advertise PGP or S/MIME without engines', () async {
      final crypto = DartCryptoProvider();
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
      );
      final caps = await client.discoveryCapabilities();
      expect(caps['families'], isEmpty);
    });

    test('retries connection failures then succeeds', () async {
      final crypto = DartCryptoProvider();
      var attempts = 0;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        attempts += 1;
        if (attempts < 3) {
          throw DioException(
            requestOptions: options,
            type: DioExceptionType.connectionError,
            message: 'The connection errored: Connection failed',
          );
        }
        return _jsonOk({'status': 'ok'});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'http://127.0.0.1:3000',
        writeBaseUrl: 'http://127.0.0.1:3000',
        dio: dio,
      );
      final selected = await client.getBestKey(
        email: 'alice@example.com',
        purpose: 'encryption',
        capabilities: {
          'families': {
            'smime': ['smime-mlkem-768'],
          },
        },
      );
      expect(attempts, 3);
      expect(selected['status'], 'ok');
    });

    test(
      'signed mutate treats nonce_replayed after connection drop as success',
      () async {
        final crypto = DartCryptoProvider();
        final msk = await crypto.generateSigningKey('ed25519');
        var attempts = 0;
        final dio = Dio();
        dio.httpClientAdapter = _ScriptedAdapter((options) async {
          attempts += 1;
          if (attempts == 1) {
            throw DioException(
              requestOptions: options,
              type: DioExceptionType.connectionError,
              message: 'The connection errored: Connection reset',
            );
          }
          return _jsonError(ErrorCodes.nonceReplayed);
        });
        final client = PubkeyClient(
          crypto: crypto,
          readBaseUrl: 'https://pubkey.test',
          writeBaseUrl: 'https://api.pubkey.test',
          dio: dio,
        );

        final result = await client.setKeys(
          email: 'alice@example.com',
          artifacts: [
            {
              'family': 'pgp',
              'purpose': 'encryption',
              'algorithm': 'openpgp-cv25519',
              'public_material': 'dGVzdA',
            },
          ],
          mskKey: msk,
        );

        expect(attempts, 2);
        expect(result['reconciled_from_replay'], isTrue);
        expect(result['ok'], isTrue);
      },
    );

    test(
      'signed mutate still fails on nonce_replayed without a prior drop',
      () async {
        final crypto = DartCryptoProvider();
        final msk = await crypto.generateSigningKey('ed25519');
        final dio = Dio();
        dio.httpClientAdapter = _ScriptedAdapter((options) async {
          return _jsonError(ErrorCodes.nonceReplayed);
        });
        final client = PubkeyClient(
          crypto: crypto,
          readBaseUrl: 'https://pubkey.test',
          writeBaseUrl: 'https://api.pubkey.test',
          dio: dio,
        );

        try {
          await client.setKeys(
            email: 'alice@example.com',
            artifacts: [
              {
                'family': 'pgp',
                'purpose': 'encryption',
                'algorithm': 'openpgp-cv25519',
                'public_material': 'dGVzdA',
              },
            ],
            mskKey: msk,
          );
          fail('expected PubkeyException');
        } on PubkeyException catch (error) {
          expect(error.code, ErrorCodes.nonceReplayed);
          expect(error.isReplayRejection, isTrue);
        }
      },
    );

    test(
      'uploadVault reconciles nonce_replayed after drop and commits hash',
      () async {
        final crypto = DartCryptoProvider();
        final msk = await crypto.generateSigningKey('ed25519');
        final vault = Vault(crypto: crypto);
        await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
        vault.generation = 1;
        final vek = KeyHierarchy.generateVek(crypto);

        var mutateAttempts = 0;
        Uint8List? uploadedHash;
        final dio = Dio();
        dio.httpClientAdapter = _ScriptedAdapter((options) async {
          final path = options.uri.path;
          if (path.endsWith('/v1/mutate')) {
            mutateAttempts += 1;
            final body = options.data as Map;
            final payload = body['payload'] as Map;
            uploadedHash =
                decodeBase64Url(payload['ciphertext_hash'] as String);
            if (mutateAttempts == 1) {
              throw DioException(
                requestOptions: options,
                type: DioExceptionType.receiveTimeout,
                message: 'Receiving timed out',
              );
            }
            return _jsonError(ErrorCodes.nonceReplayed);
          }
          if (path.contains('/v1/vault/') && path.endsWith('/current')) {
            return _jsonOk({
              'vault': {
                'generation': 1,
                'ciphertext_hash': encodeBase64Url(uploadedHash!),
                'ciphertext': 'AA',
                'nonce': encodeBase64Url(Uint8List(12)),
                'timestamp': 1,
                'msk_signature': 'AA',
                'msk_public_key': encodeBase64Url(msk.publicKey!),
              },
            });
          }
          fail('unexpected ${options.uri}');
        });
        final client = PubkeyClient(
          crypto: crypto,
          writeBaseUrl: 'https://api.pubkey.test',
          readBaseUrl: 'https://api.pubkey.test',
          dio: dio,
        );

        final result = await client.uploadVault(
          email: 'alice@example.com',
          mskKey: msk,
          vault: vault,
          vek: vek,
        );

        expect(mutateAttempts, 2);
        expect(result['reconciled_from_replay'], isTrue);
        expect(result['generation'], 1);
        expect(vault.generation, 1);
        expect(vault.lastCiphertextHash, uploadedHash);
      },
    );

    test('maps exhausted connection failures to provider_unavailable', () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.connectionError,
          message: 'The connection errored: Connection failed',
        );
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'http://127.0.0.1:3000',
        writeBaseUrl: 'http://127.0.0.1:3000',
        dio: dio,
      );
      try {
        await client.getBestKey(
          email: 'alice@example.com',
          purpose: 'encryption',
          capabilities: {
            'families': {
              'smime': ['smime-mlkem-768'],
            },
          },
        );
        fail('expected PubkeyException');
      } on PubkeyException catch (error) {
        expect(error.code, ErrorCodes.providerUnavailable);
        expect(error.message, contains('pubkey server'));
      }
    });

    test('enrollMsk posts email and MSK public key', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      late RequestOptions seen;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        seen = options;
        return _jsonOk({'status': 'pending'});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      await client.enrollMsk(
        email: 'alice@example.com',
        mskPublicKey: msk.publicKey!,
      );
      expect(seen.uri.toString(), 'https://api.pubkey.test/v1/msk/enroll');
      expect(seen.method, 'POST');
      expect(seen.data['email'], 'alice@example.com');
      expect(seen.data['msk']['algorithm'], 'ed25519');
    });

    test('uploadVault signs generation 1 for genesis and persists locally',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      // Genesis sets generation to 1 before any upload —
      // replicated here since that assignment lives at the app layer
      // (PubkeyRuntime.persistMsk), not inside Vault/PubkeyClient.
      vault.generation = 1;
      vault.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'k1',
        'private_material': encodeBase64Url(Uint8List.fromList([1, 2, 3])),
      });
      final vek = KeyHierarchy.generateVek(crypto);

      Map<String, dynamic>? sentPayload;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        final body = options.data as Map;
        sentPayload = Map<String, dynamic>.from(body['payload'] as Map);
        return _jsonOk({'generation': 1, 'created_at': 1780000000000});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final result = await client.uploadVault(
        email: 'alice@example.com',
        mskKey: msk,
        vault: vault,
        vek: vek,
        uploadingDevice: 'device-1',
      );

      expect(result['generation'], 1);
      expect(vault.generation, 1);
      expect(vault.lastCiphertextHash, isNotNull);
      expect(sentPayload!['generation'], 1);
      expect(sentPayload!['previous_generation_hash'], isNull);
      expect(sentPayload!['uploading_device'], 'device-1');

      final signature = decodeBase64Url(sentPayload!['msk_signature'] as String);
      final verifyBytes = canonicalVaultRecordBytes(
        protocolVersion: protocolVersion,
        identityId: '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976',
        generation: 1,
        ciphertextHash: decodeBase64Url(sentPayload!['ciphertext_hash'] as String),
        previousGenerationHash: null,
        timestamp: sentPayload!['timestamp'] as int,
        nonce: decodeBase64Url(sentPayload!['nonce'] as String),
      );
      expect(
        await crypto.verify(msk.publicKey!, verifyBytes, signature),
        isTrue,
      );
    });

    test('uploadVault increments generation and chains from lastCiphertextHash on a second upload',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.generation = 3;
      vault.lastCiphertextHash = Uint8List.fromList(List.filled(32, 5));

      Map<String, dynamic>? sentPayload;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        final body = options.data as Map;
        sentPayload = Map<String, dynamic>.from(body['payload'] as Map);
        return _jsonOk({'generation': 4, 'created_at': 1780000000000});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final vek = KeyHierarchy.generateVek(crypto);
      await client.uploadVault(
        email: 'alice@example.com',
        mskKey: msk,
        vault: vault,
        vek: vek,
      );

      expect(vault.generation, 4);
      expect(sentPayload!['generation'], 4);
      expect(
        sentPayload!['previous_generation_hash'],
        encodeBase64Url(Uint8List.fromList(List.filled(32, 5))),
      );

      // The uploaded ciphertext's own embedded plaintext generation must
      // match the outer claimed/signed generation exactly — not the old
      // pre-upload value. A regression here would silently desynchronize
      // what's signed from what's actually inside the ciphertext.
      final uploadedPlaintextBytes = await KeyHierarchy.decryptVaultCiphertextWithVek(
        crypto,
        vek,
        WrappedKey(
          iv: decodeBase64Url(sentPayload!['nonce'] as String),
          ciphertext: decodeBase64Url(sentPayload!['ciphertext'] as String),
        ),
      );
      final uploadedPlaintext =
          jsonDecode(utf8.decode(uploadedPlaintextBytes)) as Map;
      expect(uploadedPlaintext['generation'], 4);
    });

    test('downloadCurrentVault verifies signature, checks hash chain, and applies',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';

      // Build a plausible generation 1 record the way uploadVault would.
      final source = Vault(crypto: crypto);
      await source.createVault(principal);
      source.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'k1',
        'private_material': encodeBase64Url(Uint8List.fromList([9, 8, 7])),
      });
      final vek = KeyHierarchy.generateVek(crypto);
      final exported = await source.exportVault(vek);
      final iv = decodeBase64Url((exported['encryption'] as Map)['iv'] as String);
      final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
      final ciphertextHash = sha256Bytes(ciphertext);
      const timestamp = 1780000000000;
      final signature = await crypto.sign(
        msk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 1,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: null,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 1,
            'previous_generation_hash': null,
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'uploading_device': 'device-1',
            'msk_signature': encodeBase64Url(signature),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto);

      final generation = await client.downloadCurrentVault(
        email: 'alice@example.com',
        vault: dest,
        vek: vek,
      );

      expect(generation, 1);
      expect(dest.unlocked, isTrue);
      expect(dest.getKeyByFingerprint('k1')?.fingerprint, 'k1');
      expect(dest.lastCiphertextHash, equals(ciphertextHash));
    });

    test('downloadCurrentVault rejects a ciphertext that does not match its claimed hash',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 1,
            'previous_generation_hash': null,
            'ciphertext_hash': encodeBase64Url(Uint8List(32)),
            'ciphertext': encodeBase64Url(Uint8List.fromList([1, 2, 3])),
            'nonce': encodeBase64Url(Uint8List(12)),
            'msk_signature': encodeBase64Url(Uint8List(64)),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': 1780000000000,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto);

      expect(
        () => client.downloadCurrentVault(
          email: 'alice@example.com',
          vault: dest,
          vek: KeyHierarchy.generateVek(crypto),
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultCorrupt,
          ),
        ),
      );
    });

    test('downloadCurrentVault rejects an invalid signature', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final wrongSigner = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';
      final ciphertext = Uint8List.fromList([9, 8, 7]);
      final ciphertextHash = sha256Bytes(ciphertext);
      final iv = Uint8List(12);
      const timestamp = 1780000000000;
      // Signed by a key that isn't the one being verified against.
      final signature = await crypto.sign(
        wrongSigner,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 1,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: null,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 1,
            'previous_generation_hash': null,
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'msk_signature': encodeBase64Url(signature),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      expect(
        () => client.downloadCurrentVault(
          email: 'alice@example.com',
          vault: Vault(crypto: crypto),
          vek: KeyHierarchy.generateVek(crypto),
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.invalidSignature,
          ),
        ),
      );
    });

    test(
        'downloadCurrentVault accepts a generation more than one step ahead '
        'of this device\'s own last-known generation', () async {
      // A plain pull applies whichever generation the server reports as
      // current wholesale (a full snapshot, not a diff) — this device being
      // several generations behind (e.g. another device made several
      // related vault changes since this device's last sync) is the normal
      // case, not a broken chain. Only the record's own signature/hash
      // integrity (already verified above this point) matters.
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';

      final source = Vault(crypto: crypto);
      await source.createVault(principal);
      source.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'k1',
        'private_material': encodeBase64Url(Uint8List.fromList([9, 8, 7])),
      });
      final vek = KeyHierarchy.generateVek(crypto);
      final exported = await source.exportVault(vek);
      final iv = decodeBase64Url((exported['encryption'] as Map)['iv'] as String);
      final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
      final ciphertextHash = sha256Bytes(ciphertext);
      final unrelatedPreviousHash = Uint8List.fromList(List.filled(32, 3));
      const timestamp = 1780000000000;
      final signature = await crypto.sign(
        msk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 5,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: unrelatedPreviousHash,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 5,
            'previous_generation_hash': encodeBase64Url(unrelatedPreviousHash),
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'msk_signature': encodeBase64Url(signature),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto)
        ..generation = 1
        ..lastCiphertextHash = Uint8List.fromList(List.filled(32, 9));

      final generation = await client.downloadCurrentVault(
        email: 'alice@example.com',
        vault: dest,
        vek: vek,
      );

      expect(generation, 5);
      expect(dest.lastCiphertextHash, ciphertextHash);
      expect(dest.getKeyByFingerprint('k1')?.fingerprint, 'k1');
    });

    test(
        'downloadCurrentVault rejects a generation older than one this '
        'device already applied', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';
      final ciphertext = Uint8List.fromList([9, 8, 7]);
      final ciphertextHash = sha256Bytes(ciphertext);
      final iv = Uint8List(12);
      final previousHash = Uint8List.fromList(List.filled(32, 3));
      const timestamp = 1780000000000;
      // A genuinely valid signature over an older generation than the one
      // this device already applied — the endpoint should never actually
      // return this (it's always ORDER BY generation DESC LIMIT 1), but the
      // client should refuse to regress if it somehow does.
      final signature = await crypto.sign(
        msk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 2,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: previousHash,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 2,
            'previous_generation_hash': encodeBase64Url(previousHash),
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'msk_signature': encodeBase64Url(signature),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto)
        ..generation = 6
        ..lastCiphertextHash = Uint8List.fromList(List.filled(32, 9));

      expect(
        () => client.downloadCurrentVault(
          email: 'alice@example.com',
          vault: dest,
          vek: KeyHierarchy.generateVek(crypto),
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultRevisionConflict,
          ),
        ),
      );
    });

    test(
        'downloadCurrentVault is a no-op when the downloaded generation is '
        'already this device\'s own last-known generation', () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';
      final ciphertext = Uint8List.fromList([9, 8, 7]);
      final ciphertextHash = sha256Bytes(ciphertext);
      final iv = Uint8List(12);
      final previousHash = Uint8List.fromList(List.filled(32, 3));
      const timestamp = 1780000000000;
      // A device that just uploaded this exact generation itself has
      // already set its own lastCiphertextHash to ciphertextHash (see
      // uploadVault/mutateAndUpload) — that must not be mistaken for a
      // broken chain when it immediately re-syncs and downloads the same
      // record back.
      final signature = await crypto.sign(
        msk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 5,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: previousHash,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 5,
            'previous_generation_hash': encodeBase64Url(previousHash),
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'msk_signature': encodeBase64Url(signature),
            'msk_public_key': encodeBase64Url(msk.publicKey!),
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto)..lastCiphertextHash = ciphertextHash;

      final generation = await client.downloadCurrentVault(
        email: 'alice@example.com',
        vault: dest,
        vek: KeyHierarchy.generateVek(crypto),
      );

      expect(generation, 5);
      // Already in sync — nothing to apply, so the vault is untouched.
      expect(dest.unlocked, isFalse);
      expect(dest.lastCiphertextHash, equals(ciphertextHash));
    });

    test('downloadCurrentVault returns null when nothing has been uploaded yet',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({'vault': null});
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );
      final dest = Vault(crypto: crypto);

      final generation = await client.downloadCurrentVault(
        email: 'alice@example.com',
        vault: dest,
        vek: KeyHierarchy.generateVek(crypto),
      );

      expect(generation, isNull);
      expect(dest.unlocked, isFalse);
    });

    test(
        'downloadVaultGeneration decrypts an old generation with the old VEK '
        'and verifies against any of the returned msk_public_keys',
        () async {
      final crypto = DartCryptoProvider();
      final oldMsk = await crypto.generateSigningKey('ed25519');
      final currentMsk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';

      final source = Vault(crypto: crypto);
      await source.createVault(principal);
      source.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'old-key-1',
        'private_material': encodeBase64Url(Uint8List.fromList([1, 2, 3])),
      });
      final oldVek = KeyHierarchy.generateVek(crypto);
      final exported = await source.exportVault(oldVek);
      final iv = decodeBase64Url((exported['encryption'] as Map)['iv'] as String);
      final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
      final ciphertextHash = sha256Bytes(ciphertext);
      const timestamp = 1700000000000;
      // Signed by the OLD MSK (the one active when generation 2 was
      // originally uploaded) — not the current one, matching the
      // scenario that a discontinuity happened since.
      final signature = await crypto.sign(
        oldMsk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 2,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: null,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      String? seenPath;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        seenPath = options.uri.path;
        return _jsonOk({
          'vault': {
            'generation': 2,
            'previous_generation_hash': null,
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'uploading_device': 'old-device',
            'msk_signature': encodeBase64Url(signature),
            // The server returns EVERY key this principal has ever armed —
            // current first, then archived — not just the one that actually
            // signed this generation (see vaultService.ts's doc comment).
            'msk_public_keys': [
              encodeBase64Url(currentMsk.publicKey!),
              encodeBase64Url(oldMsk.publicKey!),
            ],
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final entries = await client.downloadVaultGeneration(
        email: 'alice@example.com',
        generation: 2,
        vek: oldVek,
      );

      expect(
        seenPath,
        '/v1/vault/${emailSha256Hex('alice@example.com')}/generation/2',
      );
      expect(entries, isNotNull);
      expect(entries!.single.fingerprint, 'old-key-1');
    });

    test('downloadVaultGeneration rejects a signature that verifies against none of the returned keys',
        () async {
      final crypto = DartCryptoProvider();
      final oldMsk = await crypto.generateSigningKey('ed25519');
      final unrelatedMsk = await crypto.generateSigningKey('ed25519');
      final principal = '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976';

      final source = Vault(crypto: crypto);
      await source.createVault(principal);
      final oldVek = KeyHierarchy.generateVek(crypto);
      final exported = await source.exportVault(oldVek);
      final iv = decodeBase64Url((exported['encryption'] as Map)['iv'] as String);
      final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
      final ciphertextHash = sha256Bytes(ciphertext);
      const timestamp = 1700000000000;
      final signature = await crypto.sign(
        oldMsk,
        canonicalVaultRecordBytes(
          protocolVersion: protocolVersion,
          identityId: principal,
          generation: 2,
          ciphertextHash: ciphertextHash,
          previousGenerationHash: null,
          timestamp: timestamp,
          nonce: iv,
        ),
      );

      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({
          'vault': {
            'generation': 2,
            'previous_generation_hash': null,
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(iv),
            'uploading_device': 'old-device',
            'msk_signature': encodeBase64Url(signature),
            // deliberately does NOT include oldMsk's public key
            'msk_public_keys': [encodeBase64Url(unrelatedMsk.publicKey!)],
            'timestamp': timestamp,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      expect(
        () => client.downloadVaultGeneration(
          email: 'alice@example.com',
          generation: 2,
          vek: oldVek,
        ),
        throwsA(
          predicate((e) =>
              e is PubkeyException && e.code == ErrorCodes.invalidSignature),
        ),
      );
    });

    test('downloadVaultGeneration returns null when that generation never existed',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({'vault': null});
      });
      final client = PubkeyClient(
        crypto: crypto,
        writeBaseUrl: 'https://api.pubkey.test',
        readBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final entries = await client.downloadVaultGeneration(
        email: 'alice@example.com',
        generation: 99,
        vek: KeyHierarchy.generateVek(crypto),
      );

      expect(entries, isNull);
    });

    test('uploadVault includes mutation_kind and target_device_id when declared',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.generation = 1;
      final vek = KeyHierarchy.generateVek(crypto);

      Map<String, dynamic>? sentPayload;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        final body = options.data as Map;
        sentPayload = Map<String, dynamic>.from(body['payload'] as Map);
        return _jsonOk({
          'generation': 1,
          'created_at': 1780000000000,
          'high_risk_mutation': {
            'mutation_id': 'm1',
            'state': 'pending',
            'created_at': '2026-01-01T00:00:00Z',
            'confirm_at': '2026-01-01T00:05:00Z',
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final result = await client.uploadVault(
        email: 'alice@example.com',
        mskKey: msk,
        vault: vault,
        vek: vek,
        mutationKind: HighRiskMutationKinds.deviceAdd,
        targetDeviceId: 'device-b-id',
      );

      expect(sentPayload!['mutation_kind'], HighRiskMutationKinds.deviceAdd);
      expect(sentPayload!['target_device_id'], 'device-b-id');
      expect(result['high_risk_mutation']['mutation_id'], 'm1');
    });

    test('uploadVault omits mutation_kind/target_device_id when not declared',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.generation = 1;
      final vek = KeyHierarchy.generateVek(crypto);

      Map<String, dynamic>? sentPayload;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        final body = options.data as Map;
        sentPayload = Map<String, dynamic>.from(body['payload'] as Map);
        return _jsonOk({'generation': 1, 'created_at': 1780000000000});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final result = await client.uploadVault(
        email: 'alice@example.com',
        mskKey: msk,
        vault: vault,
        vek: vek,
      );

      expect(sentPayload!.containsKey('mutation_kind'), isFalse);
      expect(sentPayload!.containsKey('target_device_id'), isFalse);
      expect(result.containsKey('high_risk_mutation'), isFalse);
    });

    test('fetchPendingHighRiskMutations maps the response into typed rows',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        expect(options.path, contains('/pending-mutations'));
        return _jsonOk({
          'mutations': [
            {
              'mutation_id': 'm1',
              'mutation_kind': 'device_add',
              'target_device_id': 'device-b-id',
              'generation': 4,
              'state': 'pending',
              'created_at': '2026-01-01T00:00:00Z',
              'confirm_at': '2026-01-01T00:05:00Z',
            },
          ],
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final mutations = await client.fetchPendingHighRiskMutations(
        email: 'alice@example.com',
      );

      expect(mutations, hasLength(1));
      expect(mutations.single.mutationId, 'm1');
      expect(mutations.single.mutationKind, HighRiskMutationKinds.deviceAdd);
      expect(mutations.single.targetDeviceId, 'device-b-id');
      expect(mutations.single.generation, 4);
      expect(mutations.single.state, 'pending');
    });

    test('fetchPendingHighRiskMutations returns an empty list when nothing is pending',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({'mutations': []});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final mutations = await client.fetchPendingHighRiskMutations(
        email: 'alice@example.com',
      );

      expect(mutations, isEmpty);
    });

    test('cancelHighRiskMutation signs and posts the mutation_id via mutate',
        () async {
      final crypto = DartCryptoProvider();
      final msk = await crypto.generateSigningKey('ed25519');
      Map<String, dynamic>? envelope;
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        envelope = Map<String, dynamic>.from(options.data as Map);
        return _jsonOk({'mutation_id': 'm1', 'state': 'cancelled'});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final result = await client.cancelHighRiskMutation(
        email: 'alice@example.com',
        mutationId: 'm1',
        mskKey: msk,
      );

      expect(result['state'], 'cancelled');
      expect(envelope!['operation'], Operations.cancelHighRiskMutation);
      expect(
        (envelope!['payload'] as Map)['mutation_id'],
        'm1',
      );
    });

    test(
        'fetchCurrentVaultGenerationInfo returns generation + ciphertext hash '
        'without decrypting or verifying', () async {
      final crypto = DartCryptoProvider();
      final ciphertext = Uint8List.fromList(List.generate(32, (i) => i));
      final ciphertextHash = sha256Bytes(ciphertext);
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        expect(options.path, contains('/current'));
        return _jsonOk({
          'vault': {
            'generation': 7,
            'ciphertext_hash': encodeBase64Url(ciphertextHash),
            'ciphertext': encodeBase64Url(ciphertext),
            'nonce': encodeBase64Url(Uint8List(12)),
            'msk_signature': encodeBase64Url(Uint8List(64)),
            'msk_public_key': encodeBase64Url(Uint8List(32)),
            'timestamp': 1780000000000,
          },
        });
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final info = await client.fetchCurrentVaultGenerationInfo(
        email: 'alice@example.com',
      );

      expect(info, isNotNull);
      expect(info!.generation, 7);
      expect(info.ciphertextHash, equals(ciphertextHash));
    });

    test('fetchCurrentVaultGenerationInfo returns null when nothing has been '
        'uploaded yet', () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({'vault': null});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final info = await client.fetchCurrentVaultGenerationInfo(
        email: 'alice@example.com',
      );

      expect(info, isNull);
    });

    test(
        'hasRecoveryEnvelope reflects the server\'s { exists } response',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        expect(options.path, contains('/recovery/envelope-exists/'));
        return _jsonOk({'exists': true});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final exists = await client.hasRecoveryEnvelope(email: 'alice@example.com');

      expect(exists, isTrue);
    });

    test('hasRecoveryEnvelope returns false when none was ever set up',
        () async {
      final crypto = DartCryptoProvider();
      final dio = Dio();
      dio.httpClientAdapter = _ScriptedAdapter((options) async {
        return _jsonOk({'exists': false});
      });
      final client = PubkeyClient(
        crypto: crypto,
        readBaseUrl: 'https://api.pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
        dio: dio,
      );

      final exists = await client.hasRecoveryEnvelope(email: 'alice@example.com');

      expect(exists, isFalse);
    });
  });
}
