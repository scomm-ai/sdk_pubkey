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
      expect(body['principal'], hasLength(64));
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
        identityId: 'ab' * 32,
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
        identityId: 'ab' * 32,
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

    test('requestVaultRecover rejects OTP recovery', () async {
      final client = PubkeyClient(
        crypto: DartCryptoProvider(),
        readBaseUrl: 'https://pubkey.test',
        writeBaseUrl: 'https://api.pubkey.test',
      );
      expect(
        () => client.requestVaultRecover(email: 'alice@example.com'),
        throwsA(isA<PubkeyException>().having(
          (e) => e.code,
          'code',
          ErrorCodes.otpNotDeviceEnrollment,
        )),
      );
    });
  });
}
