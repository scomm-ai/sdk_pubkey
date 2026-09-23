import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/runtime/pubkey_runtime.dart';
import 'package:test/test.dart';

void main() {
  test('enroll, directory, and recovery omit mailbox addresses', () async {
    final seen = <RequestOptions>[];
    final dio = Dio();
    dio.httpClientAdapter = _Capture((options) async {
      seen.add(options);
      final path = options.uri.path;
      if (path.endsWith('/v1/otp/request')) {
        return _json({'ok': true}, status: 202);
      }
      if (path.endsWith('/v1/otp/verify')) {
        return _json({
          'identity_id': 'ab' * 32,
          'otp_grant': 'header.payload.sig',
        });
      }
      if (path.endsWith('/v1/id/oprf/evaluate')) {
        final body = Map<String, dynamic>.from(options.data as Map);
        expect(body.keys, ['blind']);
        return _json({'evaluation': body['blind']});
      }
      if (path.endsWith('/v1/keys')) {
        expect(options.uri.queryParameters.containsKey('sha256'), isFalse);
        expect(options.uri.queryParameters['identity_id'], hasLength(64));
        return _json({'public_material': null});
      }
      if (path.endsWith('/v1/msk/enroll') ||
          path.endsWith('/v1/msk/enroll/verify')) {
        final encoded = jsonEncode(options.data);
        expect(encoded.contains('@'), isFalse);
        expect(options.data, isNot(contains('email')));
        return _json({'ok': true});
      }
      if (path.endsWith('/v1/recovery/envelope/fetch')) {
        final encoded = jsonEncode(options.data);
        expect(encoded.contains('@'), isFalse);
        expect(options.data, isNot(contains('email')));
        return _json({
          'vek_envelope': {
            'kdf': 'argon2id',
            'salt': 'AAAA',
            'iv': 'AAAA',
            'ciphertext': 'AAAA',
            'kdf_params': {'memory': 1, 'iterations': 1, 'parallelism': 1},
          },
        });
      }
      return _json({'error': 'unexpected', 'message': path}, status: 500);
    });

    final runtime = createPubkeyRuntime(
      'alice@example.com',
      dio: dio,
      readBaseUrl: 'http://pubkey.test',
      writeBaseUrl: 'http://pubkey.test',
      mailerBaseUrl: 'http://mailer.test',
    );
    await runtime.mailer.requestOtp(
      email: 'alice@example.com',
      purpose: MailerOtpPurpose.enroll,
    );
    final grant = await runtime.mailer.verifyOtp(
      email: 'Alice@Example.com',
      otp: '0123456789A',
      purpose: MailerOtpPurpose.enroll,
    );
    await runtime.store.setIdentityId(grant.identityId);
    await runtime.store.setVaultId('cd' * 32);
    await runtime.client.enrollMskForIdentity(
      identityId: grant.identityId,
      vaultId: 'cd' * 32,
      mskPublicKey: Uint8List(32),
    );
    await runtime.client.selectDirectoryKey(email: 'bob@example.com');
    await runtime.client.fetchRecoveryEnvelopeWithGrant(
      identityId: grant.identityId,
      otpGrant: grant.otpGrant,
    );

    final mailer = seen.where((r) => r.uri.host == 'mailer.test').toList();
    final pubkey = seen.where((r) => r.uri.host == 'pubkey.test').toList();
    expect(mailer, isNotEmpty);
    expect(mailer.every((r) => jsonEncode(r.data).contains('alice@example.com')), isTrue);
    expect(pubkey, isNotEmpty);
    for (final request in pubkey) {
      expect(request.uri.toString().contains('@'), isFalse);
      if (request.data != null) {
        expect(jsonEncode(request.data).contains('@'), isFalse);
        expect(jsonEncode(request.data).contains('"email"'), isFalse);
        expect(jsonEncode(request.data).contains('email_sha256'), isFalse);
      }
    }
  });

  test('vault reads are authorized and not keyed by email hash', () async {
    final seen = <RequestOptions>[];
    final dio = Dio();
    const vaultId = 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd';
    dio.httpClientAdapter = _Capture((options) async {
      seen.add(options);
      final path = options.uri.path;
      if (path.endsWith('/pending-mutations')) {
        return _json({'mutations': []});
      }
      if (path.contains('/generation/')) {
        return _json({'vault': null});
      }
      if (path.endsWith('/current')) {
        return _json({
          'msk_public_key': 'AAAA',
          'vault': null,
        });
      }
      return _json({'error': 'unexpected', 'message': path}, status: 500);
    });
    final runtime = createPubkeyRuntime(
      'alice@example.com',
      dio: dio,
      readBaseUrl: 'http://pubkey.test',
      writeBaseUrl: 'http://pubkey.test',
      mailerBaseUrl: 'http://mailer.test',
    );
    await runtime.store.setIdentityId('ab' * 32);
    await runtime.store.setVaultId(vaultId);
    runtime.client.deviceSigningKey = await runtime.crypto.generateMSK();

    await runtime.client.fetchArmedMskPublicKey(email: 'alice@example.com');
    await runtime.client.fetchPendingHighRiskMutations(email: 'alice@example.com');
    await runtime.client.downloadVaultGeneration(
      email: 'alice@example.com',
      generation: 2,
      vek: Uint8List(32),
    );
    await runtime.client.fetchCurrentVaultGenerationInfo(email: 'alice@example.com');

    expect(seen, isNotEmpty);
    for (final request in seen) {
      expect(request.uri.path, contains(vaultId));
      expect(request.uri.path.contains('envelope-exists'), isFalse);
      expect(request.uri.path.contains('backup-exists'), isFalse);
      expect(request.headers['Authorization'], startsWith('Device '));
      expect(request.uri.toString().contains('@'), isFalse);
    }
  });
}

ResponseBody _json(Object body, {int status = 200}) {
  return ResponseBody.fromString(
    jsonEncode(body),
    status,
    headers: {
      Headers.contentTypeHeader: [Headers.jsonContentType],
    },
  );
}

class _Capture implements HttpClientAdapter {
  _Capture(this._handle);

  final Future<ResponseBody> Function(RequestOptions options) _handle;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) =>
      _handle(options);

  @override
  void close({bool force = false}) {}
}
