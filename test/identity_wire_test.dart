import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/runtime/pubkey_runtime.dart';
import 'package:test/test.dart';

void main() {
  test('enroll and directory omit mailbox addresses on pubkey host', () async {
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
      if (path.endsWith('/v1/keys')) {
        expect(options.uri.queryParameters.containsKey('identity_id'), isFalse);
        expect(options.uri.queryParameters['sha256'], hasLength(64));
        return _json({'public_material': null});
      }
      if (path.endsWith('/v1/msk/enroll') ||
          path.endsWith('/v1/msk/enroll/verify')) {
        final encoded = jsonEncode(options.data);
        expect(encoded.contains('@'), isFalse);
        expect(options.data, isNot(contains('email')));
        return _json({'ok': true});
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
      mskPublicKey: Uint8List(32),
    );
    final grant = await runtime.mailer.verifyOtp(
      email: 'Alice@Example.com',
      otp: '0123456789A',
      purpose: MailerOtpPurpose.enroll,
    );
    // ignore: deprecated_member_use_from_same_package
    await runtime.client.enrollMskForIdentity(
      identityId: grant.requireIdentityId,
      vaultId: 'cd' * 32,
      mskPublicKey: Uint8List(32),
    );
    await runtime.client.selectDirectoryKey(email: 'bob@example.com');

    final mailer = seen.where((r) => r.uri.host == 'mailer.test').toList();
    final pubkey = seen.where((r) => r.uri.host == 'pubkey.test').toList();
    expect(mailer, isNotEmpty);
    expect(
      mailer.any(
        (r) =>
            r.uri.path.endsWith('/otp/request') &&
            jsonEncode(r.data).contains('alice@example.com'),
      ),
      isTrue,
    );
    expect(
      mailer.where((r) => r.uri.path.endsWith('/otp/verify')).every((r) {
        final body = jsonEncode(r.data);
        return !body.contains('alice@example.com') &&
            !body.contains('"email"') &&
            body.contains('sha256');
      }),
      isTrue,
    );
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

  test('first-device enroll verify stays on the directory', () async {
    final seen = <Uri>[];
    final dio = Dio();
    dio.httpClientAdapter = _Capture((options) async {
      seen.add(options.uri);
      if (options.uri.path.endsWith('/v1/msk/arm')) {
        return _json({'status': 'armed'});
      }
      return _json(
        {'error': 'unexpected', 'message': options.uri.path},
        status: 500,
      );
    });
    final runtime = createPubkeyRuntime(
      'alice@example.com',
      dio: dio,
      readBaseUrl: 'http://pubkey.test',
      writeBaseUrl: 'http://pubkey.test',
      vaultBaseUrl: 'http://vault.test',
      mailerBaseUrl: 'http://mailer.test',
    );
    final msk = await runtime.crypto.generateMSK();
    await runtime.client.verifyEnrollForIdentity(
      identityId: 'ab' * 32,
      vaultId: 'cd' * 32,
      otpGrant: 'header.payload.sig',
      mskKey: msk,
    );
    expect(seen, hasLength(1));
    expect(seen.single.host, 'pubkey.test');
    expect(seen.single.path, '/v1/msk/arm');
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
