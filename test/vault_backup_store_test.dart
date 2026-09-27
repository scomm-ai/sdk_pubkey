import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('LocalFileBackupStore round-trips a scomm-vault-export blob', () async {
    final files = <String, Uint8List>{};
    final store = LocalFileBackupStore(
      writeBytes: (identity, bytes) async => files[identity] = bytes,
      readBytes: (identity) async => files[identity],
      deleteBytes: (identity) async => files.remove(identity),
    );
    const identity = 'alice@example.com';
    final blob = {
      'kind': vaultExportKind,
      'header': {
        'format_version': vaultExportFormatVersion,
        'identity': identity,
        'tier': 'limited',
      },
      'vek_envelope': {'kdf': 'argon2id'},
    };
    await store.put(identity: identity, blob: blob);
    final got = await store.get(identity: identity);
    expect(got?['kind'], vaultExportKind);
    expect(jsonDecode(utf8.decode(files[identity]!))['header']['identity'],
        identity);
    await store.delete(identity: identity);
    expect(await store.get(identity: identity), isNull);
  });

  test('get verifies the OTP then getWithGrant fetches with the grant', () async {
    final identityId = 'cd' * 32;
    final client = _RecordingClient();
    final dio = Dio();
    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          handler.resolve(
            Response<dynamic>(
              requestOptions: options,
              statusCode: 200,
              data: {
                'identity_id': identityId,
                'otp_grant': 'from-otp',
              },
            ),
          );
        },
      ),
    );
    final store = DiscoveryBackupStore(
      client,
      mailer: MailerClient(baseUrl: 'http://mailer.test', dio: dio),
    );
    final viaOtp = await store.get(identity: 'user@gmail.com', otp: 'Abcdefghijk');
    expect(viaOtp?['ok'], isTrue);
    expect(client.otpGrant, 'from-otp');
    expect(client.calls, 1);

    final viaGrant = await store.getWithGrant(
      identity: 'user@gmail.com',
      grant: MailerOtpGrant(identityId: identityId, otpGrant: 'direct'),
    );
    expect(viaGrant?['ok'], isTrue);
    expect(client.otpGrant, 'direct');
    expect(client.calls, 2);
  });
}

class _RecordingClient extends PubkeyClient {
  _RecordingClient()
      : super(
          crypto: DartCryptoProvider(),
          readBaseUrl: 'http://read.test',
          writeBaseUrl: 'http://write.test',
          vaultBaseUrl: 'http://vault.test',
          dio: Dio(),
        );

  int calls = 0;
  String? otpGrant;

  @override
  Future<Map<String, dynamic>> fetchVaultBackupWithGrant({
    required String identityId,
    required String otpGrant,
  }) async {
    calls += 1;
    this.otpGrant = otpGrant;
    return {'ok': true, 'identity_id': identityId};
  }
}
