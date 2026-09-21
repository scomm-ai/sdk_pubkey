import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('PubkeyConfig.requireUrl', () {
    test('returns a non-empty origin', () {
      expect(
        PubkeyConfig.requireUrl(
          'PUBKEY_READ_BASE_URL',
          'https://pubkey.test',
        ),
        'https://pubkey.test',
      );
    });

    test('fails closed on null', () {
      expect(
        () => PubkeyConfig.requireUrl('PUBKEY_READ_BASE_URL', null),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('PUBKEY_READ_BASE_URL'),
          ),
        ),
      );
    });

    test('fails closed on blank', () {
      expect(
        () => PubkeyConfig.requireUrl('PUBKEY_WRITE_BASE_URL', '  '),
        throwsStateError,
      );
    });
  });

  test('PubkeyClient fails closed when hosts are omitted', () {
    expect(
      () => PubkeyClient(crypto: DartCryptoProvider()),
      throwsStateError,
    );
  });
}
