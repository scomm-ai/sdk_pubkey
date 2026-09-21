import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('device authorization omits unenforced permissions', () {
    final a = canonicalizeDeviceAuthorization({
      'principalId': 'p',
      'deviceId': 'd',
      'devicePublicKey': 'pub',
      'createdAt': 1,
      'nonce': 'n',
    });
    final b = canonicalizeDeviceAuthorization({
      'principal_id': 'p',
      'device_id': 'd',
      'device_public_key': 'pub',
      'created_at': 1,
      'nonce': 'n',
    });
    expect(a, b);
  });

  test('missing local MSK does not imply generate', () {
    expect(
      mustNotGenerateMsk(
        principalExists: true,
        localMsk: false,
        explicitRecovery: false,
      ),
      isTrue,
    );
    expect(
      resolveIdentityUxState(principalExists: true, localMsk: false),
      IdentityUxStates.unauthorized,
    );
  });
}
