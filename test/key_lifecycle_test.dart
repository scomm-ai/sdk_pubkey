import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('retired encryption can decrypt and cannot encrypt', () {
    final caps = keyCapabilities(
      purpose: 'encryption',
      lifecycle: KeyGenerationStatus.retired,
      hasPrivateMaterial: true,
      hasPublicMaterial: false,
    );
    expect(caps.canEncryptNow, isFalse);
    expect(caps.canDecrypt, isTrue);
    expect(caps.canSignNow, isFalse);
  });

  test('revoked signing cannot sign and can still verify', () {
    final caps = keyCapabilities(
      purpose: 'signing',
      lifecycle: 'compromised',
      hasPrivateMaterial: false,
      hasPublicMaterial: true,
    );
    expect(caps.canSignNow, isFalse);
    expect(caps.canVerify, isTrue);
  });

  test('active signing requires private material to sign', () {
    final caps = keyCapabilities(
      purpose: 'signing',
      lifecycle: KeyGenerationStatus.active,
      hasPrivateMaterial: false,
      hasPublicMaterial: true,
    );
    expect(caps.canSignNow, isFalse);
    expect(caps.canVerify, isTrue);
  });
}
