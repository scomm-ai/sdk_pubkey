import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('formats OpenPGP 64-bit Key-ID', () {
    expect(formatOpenPgpLocator('ab12cd34ef567890'), 'AB12-CD34-EF56-7890');
    expect(
      formatOpenPgpLocator('0011223344556677AB12CD34EF567890'),
      'AB12-CD34-EF56-7890',
    );
  });
}
