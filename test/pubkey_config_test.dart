import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('read and write base URLs have defaults', () {
    expect(PubkeyConfig.readBaseUrl, isNotEmpty);
    expect(PubkeyConfig.writeBaseUrl, isNotEmpty);
    expect(PubkeyConfig.readBaseUrl, contains('pubkey'));
    expect(PubkeyConfig.writeBaseUrl, contains('api'));
  });
}
