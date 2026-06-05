import 'package:flutter_test/flutter_test.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import 'package:secmail_pubkey_sdk/src/auth/pubkey_session.dart';
import 'package:secmail_pubkey_sdk/src/auth/pubkey_session_wiring.dart';
import 'package:secmail_pubkey_sdk/src/models/key_list_item.dart';

void main() {
  test('withSigningKeyFromList picks preferred active signing key', () {
    const session = PubkeySession(
      email: 'a@b.com',
      sigFamily: PubkeySigFamily.openPgp,
    );
    final keys = [
      const KeyListItem(
        keyId: '2',
        algorithm: 'openpgp-cv25519',
        status: 'active',
        isPreferred: false,
        discoverable: true,
        hasRecoveryPhrase: false,
        hasBlob: false,
      ),
      const KeyListItem(
        keyId: '1',
        algorithm: 'openpgp-ed25519',
        status: 'active',
        isPreferred: true,
        discoverable: true,
        hasRecoveryPhrase: false,
        hasBlob: true,
      ),
    ];

    final wired = session.withSigningKeyFromList(keys);
    expect(wired.signingKeyId, '1');
    expect(wired.sigFamily, PubkeySigFamily.openPgp);
  });
}
