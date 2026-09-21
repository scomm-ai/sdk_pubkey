import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

/// The vault document is shared with the Office add-in
/// (`C:\dev\package\pubkey\office`, `packages/scomm-pubkey/src/vault/vault.js`),
/// so this parser has to survive what that client writes.
///
/// It wrote `current_signing_key_id`/`current_encryption_key_id` as JSON
/// numbers while this side hard-cast them to `String?`. That threw a raw
/// `TypeError` out of the middle of the parse — not a `PubkeyException` — and
/// left the vault empty and locked. Because generations are immutable and
/// never deleted, the offending generation stayed current: this device could
/// then neither read the vault nor upload a replacement.
Future<Vault> _vaultFrom(
  DartCryptoProvider crypto,
  Uint8List vek,
  Map<String, dynamic> plaintext,
) async {
  final vault = Vault(crypto: crypto);
  await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
  final wrapped = await KeyHierarchy.encryptVaultPlaintextWithVek(
    crypto,
    vek,
    utf8.encode(jsonEncode(plaintext)),
  );
  await vault.applyDownloadedGeneration(
    vek: vek,
    iv: wrapped.iv,
    ciphertext: wrapped.ciphertext,
    ciphertextHash: Uint8List(32),
  );
  return vault;
}

Map<String, dynamic> _plaintext({
  Object? signingPointer,
  Object? encryptionPointer,
}) => <String, dynamic>{
  'vault_format_version': vaultFormatVersion,
  'generation': 1,
  'principal': '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976',
  'created_at': 1780000000000,
  'updated_at': 1780000000000,
  'current_signing_key_id': signingPointer,
  'current_encryption_key_id': encryptionPointer,
  'msk_envelope': null,
  'openpgp_keys': [
    {
      'key_id': '9',
      'type': 'encryption',
      'status': 'active',
      'fingerprint': 'BBBB2222',
      'private_key': encodeBase64Url(Uint8List.fromList([4, 5, 6])),
    },
  ],
  'smime_keys': <dynamic>[],
  'signing_keys': <dynamic>[],
  'legacy_entries': <dynamic>[],
  'metadata': {'devices': <dynamic>[]},
};

void main() {
  group('Office interop', () {
    test('a numeric canonical key pointer loads instead of throwing', () async {
      final crypto = DartCryptoProvider();
      final vek = Uint8List.fromList(List<int>.generate(32, (i) => i));

      final vault = await _vaultFrom(
        crypto,
        vek,
        _plaintext(signingPointer: 7, encryptionPointer: 9),
      );

      expect(vault.currentSigningKeyId, '7');
      expect(vault.currentEncryptionKeyId, '9');
      expect(
        vault.entries.length,
        1,
        reason: 'the rest of the vault must load, not be lost with the cast',
      );
    });

    test('the string form this client writes still round-trips', () async {
      final crypto = DartCryptoProvider();
      final vek = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

      final vault = await _vaultFrom(
        crypto,
        vek,
        _plaintext(signingPointer: '7', encryptionPointer: '9'),
      );

      expect(vault.currentSigningKeyId, '7');
      expect(vault.currentEncryptionKeyId, '9');
    });

    test('an absent or empty pointer reads as null, not ""', () async {
      final crypto = DartCryptoProvider();
      final vek = Uint8List.fromList(List<int>.generate(32, (i) => i + 2));

      final vault = await _vaultFrom(
        crypto,
        vek,
        _plaintext(signingPointer: null, encryptionPointer: ''),
      );

      expect(vault.currentSigningKeyId, isNull);
      expect(vault.currentEncryptionKeyId, isNull);
    });
  });
}
