import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

Future<Vault> _vault() async {
  final vault = Vault(crypto: DartCryptoProvider());
  await vault.createVault('p');
  return vault;
}

Map<String, dynamic> _entry({
  int? keyId,
  required String fingerprint,
  String purpose = 'encryption',
  String? family = 'pgp',
  List<int> material = const [1, 2, 3],
}) =>
    {
      'kind': 'content',
      if (keyId != null) 'key_id': keyId,
      if (family != null) 'family': family,
      'purpose': purpose,
      'fingerprint': fingerprint,
      'private_material': encodeBase64Url(Uint8List.fromList(material)),
      'status': 'active',
    };

void main() {
  group('Vault canonical pointers', () {
    test('retiring the advertised encryption key clears the pointer',
        () async {
      final vault = await _vault();
      vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));
      vault.currentEncryptionKeyId = '42';

      vault.retireKey(42);

      expect(vault.getKey(42)!.status, 'retired');
      expect(
        vault.currentEncryptionKeyId,
        isNull,
        reason:
            'the pointer means "advertised right now" — it must not outlive '
            'the entry it names',
      );
    });

    test('revoking the advertised encryption key clears the pointer too',
        () async {
      final vault = await _vault();
      vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));
      vault.currentEncryptionKeyId = '42';

      vault.revokeKey(42);

      expect(vault.getKey(42)!.status, 'revoked');
      expect(vault.currentEncryptionKeyId, isNull);
    });

    test('retiring the canonical signing key clears the signing pointer',
        () async {
      final vault = await _vault();
      vault.addKey(
        _entry(keyId: 7, fingerprint: 'SIGNFP', purpose: 'signing'),
      );
      vault.currentSigningKeyId = '7';

      vault.retireKey(7);

      expect(vault.currentSigningKeyId, isNull);
    });

    test('retiring an unrelated key leaves both pointers alone', () async {
      final vault = await _vault();
      vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));
      vault.addKey(
        _entry(keyId: 7, fingerprint: 'SIGNFP', purpose: 'signing'),
      );
      vault.addKey(
        _entry(keyId: 43, fingerprint: 'SPAREFP', material: [9, 9]),
      );
      vault.currentEncryptionKeyId = '42';
      vault.currentSigningKeyId = '7';

      vault.retireKey(43);

      expect(vault.currentEncryptionKeyId, '42');
      expect(vault.currentSigningKeyId, '7');
    });

    test('retiring a key that is not in the vault changes nothing', () async {
      final vault = await _vault();
      vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));
      vault.currentEncryptionKeyId = '42';

      expect(vault.retireKey(99), isNull);
      expect(vault.currentEncryptionKeyId, '42');
    });
  });

  group('Vault.addKey server key id reconciliation', () {
    test(
      're-adding known material that has since been published back-fills its '
      'server key id, so retire/lookup by that id works',
      () async {
        final vault = await _vault();

        // A locally generated/imported encryption key: in the vault, but not
        // yet published, so it has no server key id.
        vault.addKey(_entry(fingerprint: 'ENCFP'));
        expect(vault.entries.single.keyId, isNull);

        // "Make active" publishes it and re-adds the same material, now
        // carrying the id the server minted.
        final merged = vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));

        expect(vault.entries, hasLength(1), reason: 'still deduped');
        expect(merged.keyId, 42);
        expect(
          vault.getKey(42),
          isNotNull,
          reason:
              'without this, every later lookup by server key id misses — '
              'including retireKey(), so deleting the key would silently fail '
              'to retire it and the next sync would resurrect it as active',
        );

        vault.currentEncryptionKeyId = '42';
        expect(vault.retireKey(42)!.status, 'retired');
        expect(vault.currentEncryptionKeyId, isNull);
      },
    );

    test(
      'an OpenPGP key id and its full fingerprint are the same key',
      () async {
        final vault = await _vault();
        // This client stores only the low 64 bits; office stores the full v4
        // fingerprint. One key, two spellings — deduping them as exact
        // strings put both in the vault and every client showed it twice.
        const full = 'B9672B00A358358D562F62BB742F90F6713A6750';
        vault.addKey(_entry(keyId: 33, fingerprint: full));
        vault.addKey(_entry(keyId: 33, fingerprint: full.substring(full.length - 16)));

        expect(vault.entries, hasLength(1));
        expect(vault.findKeyByFingerprint(full), isNotNull);
        expect(
          vault.findKeyByFingerprint(full.substring(full.length - 16)),
          isNotNull,
        );
      },
    );

    test('genuinely different keys stay apart', () async {
      final vault = await _vault();
      vault.addKey(_entry(keyId: 1, fingerprint: 'AAAA1111BBBB2222'));
      vault.addKey(
        _entry(keyId: 2, fingerprint: 'CCCC3333DDDD4444', material: [9, 9]),
      );
      expect(vault.entries, hasLength(2));
    });

    test(
      'an id already on the entry is never overwritten by a different one',
      () async {
        final vault = await _vault();
        vault.addKey(_entry(keyId: 7, fingerprint: 'ENCFP'));

        vault.addKey(_entry(keyId: 42, fingerprint: 'ENCFP'));

        expect(vault.entries.single.keyId, 7);
      },
    );
  });
}
