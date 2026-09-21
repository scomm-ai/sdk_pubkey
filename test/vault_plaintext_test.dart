import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

Future<Map<String, dynamic>> _decodedPlaintext(
  DartCryptoProvider crypto,
  Vault vault,
  Uint8List vek,
) async {
  final exported = await vault.exportVault(vek);
  final unwrapped = await KeyHierarchy.decryptVaultCiphertextWithVek(
    crypto,
    vek,
    WrappedKey(
      iv: decodeBase64Url((exported['encryption'] as Map)['iv'] as String),
      ciphertext: decodeBase64Url(exported['ciphertext'] as String),
    ),
  );
  return Map<String, dynamic>.from(jsonDecode(utf8.decode(unwrapped)) as Map);
}

void main() {
  group('VaultPlaintext', () {
    test('splits entries into openpgp_keys/smime_keys/signing_keys on export',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'pgp1',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });
      vault.addKey({
        'kind': 'content',
        'key_id': 2,
        'family': 'smime',
        'fingerprint': 'smime1',
        'status': 'active',
        'certificate': encodeBase64Url(Uint8List.fromList([9, 9])),
        'private_material': encodeBase64Url(Uint8List.fromList([2])),
      });
      vault.addKey({
        'kind': 'content',
        'key_id': 3,
        'purpose': 'device-auth',
        'fingerprint': 'sig1',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([3])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);

      expect((plaintext['openpgp_keys'] as List).single['type'], 'encryption');
      expect((plaintext['smime_keys'] as List).single['cert_id'], '2');
      expect((plaintext['smime_keys'] as List).single['certificate'], isNotNull);
      expect((plaintext['signing_keys'] as List).single['purpose'], 'device-auth');
      expect(plaintext['legacy_entries'], isEmpty);
    });

    test('post-quantum entries fall back to legacy_entries (out of scope for this pass)',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'family': 'pq',
        'purpose': 'kem',
        'fingerprint': 'pq1',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([7])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);

      expect(plaintext['openpgp_keys'], isEmpty);
      expect(plaintext['smime_keys'], isEmpty);
      expect(plaintext['signing_keys'], isEmpty);
      expect((plaintext['legacy_entries'] as List).single['family'], 'pq');

      // Round-trips back through Vault without data loss.
      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      expect(restored.getKeyByFingerprint('pq1')?.family, 'pq');
    });

    test('RFC 9980 OpenPGP keys persist on openpgp_keys, not legacy_entries',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'key_id': 8,
        'family': 'pgp',
        'purpose': 'encryption',
        'algorithm': 'openpgp-mlkem768-x25519',
        'fingerprint': 'pgp-pqc',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([8])),
      });
      vault.addKey({
        'kind': 'content',
        'key_id': 9,
        'family': 'pgp',
        'purpose': 'signing',
        'algorithm': 'openpgp-mldsa65-ed25519',
        'fingerprint': 'pgp-pqc-sign',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([9])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      final openPgp = plaintext['openpgp_keys'] as List;
      expect(openPgp, hasLength(2));
      expect(
        openPgp.map((e) => (e as Map)['algorithm']),
        containsAll(['openpgp-mlkem768-x25519', 'openpgp-mldsa65-ed25519']),
      );
      expect(plaintext['legacy_entries'], isEmpty);
    });

    test('legacy_entries also use the spec status vocabulary', () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'family': 'pq',
        'fingerprint': 'pq2',
        'status': 'retired',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      expect((plaintext['legacy_entries'] as List).single['status'], 'historical');

      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      expect(restored.getKeyByFingerprint('pq2')?.status, 'retired');
    });

    test('smime entry with no fingerprint stays fingerprint-less on round-trip',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'key_id': 9,
        'family': 'smime',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      expect((plaintext['smime_keys'] as List).single['fingerprint'], isNull);

      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      // Must NOT have synthesized a fingerprint equal to cert_id — that
      // would change the entry's identity across export/import.
      expect(restored.getKeyByFingerprint('9'), isNull);
      expect(restored.getKey(9)?.fingerprint, isNull);
    });

    test('a null created_at is omitted, never fabricated as epoch 0', () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      // Bypass addKey's auto-stamping to exercise a genuinely absent
      // created_at, as an externally-imported entry might have.
      vault.entries.add(VaultEntry(
        kind: 'content',
        family: 'pgp',
        purpose: 'encryption',
        fingerprint: 'no-created-at',
        privateMaterial: Uint8List.fromList([1]),
      ));
      vault.entries.add(VaultEntry(
        kind: 'content',
        family: 'smime',
        fingerprint: 'no-created-at-2',
        privateMaterial: Uint8List.fromList([2]),
      ));

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      expect((plaintext['openpgp_keys'] as List).single.containsKey('created_at'), isFalse);
      expect((plaintext['smime_keys'] as List).single.containsKey('created_at'), isFalse);

      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      expect(restored.getKeyByFingerprint('no-created-at')?.createdAt, isNull);
      expect(restored.getKeyByFingerprint('no-created-at-2')?.createdAt, isNull);
    });

    test('status vocabulary: internal "retired" maps to spec "historical"',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'pgp1',
        'status': 'retired',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      expect((plaintext['openpgp_keys'] as List).single['status'], 'historical');

      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      expect(restored.getKeyByFingerprint('pgp1')?.status, 'retired');
    });

    test('generation, current_signing_key_id, and metadata.devices round-trip',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      vault.generation = 3;
      vault.currentSigningKeyId = 'sk-42';
      vault.currentEncryptionKeyId = 'ek-7';
      vault.devices = [
        const DeviceMetadata(
          deviceId: 'dev-1',
          name: "Alice's laptop",
          tier: 'full',
          addedAt: 1000,
          addedBy: 'dev-1',
        ),
      ];

      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext = await _decodedPlaintext(crypto, vault, vek);
      expect(plaintext['generation'], 3);
      expect(plaintext['current_signing_key_id'], 'sk-42');
      expect(plaintext['current_encryption_key_id'], 'ek-7');
      expect((plaintext['metadata'] as Map)['devices'], hasLength(1));

      final restored = Vault(crypto: crypto);
      await restored.importVault(await vault.exportVault(vek), vek);
      expect(restored.generation, 3);
      expect(restored.currentSigningKeyId, 'sk-42');
      expect(restored.currentEncryptionKeyId, 'ek-7');
      expect(restored.devices.single.deviceId, 'dev-1');
      expect(restored.devices.single.tier, 'full');
    });

    test('a freshly created vault defaults generation to 0 and has no devices',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      expect(vault.generation, 0);
      expect(vault.currentSigningKeyId, isNull);
      expect(vault.currentEncryptionKeyId, isNull);
      expect(vault.devices, isEmpty);
    });

    test('addKey stamps created_at when absent, preserves it when present',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      final stamped = vault.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'a',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });
      expect(stamped.createdAt, isNotNull);

      final explicit = vault.addKey({
        'kind': 'content',
        'family': 'pgp',
        'purpose': 'encryption',
        'fingerprint': 'b',
        'created_at': 123,
        'private_material': encodeBase64Url(Uint8List.fromList([2])),
      });
      expect(explicit.createdAt, 123);
    });
  });
}
