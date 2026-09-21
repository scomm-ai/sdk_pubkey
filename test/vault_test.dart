import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('Vault', () {
    test('exports, imports, and retains historical keys', () async {
      final crypto = DartCryptoProvider();
      final store = MemoryVaultStore();
      final vault = Vault(crypto: crypto, store: store);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      final msk = await crypto.generateSigningKey('ed25519');
      final portable = await crypto.exportPrivateKey(msk);
      final aek = KeyHierarchy.generateAek(crypto);
      await vault.setMsk(aek: aek, msk: portable);
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'family': 'pgp',
        'purpose': 'encryption',
        'algorithm': 'openpgp-cv25519',
        'fingerprint': 'k1',
        'status': 'retired',
        'private_material': encodeBase64Url(Uint8List.fromList([1, 2, 3])),
      });
      vault.addKey({
        'kind': 'content',
        'key_id': 2,
        'family': 'smime',
        'purpose': 'encryption',
        'algorithm': 'smime-mlkem-768',
        'fingerprint': 'k2',
        'status': 'active',
        'private_material': encodeBase64Url(Uint8List.fromList([4, 5, 6])),
      });

      final vek = KeyHierarchy.generateVek(crypto);
      final exported = await vault.exportVault(vek);
      expect(exported['vault_format_version'], 1);
      expect(exported['ciphertext'], isA<String>());
      expect(jsonEncode(exported).contains('private_material'), isFalse);

      final restored = Vault(crypto: crypto, store: MemoryVaultStore());
      await restored.importVault(exported, vek);
      expect(restored.getHistoricalKey(1)?.fingerprint, 'k1');
      expect(restored.getCurrentKey('encryption')?.keyId, 2);
      expect(await restored.unwrapMsk(aek), equals(portable.bytes));
    });

    test('unions different fingerprints even when generation key_id matches',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'purpose': 'encryption',
        'fingerprint': 'aaa',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
        'status': 'active',
      });
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'purpose': 'encryption',
        'fingerprint': 'bbb',
        'private_material': encodeBase64Url(Uint8List.fromList([2])),
        'status': 'active',
      });
      expect(vault.listKeys(), hasLength(2));
    });

    test('rejects the same fingerprint with different secret material',
        () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'purpose': 'encryption',
        'fingerprint': 'aaa',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
        'status': 'active',
      });
      expect(
        () => vault.addKey({
          'kind': 'content',
          'key_id': 2,
          'purpose': 'encryption',
          'fingerprint': 'aaa',
          'private_material': encodeBase64Url(Uint8List.fromList([2])),
          'status': 'active',
        }),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultIntegrity,
          ),
        ),
      );
    });

    test('exports and imports a password-wrapped single-key package', () async {
      final crypto = DartCryptoProvider();
      final source = Vault(crypto: crypto);
      final target = Vault(crypto: crypto);
      await source.createVault('p');
      await target.createVault('p');
      source.addKey({
        'kind': 'content',
        'key_id': 3,
        'family': 'pgp',
        'locator': 'ab12cd34ef567890',
        'purpose': 'encryption',
        'fingerprint': 'fp-1',
        'private_material': encodeBase64Url(Uint8List.fromList([9, 8, 7])),
        'status': 'active',
      });
      final pkg = await source.exportKeyPackage('fp-1', 'transfer-pass');
      expect(pkg['kind'], 'scomm-key-package');
      expect(pkg['locator'], 'AB12-CD34-EF56-7890');
      expect(jsonEncode(pkg).contains('private_material'), isFalse);
      await target.importKeyPackage(pkg, 'transfer-pass');
      expect(target.getKeyByFingerprint('fp-1')?.locator, 'AB12-CD34-EF56-7890');
    });

    test('merges the union of historical keys', () async {
      final crypto = DartCryptoProvider();
      final a = Vault(crypto: crypto);
      final b = Vault(crypto: crypto);
      await a.createVault('p');
      await b.createVault('p');
      a.addKey({
        'kind': 'content',
        'key_id': 1,
        'purpose': 'encryption',
        'fingerprint': 'one',
        'status': 'retired',
      });
      b.addKey({
        'kind': 'content',
        'key_id': 2,
        'purpose': 'encryption',
        'fingerprint': 'two',
        'status': 'active',
      });
      a.merge(b);
      expect(a.listKeys(), hasLength(2));
      expect(a.getHistoricalKey(1)?.fingerprint, 'one');
    });

    test('throws vault_locked and vault_authentication_failure', () async {
      final crypto = DartCryptoProvider();
      final store = MemoryVaultStore();
      final vault = Vault(crypto: crypto, store: store);
      await vault.createVault('9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976');
      vault.addKey({
        'kind': 'content',
        'key_id': 1,
        'purpose': 'encryption',
        'fingerprint': 'k1',
        'status': 'retired',
        'private_material': encodeBase64Url(Uint8List.fromList([1, 2, 3])),
      });
      final vek = KeyHierarchy.generateVek(crypto);
      await vault.persist(vek);
      vault.lockVault();
      expect(
        () => vault.listKeys(),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultLocked,
          ),
        ),
      );

      final other = Vault(crypto: crypto, store: store);
      expect(
        () => other.unlockVault(KeyHierarchy.generateVek(crypto)),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultAuthenticationFailure,
          ),
        ),
      );

      await other.unlockVault(vek);
      expect(other.getHistoricalKey(1)?.fingerprint, 'k1');
    });

    test('rejects different secrets for the same fingerprint and persists lastCiphertextHash', () async {
      final crypto = DartCryptoProvider();
      final store = MemoryVaultStore();
      final vault = Vault(crypto: crypto, store: store);
      await vault.createVault('p');
      vault.addKey({
        'kind': 'content',
        'fingerprint': 'same',
        'private_material': encodeBase64Url(Uint8List.fromList([1])),
      });
      expect(
        () => vault.addKey({
          'kind': 'content',
          'fingerprint': 'same',
          'private_material': encodeBase64Url(Uint8List.fromList([2])),
        }),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultIntegrity,
          ),
        ),
      );
      vault.lastCiphertextHash = Uint8List.fromList(List.filled(32, 7));
      final vek = KeyHierarchy.generateVek(crypto);
      await vault.persist(vek);
      final other = Vault(crypto: crypto, store: store);
      await other.unlockVault(vek);
      expect(other.lastCiphertextHash, vault.lastCiphertextHash);
    });

    test('a VEK-only unwrap of the MSK envelope fails (Boundary B4)', () async {
      final crypto = DartCryptoProvider();
      final vault = Vault(crypto: crypto);
      await vault.createVault('p');
      final msk = await crypto.generateSigningKey('ed25519');
      final portable = await crypto.exportPrivateKey(msk);
      final aek = KeyHierarchy.generateAek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      await vault.setMsk(aek: aek, msk: portable);
      expect(
        () => vault.unwrapMsk(vek),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.deviceNotAuthorized,
          ),
        ),
      );
      expect(await vault.unwrapMsk(aek), equals(portable.bytes));
    });
  });
}
