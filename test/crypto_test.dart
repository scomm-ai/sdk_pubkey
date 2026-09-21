import 'dart:convert';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('DartCryptoProvider', () {
    test('generates Ed25519 keys and verifies signatures', () async {
      final crypto = DartCryptoProvider();
      final key = await crypto.generateSigningKey('ed25519');
      expect(key.publicKey, isNotNull);
      expect(key.publicKey, hasLength(32));
      expect(key.provider, 'dart-software');
      expect(key.extractable, isTrue);
      final payload = canonicalSignedBytes(
        protocolVersion: 1,
        operation: 'set_keys',
        principal: '9a28dce8-36a8-8cad-a0e2-8eaaa8c6d976',
        timestamp: 1780000000000,
        nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
        payload: {'ok': true},
      );
      final signature = await crypto.sign(key, payload);
      expect(
        await crypto.verify(key.publicKey!, payload, signature, 'ed25519'),
        isTrue,
      );
      payload[0] = payload[0] ^ 1;
      expect(
        await crypto.verify(key.publicKey!, payload, signature, 'ed25519'),
        isFalse,
      );
    });

    test('refuses export of non-extractable keys', () async {
      final crypto = DartCryptoProvider();
      final key = await crypto.generateSigningKey(
        'ed25519',
        const KeyGenerateOptions(extractable: false),
      );
      expect(key.extractable, isFalse);
      expect(
        () => crypto.exportPrivateKey(key),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.keyNotExportable,
          ),
        ),
      );
    });

    test('generateDeviceKey falls back to software without a native provider',
        () async {
      final crypto = DartCryptoProvider();
      final key = await crypto.generateDeviceKey(extractable: true);
      expect(key.algorithm, mskAlgorithm);
      expect(key.protection, KeyProtection.software);
      expect(key.publicKey, isNotNull);
    });

    test('refuses hardware-backed generation', () async {
      final crypto = DartCryptoProvider();
      expect(
        () => crypto.generateSigningKey(
          'ed25519',
          const KeyGenerateOptions(protection: KeyProtection.hardwareBacked),
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.hardwareProtectionUnavailable,
          ),
        ),
      );
    });

    test('performs X25519 key agreement', () async {
      final crypto = DartCryptoProvider();
      final alice = await crypto.generateKey(algorithm: 'x25519');
      final bob = await crypto.generateKey(algorithm: 'x25519');
      final ab = await crypto.deriveSecret(alice, bob.publicKey!);
      final ba = await crypto.deriveSecret(bob, alice.publicKey!);
      expect(ab, ba);
    });

    test('hashes with SHA-256', () async {
      final crypto = DartCryptoProvider();
      final digest = await crypto.hash('sha-256', utf8.encode('abc'));
      expect(
        digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('PGP/S/MIME/PQ methods throw unsupported_algorithm', () async {
      final crypto = DartCryptoProvider();
      expect(
        () => crypto.generateEncryptionKey('openpgp-cv25519'),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.unsupportedAlgorithm,
          ),
        ),
      );
      expect(
        () => crypto.encrypt(algorithm: 'smime-x25519'),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.unsupportedAlgorithm,
          ),
        ),
      );
      expect(
        () => crypto.decrypt(algorithm: 'pqc-mlkem-768'),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.unsupportedAlgorithm,
          ),
        ),
      );
    });
  });

  group('CryptoProviderRegistry', () {
    test('selects the software provider for Ed25519', () async {
      final registry = createDefaultDartRegistry();
      final provider = await registry.select(
        operation: CryptoOperations.sign,
        algorithm: 'ed25519',
      );
      expect(provider.id, 'dart-software');
    });

    test('does not silently create software keys when hardware is required', () async {
      final registry = CryptoProviderRegistry([
        DartCryptoProvider(),
        UnimplementedNativeCryptoProvider('apple'),
      ]);
      expect(
        () => registry.select(
          operation: CryptoOperations.sign,
          algorithm: 'ed25519',
          protection: KeyProtection.hardwareBacked,
          protectionLevel: RequirementLevels.required,
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.hardwareProtectionUnavailable,
          ),
        ),
      );
    });

    test('maps primitives to protocol families without inventing PGP/S/MIME', () async {
      final caps = await protocolCapabilitiesFromProvider(DartCryptoProvider());
      expect(caps['families']['pgp'], isNull);
      expect(caps['families']['pq'], isNull);
      expect(caps['families']['smime'], isNull);
    });

    test('native stub reports provider_unavailable', () async {
      final native = UnimplementedNativeCryptoProvider('android');
      expect(await native.supports(CryptoOperations.sign, 'ed25519'), isFalse);
      expect(
        () => native.generateSigningKey(),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.providerUnavailable,
          ),
        ),
      );
    });
  });
}
