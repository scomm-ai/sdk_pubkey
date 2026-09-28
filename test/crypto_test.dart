import 'openssl_crypto.dart';
import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  OpensslCryptoProvider.installDigests();
  group('DartCryptoProvider', () {
    test('generates Ed25519 keys and verifies signatures', () async {
      final crypto = opensslCrypto();
      final key = await crypto.generateSigningKey('ed25519');
      expect(key.publicKey, isNotNull);
      expect(key.publicKey, hasLength(32));
      expect(key.provider, 'openssl');
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
      final crypto = opensslCrypto();
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
      final crypto = opensslCrypto();
      final key = await crypto.generateDeviceKey(extractable: true);
      expect(key.algorithm, mskAlgorithm);
      expect(key.protection, KeyProtection.software);
      expect(key.publicKey, isNotNull);
    });

    test('refuses hardware-backed generation', () async {
      final crypto = opensslCrypto();
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
      final crypto = opensslCrypto();
      final alice = await crypto.generateKey(algorithm: 'x25519');
      final bob = await crypto.generateKey(algorithm: 'x25519');
      final ab = await crypto.deriveSecret(alice, bob.publicKey!);
      final ba = await crypto.deriveSecret(bob, alice.publicKey!);
      expect(ab, ba);
    });

    test('hashes with SHA-256', () async {
      final crypto = opensslCrypto();
      final digest = await crypto.hash('sha-256', utf8.encode('abc'));
      expect(
        digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('PGP/S/MIME/PQ methods throw unsupported_algorithm', () async {
      final crypto = opensslCrypto();
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
      final registry = createCryptoRegistry([opensslCrypto()]);
      final provider = await registry.select(
        operation: CryptoOperations.sign,
        algorithm: 'ed25519',
      );
      expect(provider.id, 'openssl');
    });

    test('does not silently create software keys when hardware is required', () async {
      final registry = CryptoProviderRegistry([
        opensslCrypto(),
        _Unavailable('apple'),
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
      final caps = await protocolCapabilitiesFromProvider(opensslCrypto());
      expect(caps['families']['pgp'], isNull);
      expect(caps['families']['pq'], isNull);
      expect(caps['families']['smime'], isNull);
    });

    test('native stub reports provider_unavailable', () async {
      final native = _Unavailable('android');
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

class _Unavailable extends CryptoProvider {
  _Unavailable(this.platform);

  final String platform;

  @override
  String get id => 'native-$platform';

  @override
  String get kind => 'platform';

  Never _no() {
    throw PubkeyException(ErrorCodes.providerUnavailable, 'unavailable');
  }

  @override
  Future<CryptoCapabilities> capabilities() async => CryptoCapabilities(
        id: id,
        kind: kind,
        sign: const [],
        verify: const [],
        keyAgreement: const [],
        aead: const [],
        hash: const [],
        kem: const [],
        protections: const [KeyProtection.hardwareBacked],
        extractable: const [false],
        random: false,
      );

  @override
  Future<bool> supports(
    String operation,
    String algorithm, {
    bool? extractable,
    String? protection,
    String? purpose,
  }) async =>
      false;

  @override
  Uint8List random(int length) => _no();

  @override
  Future<Uint8List> hash(String algorithm, List<int> data) async => _no();

  @override
  Future<KeyRef> generateKey({
    required String algorithm,
    String? purpose,
    bool extractable = true,
    String protection = KeyProtection.software,
  }) async =>
      _no();

  @override
  Future<Uint8List> sign(KeyRef key, List<int> payload) async => _no();

  @override
  Future<bool> verify(
    List<int> publicKey,
    List<int> payload,
    List<int> signature, [
    String algorithm = mskAlgorithm,
  ]) async =>
      _no();

  @override
  Future<KeyRef> importPrivateKey(
    PortablePrivateKey portable, {
    bool? extractable,
    String protection = KeyProtection.software,
  }) async =>
      _no();

  @override
  Future<PortablePrivateKey> exportPrivateKey(KeyRef key) async => _no();
}
