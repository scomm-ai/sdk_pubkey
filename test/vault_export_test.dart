import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

// Speed up Argon2id in tests — the production defaults
// (argon2idDefaultMemoryKib etc.) are correctly expensive, but running the
// full round-trip suite at that cost would be needlessly slow. Cheaper
// params are still real Argon2id calls, exercising the same code path.
const _testMemoryKib = 8;
const _testIterations = 1;
const _testParallelism = 1;

void main() {
  group('CryptoProvider.deriveArgon2id (EEK derivation)', () {
    test('is deterministic given the same passphrase/salt/params', () async {
      final crypto = DartCryptoProvider();
      final salt = crypto.random(eekSaltBytes);
      final a = await crypto.deriveArgon2id(
        utf8.encode('correct horse battery staple'),
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final b = await crypto.deriveArgon2id(
        utf8.encode('correct horse battery staple'),
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      expect(a, equals(b));
      expect(a, hasLength(32));
    });

    test('different passphrases derive different EEKs', () async {
      final crypto = DartCryptoProvider();
      final salt = crypto.random(eekSaltBytes);
      final a = await crypto.deriveArgon2id(
        utf8.encode('passphrase one'),
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final b = await crypto.deriveArgon2id(
        utf8.encode('passphrase two'),
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      expect(a, isNot(equals(b)));
    });

    test('different salts derive different EEKs for the same passphrase',
        () async {
      final crypto = DartCryptoProvider();
      final a = await crypto.deriveArgon2id(
        utf8.encode('same passphrase'),
        crypto.random(eekSaltBytes),
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final b = await crypto.deriveArgon2id(
        utf8.encode('same passphrase'),
        crypto.random(eekSaltBytes),
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      expect(a, isNot(equals(b)));
    });
  });

  group('VaultExport wrap/unwrap', () {
    test('round-trips VEK through a passphrase-derived EEK envelope',
        () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final eek = await VaultExport.deriveEek(
        crypto,
        'my export passphrase',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await VaultExport.wrapWithEek(
        crypto,
        eek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );

      final recovered = await VaultExport.unwrapWithEek(
        crypto,
        'my export passphrase',
        envelope,
      );
      expect(recovered, equals(vek));
    });

    test('wrong passphrase throws envelope_authentication_failure, no '
        'weaker fallback', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final eek = await VaultExport.deriveEek(
        crypto,
        'correct passphrase',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await VaultExport.wrapWithEek(
        crypto,
        eek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );

      expect(
        () => VaultExport.unwrapWithEek(crypto, 'wrong passphrase', envelope),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });

    test('tampered ciphertext throws envelope_authentication_failure',
        () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final eek = await VaultExport.deriveEek(
        crypto,
        'passphrase',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await VaultExport.wrapWithEek(
        crypto,
        eek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final tampered = ExportEnvelope(
        kdf: envelope.kdf,
        salt: envelope.salt,
        memory: envelope.memory,
        iterations: envelope.iterations,
        parallelism: envelope.parallelism,
        wrapped: WrappedKey(
          iv: envelope.wrapped.iv,
          ciphertext: Uint8List.fromList(envelope.wrapped.ciphertext)..[0] ^= 1,
        ),
      );

      expect(
        () => VaultExport.unwrapWithEek(crypto, 'passphrase', tampered),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });
  });

  group('VaultExport.buildExportFile / parseExportFile (file format)', () {
    Future<ExportEnvelope> envelopeFor(
      DartCryptoProvider crypto,
      Uint8List secret,
      String passphrase,
    ) async {
      final salt = crypto.random(eekSaltBytes);
      final eek = await VaultExport.deriveEek(
        crypto,
        passphrase,
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      return VaultExport.wrapWithEek(
        crypto,
        eek,
        secret,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
    }

    test('limited-tier file round-trips (no aek_envelope)', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final vekEnvelope = await envelopeFor(crypto, vek, 'passphrase');
      final ciphertext = Uint8List.fromList([1, 2, 3, 4]);
      final nonce = Uint8List.fromList([9, 9, 9]);
      final ciphertextHash = Uint8List.fromList([5, 5, 5]);

      final file = VaultExport.buildExportFile(
        identity: 'alice@example.com',
        tier: 'limited',
        createdAt: 1234,
        vekEnvelope: vekEnvelope,
        generation: 3,
        ciphertext: ciphertext,
        nonce: nonce,
        ciphertextHash: ciphertextHash,
      );

      expect(file['kind'], vaultExportKind);
      expect(file.containsKey('aek_envelope'), isFalse);

      final parsed = VaultExport.parseExportFile(file);
      expect(parsed.identity, 'alice@example.com');
      expect(parsed.tier, 'limited');
      expect(parsed.isFullTier, isFalse);
      expect(parsed.aekEnvelope, isNull);
      expect(parsed.generation, 3);
      expect(parsed.ciphertext, equals(ciphertext));
      expect(parsed.nonce, equals(nonce));
      expect(parsed.ciphertextHash, equals(ciphertextHash));
      expect(parsed.previousGenerationHash, isNull);

      final recoveredVek =
          await VaultExport.unwrapWithEek(crypto, 'passphrase', parsed.vekEnvelope!);
      expect(recoveredVek, equals(vek));
    });

    test('full-tier file round-trips (vek + aek envelopes)', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final aek = KeyHierarchy.generateAek(crypto);
      final vekEnvelope = await envelopeFor(crypto, vek, 'passphrase');
      final aekEnvelope = await envelopeFor(crypto, aek, 'passphrase');
      final prevHash = Uint8List.fromList([7, 7, 7]);

      final file = VaultExport.buildExportFile(
        identity: 'bob@example.com',
        tier: 'full',
        createdAt: 555,
        vekEnvelope: vekEnvelope,
        aekEnvelope: aekEnvelope,
        generation: 5,
        ciphertext: Uint8List.fromList([1]),
        nonce: Uint8List.fromList([2]),
        ciphertextHash: Uint8List.fromList([3]),
        previousGenerationHash: prevHash,
      );

      final parsed = VaultExport.parseExportFile(file);
      expect(parsed.isFullTier, isTrue);
      expect(parsed.aekEnvelope, isNotNull);
      expect(parsed.previousGenerationHash, equals(prevHash));

      final recoveredVek =
          await VaultExport.unwrapWithEek(crypto, 'passphrase', parsed.vekEnvelope!);
      final recoveredAek = await VaultExport.unwrapWithEek(
        crypto,
        'passphrase',
        parsed.aekEnvelope!,
      );
      expect(recoveredVek, equals(vek));
      expect(recoveredAek, equals(aek));
    });

    test('vault-only file (no password protection) round-trips with no '
        'vek_envelope/aek_envelope at all', () {
      final ciphertext = Uint8List.fromList([1, 2, 3, 4]);
      final nonce = Uint8List.fromList([9, 9, 9]);
      final ciphertextHash = Uint8List.fromList([5, 5, 5]);

      final file = VaultExport.buildExportFile(
        identity: 'alice@example.com',
        tier: 'full',
        createdAt: 1234,
        generation: 3,
        ciphertext: ciphertext,
        nonce: nonce,
        ciphertextHash: ciphertextHash,
      );

      expect(file.containsKey('vek_envelope'), isFalse);
      expect(file.containsKey('aek_envelope'), isFalse);

      final parsed = VaultExport.parseExportFile(file);
      expect(parsed.hasSecrets, isFalse);
      expect(parsed.vekEnvelope, isNull);
      expect(parsed.aekEnvelope, isNull);
      expect(parsed.ciphertext, equals(ciphertext));
    });

    test('building an aek_envelope without a vek_envelope throws', () async {
      final crypto = DartCryptoProvider();
      final aekEnvelope = await envelopeFor(
        crypto,
        KeyHierarchy.generateAek(crypto),
        'passphrase',
      );
      expect(
        () => VaultExport.buildExportFile(
          identity: 'a@example.com',
          tier: 'full',
          createdAt: 0,
          aekEnvelope: aekEnvelope,
          generation: 1,
          ciphertext: Uint8List(0),
          nonce: Uint8List(0),
          ciphertextHash: Uint8List(0),
        ),
        throwsA(isA<PubkeyException>()),
      );
    });

    test('building a full-tier file without an aek_envelope throws', () async {
      final crypto = DartCryptoProvider();
      final vekEnvelope = await envelopeFor(
        crypto,
        KeyHierarchy.generateVek(crypto),
        'passphrase',
      );
      expect(
        () => VaultExport.buildExportFile(
          identity: 'a@example.com',
          tier: 'full',
          createdAt: 0,
          vekEnvelope: vekEnvelope,
          generation: 1,
          ciphertext: Uint8List(0),
          nonce: Uint8List(0),
          ciphertextHash: Uint8List(0),
        ),
        throwsA(isA<PubkeyException>()),
      );
    });

    test('parsing a non-export-file (wrong "kind") throws '
        'vault_export_format_unsupported', () {
      expect(
        () => VaultExport.parseExportFile({'kind': 'CKVF', 'format': 1}),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultExportFormatUnsupported,
          ),
        ),
      );
    });

    test('parsing an unsupported format_version throws', () async {
      final crypto = DartCryptoProvider();
      final vekEnvelope = await envelopeFor(
        crypto,
        KeyHierarchy.generateVek(crypto),
        'passphrase',
      );
      final file = VaultExport.buildExportFile(
        identity: 'a@example.com',
        tier: 'limited',
        createdAt: 0,
        vekEnvelope: vekEnvelope,
        generation: 1,
        ciphertext: Uint8List(0),
        nonce: Uint8List(0),
        ciphertextHash: Uint8List(0),
      );
      (file['header'] as Map)['format_version'] = 999;

      expect(
        () => VaultExport.parseExportFile(file),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.vaultExportFormatUnsupported,
          ),
        ),
      );
    });

    test('the passphrase itself never appears anywhere in the serialized '
        'file JSON', () async {
      final crypto = DartCryptoProvider();
      const secretPassphrase = 'xyzzy-plugh-do-not-leak-this-9182';
      final vek = KeyHierarchy.generateVek(crypto);
      final aek = KeyHierarchy.generateAek(crypto);
      final vekEnvelope = await envelopeFor(crypto, vek, secretPassphrase);
      final aekEnvelope = await envelopeFor(crypto, aek, secretPassphrase);

      final file = VaultExport.buildExportFile(
        identity: 'carol@example.com',
        tier: 'full',
        createdAt: 42,
        vekEnvelope: vekEnvelope,
        aekEnvelope: aekEnvelope,
        generation: 1,
        ciphertext: Uint8List.fromList([1, 2, 3]),
        nonce: Uint8List.fromList([4, 5]),
        ciphertextHash: Uint8List.fromList([6, 7]),
      );

      final serialized = jsonEncode(file);
      expect(serialized.contains(secretPassphrase), isFalse);
      // Also not present base64-encoded or in any other transformed form
      // that would be suspicious to find verbatim.
      expect(serialized.toLowerCase().contains('passphrase'), isFalse);
    });
  });
}
