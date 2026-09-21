import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/vault/bip39_wordlist.dart';
import 'package:test/test.dart';

// Speed up Argon2id in tests — see vault_export_test.dart's identical note.
const _testMemoryKib = 8;
const _testIterations = 1;
const _testParallelism = 1;

void main() {
  group('RecoveryCode.generateBip39Words (setup)', () {
    test('generates 24 space-separated lowercase words by default', () {
      final crypto = DartCryptoProvider();
      final phrase = RecoveryCode.generateBip39Words(crypto);
      final words = phrase.split(' ');
      expect(words, hasLength(24));
      expect(phrase, equals(phrase.toLowerCase()));
    });

    test('generates 12 words when requested', () {
      final crypto = DartCryptoProvider();
      final phrase = RecoveryCode.generateBip39Words(crypto, wordCount: 12);
      expect(phrase.split(' '), hasLength(12));
    });

    test('rejects an unsupported word count', () {
      final crypto = DartCryptoProvider();
      expect(
        () => RecoveryCode.generateBip39Words(crypto, wordCount: 15),
        throwsA(isA<PubkeyException>()),
      );
    });

    test('two calls produce different phrases (CSPRNG-backed, not fixed)',
        () {
      final crypto = DartCryptoProvider();
      final a = RecoveryCode.generateBip39Words(crypto);
      final b = RecoveryCode.generateBip39Words(crypto);
      expect(a, isNot(equals(b)));
    });

    test('every word comes from the standard 2048-word BIP-39 English '
        'wordlist, and the mnemonic carries a valid BIP-39 checksum', () {
      final crypto = DartCryptoProvider();
      for (final wordCount in [12, 24]) {
        final phrase =
            RecoveryCode.generateBip39Words(crypto, wordCount: wordCount);
        final words = phrase.split(' ');
        final indices = words.map((w) {
          final i = bip39EnglishWordlist.indexOf(w);
          expect(i, greaterThanOrEqualTo(0), reason: 'unknown word "$w"');
          return i;
        }).toList();

        // Reconstruct the bit string and split entropy || checksum exactly
        // as BIP-39 defines (ENT bits of entropy, ENT/32 bits of checksum),
        // then recompute the checksum independently and compare — this
        // fails if the implementation ever drifts from the real algorithm.
        final bits = indices
            .map((i) => i.toRadixString(2).padLeft(11, '0'))
            .join();
        final entropyBits = wordCount == 24 ? 256 : 128;
        final checksumBits = entropyBits ~/ 32;
        expect(bits.length, entropyBits + checksumBits);
        final entropyBitString = bits.substring(0, entropyBits);
        final claimedChecksum = bits.substring(entropyBits);

        final entropyBytes = Uint8List(entropyBits ~/ 8);
        for (var i = 0; i < entropyBytes.length; i++) {
          entropyBytes[i] =
              int.parse(entropyBitString.substring(i * 8, i * 8 + 8), radix: 2);
        }
        final hash = sha256Bytes(entropyBytes);
        final hashBits =
            hash.map((b) => b.toRadixString(2).padLeft(8, '0')).join();
        expect(hashBits.substring(0, checksumBits), claimedChecksum);
      }
    });
  });

  group('RecoveryCode.generateRandomCode (setup)', () {
    test('generates an uppercase Crockford base32 string of the expected '
        'length', () {
      final crypto = DartCryptoProvider();
      final code = RecoveryCode.generateRandomCode(crypto);
      // 20 bytes = 160 bits -> ceil(160/5) = 32 symbols.
      expect(code, hasLength(32));
      expect(code, equals(code.toUpperCase()));
      expect(RegExp(r'^[0-9A-HJKMNP-TV-Z]+$').hasMatch(code), isTrue);
    });

    test('honors a custom lengthBytes', () {
      final crypto = DartCryptoProvider();
      final code = RecoveryCode.generateRandomCode(crypto, lengthBytes: 5);
      expect(code, hasLength(8));
    });

    test('two calls produce different codes', () {
      final crypto = DartCryptoProvider();
      final a = RecoveryCode.generateRandomCode(crypto);
      final b = RecoveryCode.generateRandomCode(crypto);
      expect(a, isNot(equals(b)));
    });
  });

  group('RecoveryCode.normalize', () {
    test('collapses whitespace and lowercases a bip39 phrase', () {
      expect(
        RecoveryCode.normalize('  Alpha   Bravo  Charlie ',
            format: RecoveryCodeFormats.bip39),
        equals('alpha bravo charlie'),
      );
    });

    test('strips spaces and uppercases a random code', () {
      expect(
        RecoveryCode.normalize(' ab12 cd34 ',
            format: RecoveryCodeFormats.random),
        equals('AB12CD34'),
      );
    });
  });

  group('RecoveryCode REK derive/wrap/unwrap', () {
    test('is deterministic given the same code/salt/params', () async {
      final crypto = DartCryptoProvider();
      final salt = crypto.random(eekSaltBytes);
      final a = await RecoveryCode.deriveRek(
        crypto,
        'zebra unicorn dragon',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final b = await RecoveryCode.deriveRek(
        crypto,
        'zebra unicorn dragon',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      expect(a, equals(b));
      expect(a, hasLength(32));
    });

    test('round-trips VEK through a recovery-code-derived REK envelope',
        () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final rek = await RecoveryCode.deriveRek(
        crypto,
        'my recovery code',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );

      final recovered = await RecoveryCode.unwrapRecovery(
        crypto,
        'my recovery code',
        envelope,
      );
      expect(recovered, equals(vek));
    });

    test('round-trips AEK too, under the same REK/salt as VEK (full scope)',
        () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final aek = KeyHierarchy.generateAek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final rek = await RecoveryCode.deriveRek(
        crypto,
        'full scope code',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final vekEnvelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final aekEnvelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
        aek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );

      expect(
        await RecoveryCode.unwrapRecovery(crypto, 'full scope code', vekEnvelope),
        equals(vek),
      );
      expect(
        await RecoveryCode.unwrapRecovery(crypto, 'full scope code', aekEnvelope),
        equals(aek),
      );
    });

    test('wrong recovery code throws envelope_authentication_failure, no '
        'weaker fallback', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final rek = await RecoveryCode.deriveRek(
        crypto,
        'correct code',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );

      expect(
        () => RecoveryCode.unwrapRecovery(crypto, 'wrong code', envelope),
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
      final rek = await RecoveryCode.deriveRek(
        crypto,
        'a code',
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
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
        () => RecoveryCode.unwrapRecovery(crypto, 'a code', tampered),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });

    test('the recovery code itself never appears in the wrapped envelope\'s '
        'JSON', () async {
      final crypto = DartCryptoProvider();
      const secretCode = 'zzz-do-not-leak-this-recovery-code-4471';
      final vek = KeyHierarchy.generateVek(crypto);
      final salt = crypto.random(eekSaltBytes);
      final rek = await RecoveryCode.deriveRek(
        crypto,
        secretCode,
        salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final envelope = await RecoveryCode.wrapForRecovery(
        crypto,
        rek,
        vek,
        salt: salt,
        memory: _testMemoryKib,
        iterations: _testIterations,
        parallelism: _testParallelism,
      );
      final serialized = jsonEncode(envelope.toJson());
      expect(serialized.contains(secretCode), isFalse);
    });
  });
}
