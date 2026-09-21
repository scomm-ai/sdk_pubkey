import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('KeyHierarchy generation', () {
    test('AEK/VEK/DKEK are 256-bit and not equal to each other', () {
      final crypto = DartCryptoProvider();
      final aek = KeyHierarchy.generateAek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final dkek = KeyHierarchy.generateDkek(crypto);
      expect(aek, hasLength(32));
      expect(vek, hasLength(32));
      expect(dkek, hasLength(32));
      expect(aek, isNot(equals(vek)));
      expect(aek, isNot(equals(dkek)));
      expect(vek, isNot(equals(dkek)));
    });

    test('two calls never produce the same key (CSPRNG, not deterministic)',
        () {
      final crypto = DartCryptoProvider();
      final a = KeyHierarchy.generateVek(crypto);
      final b = KeyHierarchy.generateVek(crypto);
      expect(a, isNot(equals(b)));
    });
  });

  group('DKEK wraps VEK/AEK (DeviceEnvelope/AuthorityEnvelope)', () {
    test('round-trips VEK through a DKEK envelope', () async {
      final crypto = DartCryptoProvider();
      final dkek = KeyHierarchy.generateDkek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final envelope = await KeyHierarchy.wrapWithDkek(crypto, dkek, vek);
      final recovered =
          await KeyHierarchy.unwrapWithDkek(crypto, dkek, envelope);
      expect(recovered, equals(vek));
    });

    test('round-trips AEK through a DKEK envelope', () async {
      final crypto = DartCryptoProvider();
      final dkek = KeyHierarchy.generateDkek(crypto);
      final aek = KeyHierarchy.generateAek(crypto);
      final envelope = await KeyHierarchy.wrapWithDkek(crypto, dkek, aek);
      final recovered =
          await KeyHierarchy.unwrapWithDkek(crypto, dkek, envelope);
      expect(recovered, equals(aek));
    });

    test('wrong DKEK fails with envelope_authentication_failure, no fallback',
        () async {
      final crypto = DartCryptoProvider();
      final dkek = KeyHierarchy.generateDkek(crypto);
      final wrongDkek = KeyHierarchy.generateDkek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final envelope = await KeyHierarchy.wrapWithDkek(crypto, dkek, vek);
      expect(
        () => KeyHierarchy.unwrapWithDkek(crypto, wrongDkek, envelope),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });

    test('tampered ciphertext fails to unwrap', () async {
      final crypto = DartCryptoProvider();
      final dkek = KeyHierarchy.generateDkek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final envelope = await KeyHierarchy.wrapWithDkek(crypto, dkek, vek);
      final tampered = WrappedKey(
        iv: envelope.iv,
        ciphertext: Uint8List.fromList(
          envelope.ciphertext.map((b) => b).toList()
            ..[0] = envelope.ciphertext[0] ^ 1,
        ),
      );
      expect(
        () => KeyHierarchy.unwrapWithDkek(crypto, dkek, tampered),
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

  group('AEK wraps MSK private key (Boundary B4)', () {
    test('round-trips an MSK private key through an AEK envelope', () async {
      final crypto = DartCryptoProvider();
      final aek = KeyHierarchy.generateAek(crypto);
      final msk = await crypto.generateSigningKey('ed25519');
      final portable = await crypto.exportPrivateKey(msk);
      final envelope =
          await KeyHierarchy.wrapMskWithAek(crypto, aek, portable.bytes);
      final recovered =
          await KeyHierarchy.unwrapMskWithAek(crypto, aek, envelope);
      expect(recovered, equals(portable.bytes));
    });

    test(
        'VEK alone can never unwrap the MSK envelope — B4 double-encryption '
        'structure', () async {
      final crypto = DartCryptoProvider();
      final aek = KeyHierarchy.generateAek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final msk = await crypto.generateSigningKey('ed25519');
      final portable = await crypto.exportPrivateKey(msk);
      final envelope =
          await KeyHierarchy.wrapMskWithAek(crypto, aek, portable.bytes);

      // A limited-tier device holds VEK but never AEK. Attempting to use VEK
      // where AEK is required must fail — there is no code path that lets a
      // VEK-only device recover the MSK private key.
      expect(
        () => KeyHierarchy.unwrapMskWithAek(crypto, vek, envelope),
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

  group('VEK wraps the vault plaintext', () {
    test('round-trips arbitrary vault plaintext bytes', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final plaintext =
          Uint8List.fromList('{"generation":1,"openpgp_keys":[]}'.codeUnits);
      final ciphertext = await KeyHierarchy.encryptVaultPlaintextWithVek(
        crypto,
        vek,
        plaintext,
      );
      final recovered = await KeyHierarchy.decryptVaultCiphertextWithVek(
        crypto,
        vek,
        ciphertext,
      );
      expect(recovered, equals(plaintext));
    });

    test('wrong VEK fails to decrypt the vault ciphertext', () async {
      final crypto = DartCryptoProvider();
      final vek = KeyHierarchy.generateVek(crypto);
      final wrongVek = KeyHierarchy.generateVek(crypto);
      final plaintext = Uint8List.fromList('secret'.codeUnits);
      final ciphertext = await KeyHierarchy.encryptVaultPlaintextWithVek(
        crypto,
        vek,
        plaintext,
      );
      expect(
        () => KeyHierarchy.decryptVaultCiphertextWithVek(
          crypto,
          wrongVek,
          ciphertext,
        ),
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

  group('WrappedKey JSON round-trip', () {
    test('serializes and deserializes without losing bytes', () async {
      final crypto = DartCryptoProvider();
      final dkek = KeyHierarchy.generateDkek(crypto);
      final vek = KeyHierarchy.generateVek(crypto);
      final envelope = await KeyHierarchy.wrapWithDkek(crypto, dkek, vek);
      final roundTripped = WrappedKey.fromJson(envelope.toJson());
      expect(roundTripped.iv, equals(envelope.iv));
      expect(roundTripped.ciphertext, equals(envelope.ciphertext));
    });
  });
}
