import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('protocolFamiliesFromPrimitives', () {
    test('does not advertise OpenPGP PQC without pgp_pqc engine', () {
      final mapped = protocolFamiliesFromPrimitives(
        sign: const ['ed25519', 'mldsa65'],
        keyAgreement: const ['x25519'],
        kem: const ['ml-kem-768'],
        engines: const {'pgp': true, 'smime': true},
      );
      final pgp = (mapped['families'] as Map)['pgp'] as List;
      expect(pgp, contains('openpgp-cv25519'));
      expect(pgp, contains('openpgp-ed25519'));
      expect(pgp, isNot(contains('openpgp-mlkem768-x25519')));
      expect(pgp, isNot(contains('openpgp-mldsa65-ed25519')));
      final smime = (mapped['families'] as Map)['smime'] as List;
      expect(smime, contains('smime-rsa-oaep-sha256'));
      expect(smime, contains('smime-x25519'));
      expect(smime, isNot(contains('smime-mlkem768-x25519')));
    });

    test('advertises RFC 9980 pgp names when pgp_pqc is ready', () {
      final mapped = protocolFamiliesFromPrimitives(
        sign: const ['ed25519', 'mldsa65'],
        keyAgreement: const ['x25519'],
        kem: const ['ml-kem-768'],
        engines: const {'pgp': true, 'pgp_pqc': true},
      );
      final pgp = (mapped['families'] as Map)['pgp'] as List;
      expect(pgp, contains('openpgp-cv25519'));
      expect(pgp, contains('openpgp-mldsa65-ed25519'));
      expect(pgp, contains('openpgp-mlkem768-x25519'));
    });
  });

  group('OpenPgpRfc9980', () {
    test('detects RFC 9980 ML-KEM in a v4 public-key packet', () {
      // Old-format tag 6, 1-octet length, v4 key with algorithm 35.
      final packet = Uint8List.fromList([
        0x98, 6,
        4, 0, 0, 0, 1,
        OpenPgpAlgorithms.rfc9980MlKem768X25519Id,
      ]);
      expect(OpenPgpRfc9980.looksLikeRfc9980(packet), isTrue);
      expect(OpenPgpRfc9980.looksLikeLibrePgpKyber(packet), isFalse);
    });

    test('detects LibrePGP Kyber algorithm 105', () {
      final packet = Uint8List.fromList([
        0x98, 6,
        4, 0, 0, 0, 1,
        OpenPgpAlgorithms.librePgpKyber768X25519Id,
      ]);
      expect(OpenPgpRfc9980.looksLikeLibrePgpKyber(packet), isTrue);
      expect(OpenPgpRfc9980.looksLikeRfc9980(packet), isFalse);
    });
  });

  test('registry lists OpenPGP PQC under family pgp', () {
    expect(getAlgorithm(OpenPgpAlgorithms.mldsa65Ed25519)?.family, Families.pgp);
    expect(getAlgorithm(OpenPgpAlgorithms.mlkem768X25519)?.family, Families.pgp);
    expect(getAlgorithm('smime-mlkem-768')?.family, Families.smime);
    expect(getAlgorithm('pqc-mlkem-768')?.family, Families.smime);
    expect(
      getAlgorithm(OpenPgpAlgorithms.mlkem768X25519)?.algorithmClass,
      AlgorithmClasses.pqc,
    );
    expect(getAlgorithm('openpgp-rsa4096')?.algorithmClass, AlgorithmClasses.rsa);
    expect(getAlgorithm('openpgp-ed25519')?.algorithmClass, AlgorithmClasses.ecc);
    expect(
      listAlgorithms(Families.pgp).map((e) => e.algorithm),
      containsAll([
        OpenPgpAlgorithms.mldsa65Ed25519,
        OpenPgpAlgorithms.mlkem768X25519,
      ]),
    );
  });
}
