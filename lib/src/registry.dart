import 'constants.dart';
import 'errors.dart';

const int keyFnEncrypt = 1;
const int keyFnVerify = 2;
const int keyFnAuthenticate = 4;
const int keyFnKeyAgreement = 8;
const int keyFnCertify = 16;

/// Primitive class inside a wire family. Hybrids are [AlgorithmClasses.pqc].
String? algorithmClassOf(Object? algorithm) {
  final n = '$algorithm'.toLowerCase();
  if (n.isEmpty || n == 'null') return null;
  if (n.contains('mlkem') ||
      n.contains('mldsa') ||
      n.contains('slhdsa') ||
      n.contains('hqc') ||
      n.startsWith('pqc-')) {
    return AlgorithmClasses.pqc;
  }
  if (n.contains('rsa')) return AlgorithmClasses.rsa;
  if (n.contains('ecdsa') ||
      n.contains('ecdh') ||
      n.contains('ed25519') ||
      n.contains('ed448') ||
      n.contains('x25519') ||
      n.contains('x448') ||
      n.contains('cv25519') ||
      n.contains('cv448') ||
      n == 'ed25519') {
    return AlgorithmClasses.ecc;
  }
  if (n.contains('dsa') || n.contains('elgamal') || n == 'smime-dh' || n.endsWith('-dh')) {
    return AlgorithmClasses.ffc;
  }
  return null;
}

class AlgorithmMeta {
  const AlgorithmMeta({
    required this.algorithmId,
    required this.algorithm,
    this.family,
    required this.keyFunctions,
    required this.purpose,
  });

  final int algorithmId;
  final String algorithm;
  final String? family;
  final int keyFunctions;
  final String purpose;

  /// `rsa` | `ecc` | `pqc` | `ffc`. Hybrids are [AlgorithmClasses.pqc].
  String? get algorithmClass => algorithmClassOf(algorithm);
}

const AlgorithmMeta _ed25519 = AlgorithmMeta(
  algorithmId: 1,
  algorithm: 'ed25519',
  keyFunctions: keyFnVerify,
  purpose: Purposes.masterSigning,
);

/// Canonical algorithm registry. Wire families are pgp and smime.
const List<AlgorithmMeta> algorithmRegistry = [
  _ed25519,
  AlgorithmMeta(
    algorithmId: 104,
    algorithm: 'openpgp-rsa2048',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 105,
    algorithm: 'openpgp-rsa3072',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 106,
    algorithm: 'openpgp-rsa4096',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 107,
    algorithm: 'openpgp-dsa2048',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 108,
    algorithm: 'openpgp-ecdsa-p256',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 109,
    algorithm: 'openpgp-ecdsa-p384',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 110,
    algorithm: 'openpgp-ecdsa-p521',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 111,
    algorithm: 'openpgp-ed25519',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 112,
    algorithm: 'openpgp-ed448',
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 113,
    algorithm: 'openpgp-cv25519',
    family: Families.pgp,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 114,
    algorithm: 'openpgp-cv448',
    family: Families.pgp,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 115,
    algorithm: 'openpgp-elgamal',
    family: Families.pgp,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 116,
    algorithm: OpenPgpAlgorithms.mldsa65Ed25519,
    family: Families.pgp,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 117,
    algorithm: OpenPgpAlgorithms.mlkem768X25519,
    family: Families.pgp,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 203,
    algorithm: 'smime-rsa-pss-sha256',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 204,
    algorithm: 'smime-rsa-sha256',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 205,
    algorithm: 'smime-rsa-sha384',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 206,
    algorithm: 'smime-rsa-sha512',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 207,
    algorithm: 'smime-ecdsa-sha256',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 208,
    algorithm: 'smime-ecdsa-sha384',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 209,
    algorithm: 'smime-ecdsa-sha512',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 210,
    algorithm: 'smime-ed25519',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 211,
    algorithm: 'smime-ed448',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 212,
    algorithm: 'smime-rsa-pkcs1',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 213,
    algorithm: 'smime-rsa-oaep-sha1',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 214,
    algorithm: 'smime-rsa-oaep-sha256',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 215,
    algorithm: 'smime-rsa-oaep-sha384',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 216,
    algorithm: 'smime-rsa-oaep-sha512',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.encryption,
  ),
  AlgorithmMeta(
    algorithmId: 217,
    algorithm: 'smime-ecdh-p256',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 218,
    algorithm: 'smime-ecdh-p384',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 219,
    algorithm: 'smime-ecdh-p521',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 220,
    algorithm: 'smime-x25519',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 221,
    algorithm: 'smime-x448',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 222,
    algorithm: 'smime-dh',
    family: Families.smime,
    keyFunctions: keyFnKeyAgreement,
    purpose: Purposes.keyAgreement,
  ),
  AlgorithmMeta(
    algorithmId: 223,
    algorithm: 'smime-ed25519-kem',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 224,
    algorithm: 'smime-ed448-kem',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 225,
    algorithm: 'smime-mlkem-512',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 226,
    algorithm: 'smime-mlkem-768',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 227,
    algorithm: 'smime-mlkem-1024',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 228,
    algorithm: 'smime-mlkem768-x25519',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 229,
    algorithm: 'smime-mlkem768-p256',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 230,
    algorithm: 'smime-mlkem1024-p384',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 303,
    algorithm: 'pqc-mldsa44',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 304,
    algorithm: 'pqc-mldsa65',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 305,
    algorithm: 'pqc-mldsa87',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 306,
    algorithm: 'pqc-slhdsa-sha256',
    family: Families.smime,
    keyFunctions: keyFnVerify,
    purpose: Purposes.signing,
  ),
  AlgorithmMeta(
    algorithmId: 307,
    algorithm: 'pqc-mlkem-512',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 308,
    algorithm: 'pqc-mlkem-768',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 309,
    algorithm: 'pqc-mlkem-1024',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 310,
    algorithm: 'pqc-mlkem768-x25519',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 311,
    algorithm: 'pqc-mlkem768-p256',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 312,
    algorithm: 'pqc-mlkem1024-p384',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 313,
    algorithm: 'pqc-mlkem768-p521',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 314,
    algorithm: 'pqc-mlkem1024-p521',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 315,
    algorithm: 'pqc-hqc-128',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 316,
    algorithm: 'pqc-hqc-192',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
  AlgorithmMeta(
    algorithmId: 317,
    algorithm: 'pqc-hqc-256',
    family: Families.smime,
    keyFunctions: keyFnEncrypt,
    purpose: Purposes.kem,
  ),
];

final Map<String, AlgorithmMeta> _byName = {
  for (final row in algorithmRegistry) row.algorithm: row,
};

final Map<int, AlgorithmMeta> _byId = {
  for (final row in algorithmRegistry) row.algorithmId: row,
};

AlgorithmMeta? getAlgorithm(String name) => _byName[name];

AlgorithmMeta requireAlgorithm(String name) {
  final meta = getAlgorithm(name);
  if (meta == null) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'Unknown algorithm: $name',
    );
  }
  return meta;
}

AlgorithmMeta? getAlgorithmById(int id) => _byId[id];

List<AlgorithmMeta> listAlgorithms([String? family]) {
  if (family == null) {
    return List<AlgorithmMeta>.from(algorithmRegistry);
  }
  return algorithmRegistry.where((row) => row.family == family).toList();
}

const _wireFamilies = {Families.pgp, Families.smime};

bool _isPqAlgorithm(Object? algorithm) =>
    algorithmClassOf(algorithm) == AlgorithmClasses.pqc;

int algorithmPreferenceRank(Object? algorithm) => _isPqAlgorithm(algorithm) ? 1 : 0;

int familyPreferenceRank(String? family) {
  if (family == Families.smime) return 1;
  if (family == Families.pgp) return 0;
  return -1;
}

/// Select the best mutually supported artifact.
/// Families on the wire are pgp and smime only. PQC is [AlgorithmClasses.pqc].
Map<String, dynamic>? selectBestArtifact(
  List<dynamic> artifacts,
  Map<String, dynamic>? capabilities, [
  Map<String, dynamic>? preferences,
  String? purpose,
]) {
  final supported = <String>{};
  final families = capabilities?['families'];
  if (families is Map) {
    for (final entry in families.entries) {
      if (!_wireFamilies.contains(entry.key.toString())) continue;
      final algos = entry.value;
      if (algos is List) {
        for (final algo in algos) {
          supported.add('${entry.key}:$algo');
        }
      }
    }
  }

  final candidates = <Map<String, dynamic>>[];
  for (final raw in artifacts) {
    if (raw is! Map) continue;
    final artifact = Map<String, dynamic>.from(raw);
    final status = artifact['status'];
    if (status != null && status != 'active') {
      continue;
    }
    final family = artifact['family']?.toString();
    if (!_wireFamilies.contains(family)) continue;
    if (purpose != null &&
        artifact['purpose'] != null &&
        artifact['purpose'] != purpose) {
      continue;
    }
    if (supported.contains('${artifact['family']}:${artifact['algorithm']}')) {
      candidates.add(artifact);
    }
  }

  if (candidates.isEmpty) {
    return null;
  }

  final preferredFamily = preferences?['preferred_family'];
  final preferredAlgorithm = preferences?['preferred_algorithm'];
  if (_wireFamilies.contains(preferredFamily)) {
    for (final artifact in candidates) {
      if (artifact['family'] == preferredFamily &&
          (preferredAlgorithm == null ||
              artifact['algorithm'] == preferredAlgorithm)) {
        return artifact;
      }
    }
  }

  candidates.sort((a, b) {
    final pq =
        algorithmPreferenceRank(b['algorithm']) -
        algorithmPreferenceRank(a['algorithm']);
    if (pq != 0) return pq;
    final rank =
        familyPreferenceRank(b['family']?.toString()) -
        familyPreferenceRank(a['family']?.toString());
    if (rank != 0) return rank;
    return (_asInt(b['key_id']) ?? 0) - (_asInt(a['key_id']) ?? 0);
  });
  return candidates.first;
}

int? _asInt(Object? value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  return int.tryParse('$value');
}
