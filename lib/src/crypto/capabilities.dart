import '../constants.dart';
import '../errors.dart';
import 'provider.dart';

const _wireFamilies = [Families.pgp, Families.smime];

/// Translate primitive provider algorithms into Pubkey discovery families.
///
  /// Wire families are pgp and smime only. ML-KEM is advertised as
  /// `smime-mlkem-*` (class pqc) when an S/MIME engine can run it, and as
  /// `openpgp-mlkem768-x25519` only when `pgp_pqc` is set (Sequoia RFC 9980).
Map<String, dynamic> protocolFamiliesFromPrimitives({
  List<String> sign = const [],
  List<String> keyAgreement = const [],
  List<String> kem = const [],
  Map<String, bool> engines = const {},
}) {
  final families = <String, List<String>>{};
  final agree = keyAgreement.map((item) => item.toLowerCase()).toSet();
  final kems = kem.map((item) => item.toLowerCase()).toSet();
  final signs = sign.map((item) => item.toLowerCase()).toSet();

  if (engines[EngineFlags.pgp] == true) {
    final pgp = <String>[];
    if (signs.contains('ed25519') ||
        signs.contains(OpenPgpAlgorithms.ed25519)) {
      pgp.add(OpenPgpAlgorithms.ed25519);
    }
    if (agree.contains('x25519')) {
      pgp.add(OpenPgpAlgorithms.cv25519);
    }
    // RFC 9980 names only when a Sequoia engine reports it can decrypt them.
    if (engines[EngineFlags.pgpPqc] == true) {
      if (signs.contains('mldsa65') ||
          signs.contains(OpenPgpAlgorithms.mldsa65Ed25519)) {
        pgp.add(OpenPgpAlgorithms.mldsa65Ed25519);
      }
      if (kems.contains('ml-kem-768') ||
          kems.contains(OpenPgpAlgorithms.mlkem768X25519)) {
        pgp.add(OpenPgpAlgorithms.mlkem768X25519);
      }
    }
    if (pgp.isNotEmpty) families[Families.pgp] = pgp;
  }

  if (engines[EngineFlags.smime] == true) {
    final smime = <String>[
      SmimeAlgorithms.rsaOaepSha256,
      SmimeAlgorithms.rsaPssSha256,
    ];
    if (agree.contains('x25519')) smime.add(SmimeAlgorithms.x25519);
    if (agree.contains('p-256') || agree.contains('ecdh-p256')) {
      smime.add('smime-ecdh-p256');
    }
    final pqcReady = engines['smime_pqc'] == true;
    if (pqcReady &&
        (kems.contains('ml-kem-768') ||
            kems.contains(SmimeAlgorithms.mlkem768X25519) ||
            kems.contains('smime-mlkem-768'))) {
      smime.add(SmimeAlgorithms.mlkem768X25519);
    }
    if (pqcReady &&
        (signs.contains('mldsa65') ||
            signs.contains(SmimeAlgorithms.mldsa65))) {
      smime.add(SmimeAlgorithms.mldsa65);
    }
    if (smime.isNotEmpty) families[Families.smime] = smime;
  }

  return {'families': families};
}

Map<String, dynamic> applyCapabilityPolicy(
  Map<String, dynamic> capabilities, [
  Map<String, String> policy = const {},
]) {
  final families = <String, List<String>>{};
  final raw = capabilities['families'];
  if (raw is Map) {
    for (final entry in raw.entries) {
      if (entry.key.toString() == Families.pq) continue;
      final value = entry.value;
      if (value is List) {
        families[entry.key.toString()] = [
          for (final item in value) item.toString(),
        ];
      }
    }
  }

  for (final family in _wireFamilies) {
    final level = policy[family];
    final present = families[family]?.isNotEmpty ?? false;
    if (level == RequirementLevels.required && !present) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'Capability policy requires $family, but no compatible algorithms are available',
      );
    }
    if (level == RequirementLevels.unavailable && present) {
      families.remove(family);
    }
  }

  return {'families': families};
}

Future<Map<String, dynamic>> protocolCapabilitiesFromProvider(
  CryptoProvider provider, [
  Map<String, String> policy = const {},
  Map<String, bool> engines = const {},
]) async {
  final caps = await provider.capabilities();
  return applyCapabilityPolicy(
    protocolFamiliesFromPrimitives(
      sign: caps.sign,
      keyAgreement: caps.keyAgreement,
      kem: caps.kem,
      engines: {...caps.engines, ...engines},
    ),
    policy,
  );
}
