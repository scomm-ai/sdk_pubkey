import 'dart:math';
import 'dart:typed_data';

import 'package:ristretto255/ristretto255.dart';

import '../errors.dart';
import 'rfc9497.dart';

/// Identity OPRF against the vault host (ckvf `profiles/vault-host.md` §2.1).
///
/// Blind and Finalize are RFC 9497 mode `0x00`, so `identity_id` matches
/// every earlier client. The host adds a DLEQ proof under the VOPRF (`0x01`)
/// context; [identityFinalize] verifies it against the host public key.
class IdentityBlindState {
  const IdentityBlindState({
    required this.input,
    required this.blind,
    required this.blinded,
  });

  final Uint8List input;
  final Uint8List blind;
  final Uint8List blinded;
}

IdentityBlindState identityBlind(
  List<int> input, {
  List<int>? blind,
  Random? random,
}) {
  final r = blind != null ? decodeScalar(blind) : randomScalar(random);
  final point = hashToGroup(input, modeOprf);
  if (point.equal(Element.newIdentityElement()) == 1) {
    throw VaultClientException('oprf_failed', 'input maps to the identity');
  }
  return IdentityBlindState(
    input: Uint8List.fromList(input),
    blind: encScalar(r),
    blinded: enc(mul(r, point)),
  );
}

/// Verifies [proof] against [publicKey] and returns the 64-byte output.
Uint8List identityFinalize(
  IdentityBlindState state,
  List<int> evaluated,
  List<int> proof,
  List<int> publicKey,
) {
  final ev = decodeElement(evaluated);
  final ok = verifyProof(
    modeVoprf,
    decodeElement(publicKey),
    decodeElement(state.blinded),
    ev,
    proof,
  );
  if (!ok) {
    throw VaultClientException(
      'invalid_evaluation',
      'the vault host returned an identity evaluation that does not verify',
    );
  }
  final inverse = Scalar()..invert(decodeScalar(state.blind));
  return finalizeHash(state.input, mul(inverse, ev));
}

/// Host evaluation plus VOPRF proof, as the vault host returns it. The app
/// never holds the identity key; tests and local harnesses only.
({Uint8List evaluated, Uint8List proof}) identityBlindEvaluateForTests(
  List<int> secretKey,
  List<int> blinded, {
  Random? random,
}) {
  final k = decodeScalar(secretKey);
  final c = decodeElement(blinded);
  final d = mul(k, c);
  final proof = generateProof(modeVoprf, k, mulGen(k), c, d, random: random);
  return (evaluated: enc(d), proof: proof);
}

/// First 32 bytes of Finalize, lowercase hex.
String identityIdFromOutput(List<int> output) => output
    .sublist(0, 32)
    .map((b) => b.toRadixString(16).padLeft(2, '0'))
    .join();
