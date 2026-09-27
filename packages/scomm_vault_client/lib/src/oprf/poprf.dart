import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ristretto255/ristretto255.dart';

import '../errors.dart';
import 'rfc9497.dart';

/// `info = "CKVF-pepper-v1" || 0x00 || vault_id || 0x00 || slot_id` (ASCII),
/// ckvf `profiles/pepper-oprf.md` §2.
Uint8List pepperInfo(String vaultId, String slotId) => Uint8List.fromList([
      ...ascii.encode('CKVF-pepper-v1'),
      0,
      ...ascii.encode(vaultId),
      0,
      ...ascii.encode(slotId),
    ]);

class PoprfBlindState {
  const PoprfBlindState({
    required this.input,
    required this.info,
    required this.blind,
    required this.blinded,
    required this.tweakedKey,
  });

  final Uint8List input;
  final Uint8List info;

  /// Stays on the device.
  final Uint8List blind;

  /// Sent to the host as `blind`.
  final Uint8List blinded;
  final Uint8List tweakedKey;
}

Scalar _infoScalar(List<int> info) =>
    hashToScalar([...ascii.encode('Info'), ...lp(info)], modePoprf);

/// RFC 9497 §3.3.3 Blind. [blind] fixes the scalar (vectors only).
PoprfBlindState poprfBlind(
  List<int> input,
  List<int> info,
  List<int> publicKey, {
  List<int>? blind,
  Random? random,
}) {
  final tweaked = add(mulGen(_infoScalar(info)), decodeElement(publicKey));
  if (tweaked.equal(Element.newIdentityElement()) == 1) {
    throw VaultClientException('oprf_failed', 'tweaked key is the identity');
  }
  final r = blind != null ? decodeScalar(blind) : randomScalar(random);
  final point = hashToGroup(input, modePoprf);
  if (point.equal(Element.newIdentityElement()) == 1) {
    throw VaultClientException('oprf_failed', 'input maps to the identity');
  }
  return PoprfBlindState(
    input: Uint8List.fromList(input),
    info: Uint8List.fromList(info),
    blind: encScalar(r),
    blinded: enc(mul(r, point)),
    tweakedKey: enc(tweaked),
  );
}

/// RFC 9497 §3.3.3 Finalize. Throws `invalid_evaluation` when the proof does
/// not verify against the tweaked key.
Uint8List poprfFinalize(
  PoprfBlindState state,
  List<int> evaluated,
  List<int> proof,
) {
  final ev = decodeElement(evaluated);
  final ok = verifyProof(
    modePoprf,
    decodeElement(state.tweakedKey),
    ev,
    decodeElement(state.blinded),
    proof,
  );
  if (!ok) {
    throw VaultClientException(
      'invalid_evaluation',
      'the vault host returned a pepper evaluation that does not verify',
    );
  }
  final inverse = Scalar()..invert(decodeScalar(state.blind));
  return finalizeHash(state.input, mul(inverse, ev), state.info);
}

/// Host BlindEvaluate. The app never holds the pepper key; tests and local
/// harnesses only.
({Uint8List evaluated, Uint8List proof}) poprfBlindEvaluate(
  List<int> secretKey,
  List<int> info,
  List<int> blinded, {
  Random? random,
}) {
  final t = Scalar()..add(decodeScalar(secretKey), _infoScalar(info));
  if (t.equal(Scalar()) == 1) {
    throw VaultClientException('oprf_failed', 'inverse error');
  }
  final d = decodeElement(blinded);
  final c = mul(Scalar()..invert(t), d);
  final proof = generateProof(modePoprf, t, mulGen(t), c, d, random: random);
  return (evaluated: enc(c), proof: proof);
}

/// Public key for a 32-byte secret scalar.
Uint8List oprfPublicKey(List<int> secretKey) =>
    enc(mulGen(decodeScalar(secretKey)));
