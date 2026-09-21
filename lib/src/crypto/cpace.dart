import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ristretto255/ristretto255.dart';

import '../errors.dart';

/// CPace-Ristretto255-SHA512 as in draft-irtf-cfrg-cpace-21 §8.3.
///
/// CFRG requires a hash with ≥64-byte output for ristretto255, so this
/// suite uses SHA-512 even though TEK is later HKDF-SHA-256.
const String cpaceCiphersuite = 'CPaceRistretto255-SHA512';
const String cpaceDraft = 'draft-irtf-cfrg-cpace-21';

final Uint8List _cpaceDsi = Uint8List.fromList(utf8.encode('CPaceRistretto255'));
final Uint8List _cpaceDsiIsk =
    Uint8List.fromList(utf8.encode('CPaceRistretto255_ISK'));

const int _sha512BlockBytes = 128;
const int _fieldBytes = 32;

class CPaceInitiatorState {
  CPaceInitiatorState({
    required this.scalar,
    required this.ya,
    required this.sid,
    required this.ci,
  });

  final Uint8List scalar;
  final Uint8List ya;
  final Uint8List sid;
  final Uint8List ci;
}

Uint8List cpaceLvCat(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final part in parts) {
    if (part.length > 255) {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'CPace lv_cat field longer than 255 bytes',
      );
    }
    out.addByte(part.length);
    out.add(part);
  }
  return out.toBytes();
}

Uint8List _generatorString(List<int> prs, List<int> ci, List<int> sid) {
  final dsiEncLen = 1 + _cpaceDsi.length;
  final prsEncLen = 1 + prs.length;
  final zpad = (_sha512BlockBytes - 1 - prsEncLen - dsiEncLen).clamp(0, 1 << 30);
  return cpaceLvCat([
    _cpaceDsi,
    prs,
    Uint8List(zpad),
    ci,
    sid,
  ]);
}

Element _calculateGenerator(List<int> prs, List<int> ci, List<int> sid) {
  final genStr = _generatorString(prs, ci, sid);
  final hashed = Uint8List.fromList(crypto.sha512.convert(genStr).bytes);
  final g = Element.newElement();
  g.setUniformBytes(hashed);
  return g;
}

Scalar _sampleScalar(Uint8List random64) {
  if (random64.length != 64) {
    throw ArgumentError('CPace scalar seed must be 64 bytes');
  }
  final s = Scalar();
  s.setUniformBytes(random64);
  if (s.equal(Scalar()) == 1) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'CPace sampled a zero scalar',
    );
  }
  return s;
}

Uint8List _encodeElement(Element e) => Uint8List.fromList(e.encode());

Element _decodeElement(List<int> bytes) {
  if (bytes.length != _fieldBytes) {
    throw PubkeyException(
      ErrorCodes.invalidPublicKey,
      'CPace element must be 32 bytes',
    );
  }
  final e = Element.newElement();
  try {
    e.setCanonicalBytes(Uint8List.fromList(bytes));
  } catch (_) {
    throw PubkeyException(
      ErrorCodes.invalidPublicKey,
      'CPace element is not a valid ristretto255 encoding',
    );
  }
  return e;
}

Uint8List _isk({
  required List<int> sid,
  required List<int> k,
  required List<int> ya,
  required List<int> yb,
}) {
  final prefix = cpaceLvCat([_cpaceDsiIsk, sid, k]);
  final transcript = Uint8List.fromList([
    ...cpaceLvCat([ya, const <int>[]]),
    ...cpaceLvCat([yb, const <int>[]]),
  ]);
  return Uint8List.fromList(
    crypto.sha512.convert([...prefix, ...transcript]).bytes,
  );
}

void _rejectIdentity(Element k) {
  if (k.equal(Element.newIdentityElement()) == 1) {
    throw PubkeyException(
      ErrorCodes.invalidPublicKey,
      'CPace shared element is identity',
    );
  }
}

CPaceInitiatorState cpaceStartImpl({
  required List<int> password,
  required List<int> sid,
  required List<int> ci,
  required Uint8List random64,
}) {
  final g = _calculateGenerator(password, ci, sid);
  final yaScalar = _sampleScalar(random64);
  final ya = Element.newElement()..scalarMult(yaScalar, g);
  return CPaceInitiatorState(
    scalar: Uint8List.fromList(yaScalar.encode()),
    ya: _encodeElement(ya),
    sid: Uint8List.fromList(sid),
    ci: Uint8List.fromList(ci),
  );
}

({Uint8List yb, Uint8List isk}) cpaceRespondImpl({
  required List<int> password,
  required List<int> sid,
  required List<int> ci,
  required List<int> peerYa,
  required Uint8List random64,
}) {
  final g = _calculateGenerator(password, ci, sid);
  final ybScalar = _sampleScalar(random64);
  final yb = Element.newElement()..scalarMult(ybScalar, g);
  final ybBytes = _encodeElement(yb);
  final ya = _decodeElement(peerYa);
  final k = Element.newElement()..scalarMult(ybScalar, ya);
  _rejectIdentity(k);
  final isk = _isk(sid: sid, k: _encodeElement(k), ya: peerYa, yb: ybBytes);
  return (yb: ybBytes, isk: isk);
}

Uint8List cpaceFinishImpl({
  required CPaceInitiatorState state,
  required List<int> peerYb,
}) {
  final yb = _decodeElement(peerYb);
  final scalar = Scalar()..setCanonicalBytes(state.scalar);
  final k = Element.newElement()..scalarMult(scalar, yb);
  _rejectIdentity(k);
  return _isk(sid: state.sid, k: _encodeElement(k), ya: state.ya, yb: peerYb);
}
