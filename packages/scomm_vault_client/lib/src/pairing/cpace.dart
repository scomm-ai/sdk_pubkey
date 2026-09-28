import 'dart:convert';
import 'dart:typed_data';

import 'package:ristretto255/ristretto255.dart';

import '../digest.dart';

import '../errors.dart';

/// CPace-Ristretto255-SHA512 as in draft-irtf-cfrg-cpace-21 §8.3.
///
/// CFRG requires a hash with ≥64-byte output for ristretto255, so this
/// suite uses SHA-512 even though TEK is later HKDF-SHA-256.
const String cpaceCiphersuite = 'CPaceRistretto255-SHA512';

final Uint8List _dsi = Uint8List.fromList(utf8.encode('CPaceRistretto255'));
final Uint8List _dsiIsk =
    Uint8List.fromList(utf8.encode('CPaceRistretto255_ISK'));

const int _sha512BlockBytes = 128;
const int _fieldBytes = 32;

class CPaceInitiator {
  CPaceInitiator._({
    required this.scalar,
    required this.ya,
    required this.sid,
    required this.ci,
  });

  final Uint8List scalar;

  /// Public element sent to the responder.
  final Uint8List ya;
  final Uint8List sid;
  final Uint8List ci;
}

Never _fail(String message) =>
    throw VaultClientException('pairing_protocol_error', message);

Uint8List cpaceLvCat(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final part in parts) {
    if (part.length > 255) _fail('CPace lv_cat field longer than 255 bytes');
    out.addByte(part.length);
    out.add(part);
  }
  return out.toBytes();
}

Element _generator(List<int> prs, List<int> ci, List<int> sid) {
  final zpad = (_sha512BlockBytes - 1 - (1 + prs.length) - (1 + _dsi.length))
      .clamp(0, 1 << 30);
  final genStr = cpaceLvCat([_dsi, prs, Uint8List(zpad), ci, sid]);
  final g = Element.newElement();
  g.setUniformBytes(VaultDigest.sha512(genStr));
  return g;
}

Scalar _scalar(List<int> random64) {
  if (random64.length != 64) {
    throw ArgumentError('CPace scalar seed must be 64 bytes');
  }
  final s = Scalar()..setUniformBytes(Uint8List.fromList(random64));
  if (s.equal(Scalar()) == 1) _fail('CPace sampled a zero scalar');
  return s;
}

Element _decode(List<int> bytes) {
  if (bytes.length != _fieldBytes) _fail('CPace element must be 32 bytes');
  final e = Element.newElement();
  try {
    e.setCanonicalBytes(Uint8List.fromList(bytes));
  } catch (_) {
    _fail('CPace element is not a valid ristretto255 encoding');
  }
  return e;
}

Uint8List _isk(List<int> sid, List<int> k, List<int> ya, List<int> yb) {
  final prefix = cpaceLvCat([_dsiIsk, sid, k]);
  return Uint8List.fromList(VaultDigest.sha512([
    ...prefix,
    ...cpaceLvCat([ya, const <int>[]]),
    ...cpaceLvCat([yb, const <int>[]]),
  ]));
}

Element _shared(Scalar s, Element peer) {
  final k = Element.newElement()..scalarMult(s, peer);
  if (k.equal(Element.newIdentityElement()) == 1) {
    _fail('CPace shared element is identity');
  }
  return k;
}

CPaceInitiator cpaceStart({
  required List<int> password,
  required List<int> sid,
  required List<int> ci,
  required List<int> random64,
}) {
  final s = _scalar(random64);
  final ya = Element.newElement()..scalarMult(s, _generator(password, ci, sid));
  return CPaceInitiator._(
    scalar: Uint8List.fromList(s.encode()),
    ya: Uint8List.fromList(ya.encode()),
    sid: Uint8List.fromList(sid),
    ci: Uint8List.fromList(ci),
  );
}

({Uint8List yb, Uint8List isk}) cpaceRespond({
  required List<int> password,
  required List<int> sid,
  required List<int> ci,
  required List<int> peerYa,
  required List<int> random64,
}) {
  final s = _scalar(random64);
  final yb = Uint8List.fromList(
    (Element.newElement()..scalarMult(s, _generator(password, ci, sid)))
        .encode(),
  );
  final k = _shared(s, _decode(peerYa));
  return (yb: yb, isk: _isk(sid, k.encode(), peerYa, yb));
}

Uint8List cpaceFinish(CPaceInitiator state, List<int> peerYb) {
  final s = Scalar()..setCanonicalBytes(state.scalar);
  final k = _shared(s, _decode(peerYb));
  return _isk(state.sid, k.encode(), state.ya, peerYb);
}
