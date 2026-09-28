import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ristretto255/ristretto255.dart';

import '../digest.dart';

import '../errors.dart';

/// RFC 9497 building blocks for `ristretto255-SHA512`.
const String oprfSuite = 'ristretto255-SHA512';
const int modeOprf = 0x00;
const int modeVoprf = 0x01;
const int modePoprf = 0x02;

Uint8List contextString(int mode) => Uint8List.fromList([
      ...utf8.encode('OPRFV1-'),
      mode,
      ...utf8.encode('-$oprfSuite'),
    ]);

Element hashToGroup(List<int> input, int mode) {
  final dst = [...utf8.encode('HashToGroup-'), ...contextString(mode)];
  return Element.newElement()
    ..setUniformBytes(expandMessageXmdSha512(input, dst, 64));
}

Scalar hashToScalar(List<int> input, int mode) {
  final dst = [...utf8.encode('HashToScalar-'), ...contextString(mode)];
  return Scalar()..setUniformBytes(expandMessageXmdSha512(input, dst, 64));
}

Scalar randomScalar([Random? random]) {
  final rng = random ?? Random.secure();
  final seed = Uint8List.fromList(List.generate(64, (_) => rng.nextInt(256)));
  final s = Scalar()..setUniformBytes(seed);
  if (s.equal(Scalar()) == 1) {
    throw VaultClientException('oprf_failed', 'sampled a zero scalar');
  }
  return s;
}

Scalar decodeScalar(List<int> bytes) {
  if (bytes.length != 32) {
    throw VaultClientException('invalid_evaluation', 'scalar must be 32 bytes');
  }
  try {
    return Scalar()..setCanonicalBytes(Uint8List.fromList(bytes));
  } catch (_) {
    throw VaultClientException('invalid_evaluation', 'non-canonical scalar');
  }
}

/// Canonical, non-identity ristretto255 element.
Element decodeElement(List<int> bytes) {
  if (bytes.length != 32) {
    throw VaultClientException(
        'invalid_evaluation', 'element must be 32 bytes');
  }
  final e = Element.newElement();
  try {
    e.setCanonicalBytes(Uint8List.fromList(bytes));
  } catch (_) {
    throw VaultClientException('invalid_evaluation', 'non-canonical element');
  }
  if (e.equal(Element.newIdentityElement()) == 1) {
    throw VaultClientException('invalid_evaluation', 'identity element');
  }
  return e;
}

Uint8List enc(Element e) => Uint8List.fromList(e.encode());
Uint8List encScalar(Scalar s) => Uint8List.fromList(s.encode());

Element mul(Scalar s, Element e) => Element.newElement()..scalarMult(s, e);
Element mulGen(Scalar s) => Element.newElement()..scalarBaseMult(s);
Element add(Element a, Element b) => Element.newElement()..add(a, b);

/// `I2OSP(len(x), 2) || x`.
List<int> lp(List<int> x) => [..._i2osp(x.length, 2), ...x];

(Element, Element) _composites(
  int mode,
  Element b,
  Element c,
  Element d, {
  Scalar? k,
}) {
  final seedDst = [...utf8.encode('Seed-'), ...contextString(mode)];
  final seed = VaultDigest.sha512([...lp(enc(b)), ...lp(seedDst)]);
  final di = hashToScalar([
    ...lp(seed),
    ..._i2osp(0, 2),
    ...lp(enc(c)),
    ...lp(enc(d)),
    ...utf8.encode('Composite'),
  ], mode);
  final m = mul(di, c);
  return (m, k != null ? mul(k, m) : mul(di, d));
}

Scalar _challenge(
  int mode,
  Element b,
  Element m,
  Element z,
  Element t2,
  Element t3,
) =>
    hashToScalar([
      ...lp(enc(b)),
      ...lp(enc(m)),
      ...lp(enc(z)),
      ...lp(enc(t2)),
      ...lp(enc(t3)),
      ...utf8.encode('Challenge'),
    ], mode);

/// RFC 9497 §2.2.2 VerifyProof for one element, with A = generator.
bool verifyProof(
  int mode,
  Element b,
  Element c,
  Element d,
  List<int> proof,
) {
  if (proof.length != 64) return false;
  final Scalar cs;
  final Scalar ss;
  try {
    cs = decodeScalar(proof.sublist(0, 32));
    ss = decodeScalar(proof.sublist(32));
  } on VaultClientException {
    return false;
  }
  final (m, z) = _composites(mode, b, c, d);
  // Every input here is public, so variable-time multiplication is safe.
  final t2 = Element.newElement()..varTimeDoubleScalarBaseMult(cs, b, ss);
  final t3 = Element.newElement()..varTimeMultiScalarMult([ss, cs], [m, z]);
  return _challenge(mode, b, m, z, t2, t3).equal(cs) == 1;
}

/// RFC 9497 §2.2.1 GenerateProof for one element, with A = generator.
/// Host-side; used by tests and local harnesses.
Uint8List generateProof(
  int mode,
  Scalar k,
  Element b,
  Element c,
  Element d, {
  Random? random,
}) {
  final (m, z) = _composites(mode, b, c, d, k: k);
  final r = randomScalar(random);
  final t2 = mulGen(r);
  final t3 = mul(r, m);
  final cs = _challenge(mode, b, m, z, t2, t3);
  final ss = Scalar()..subtract(r, Scalar()..multiply(cs, k));
  return Uint8List.fromList([...cs.encode(), ...ss.encode()]);
}

/// `Hash(I2OSP(len(input),2) || input || [info] || I2OSP(len(N),2) || N || "Finalize")`.
Uint8List finalizeHash(List<int> input, Element unblinded, [List<int>? info]) =>
    Uint8List.fromList(
      VaultDigest.sha512([
        ...lp(input),
        if (info != null) ...lp(info),
        ...lp(enc(unblinded)),
        ...utf8.encode('Finalize'),
      ]),
    );

/// `expand_message_xmd` with SHA-512 (RFC 9380 §5.3.1).
Uint8List expandMessageXmdSha512(List<int> msg, List<int> dst, int len) {
  const hashBytes = 64;
  const blockBytes = 128;
  if (len <= 0 || len > 255 * hashBytes || dst.length > 255) {
    throw ArgumentError('expand_message_xmd parameters out of range');
  }
  final ell = (len + hashBytes - 1) ~/ hashBytes;
  final dstPrime = [...dst, dst.length];
  final b0 = VaultDigest.sha512([
    ...Uint8List(blockBytes),
    ...msg,
    ..._i2osp(len, 2),
    0,
    ...dstPrime,
  ]);
  var prev = VaultDigest.sha512([...b0, 1, ...dstPrime]);
  final out = <int>[...prev];
  for (var i = 2; i <= ell; i++) {
    final x = List<int>.generate(64, (j) => b0[j] ^ prev[j]);
    prev = VaultDigest.sha512([...x, i, ...dstPrime]);
    out.addAll(prev);
  }
  return Uint8List.fromList(out.sublist(0, len));
}

List<int> _i2osp(int value, int length) {
  final out = List<int>.filled(length, 0);
  var v = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = v & 0xff;
    v >>= 8;
  }
  return out;
}
