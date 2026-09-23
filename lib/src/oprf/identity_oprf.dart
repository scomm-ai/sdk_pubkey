import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ristretto255/ristretto255.dart';

import '../errors.dart';
import '../identity.dart';
import 'expand_message_xmd.dart';

/// Base OPRF(ristretto255, SHA-512), RFC 9497 mode `0x00`.
///
/// `identity_id` is the first 32 bytes of Finalize (64 hex characters).
/// The OPRF input is the UTF-8 canonical mailbox. Pubkey Evaluate sees only
/// the blinded element.
const String identityOprfSuite = 'ristretto255-SHA512';
const String identityOprfInfo = 'Scomm/Pubkey/identity/v1';

final Uint8List identityOprfContextString = Uint8List.fromList([
  ...utf8.encode('OPRFV1-'),
  0x00,
  ...utf8.encode('-$identityOprfSuite'),
]);

class OprfBlindedInput {
  const OprfBlindedInput({required this.blind, required this.blindedElement});

  /// Canonical 32-byte scalar. Stays on the device.
  final Uint8List blind;

  /// 32-byte ristretto255 element sent to pubkey.
  final Uint8List blindedElement;
}

OprfBlindedInput oprfBlind(
  List<int> input, {
  Uint8List? blind,
  Random? random,
}) {
  final scalar = Scalar();
  if (blind != null) {
    scalar.setCanonicalBytes(blind);
  } else {
    final seed = Uint8List(64);
    final rng = random ?? Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = rng.nextInt(256);
    }
    scalar.setUniformBytes(seed);
    if (scalar.equal(Scalar()) == 1) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'OPRF sampled a zero blind',
      );
    }
  }
  final inputElement = _hashToGroup(input);
  if (inputElement.equal(Element.newIdentityElement()) == 1) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'OPRF input maps to the identity element',
    );
  }
  final blinded = Element.newElement()..scalarMult(scalar, inputElement);
  return OprfBlindedInput(
    blind: Uint8List.fromList(scalar.encode()),
    blindedElement: Uint8List.fromList(blinded.encode()),
  );
}

/// Server BlindEvaluate. Test and conformance use only — the app must not
/// hold the OPRF key.
Uint8List oprfBlindEvaluate({
  required Uint8List secretKey,
  required Uint8List blindedElement,
}) {
  final scalar = Scalar()..setCanonicalBytes(secretKey);
  final element = _decodeElement(blindedElement);
  final evaluated = Element.newElement()..scalarMult(scalar, element);
  return Uint8List.fromList(evaluated.encode());
}

/// RFC 9497 Finalize. Output is SHA-512 (`Nh` = 64).
Uint8List oprfFinalize({
  required List<int> input,
  required Uint8List blind,
  required Uint8List evaluatedElement,
}) {
  final inverse = Scalar()..invert(Scalar()..setCanonicalBytes(blind));
  final evaluated = _decodeElement(evaluatedElement);
  final unblinded = Element.newElement()..scalarMult(inverse, evaluated);
  final serialized = Uint8List.fromList(unblinded.encode());
  final hashInput = BytesBuilder(copy: false)
    ..add(_i2osp(input.length, 2))
    ..add(input)
    ..add(_i2osp(serialized.length, 2))
    ..add(serialized)
    ..add(utf8.encode('Finalize'));
  return Uint8List.fromList(sha512.convert(hashInput.toBytes()).bytes);
}

/// 64-character lowercase hex `identity_id`.
String identityIdFromOprfFinalize(List<int> finalizeOutput) {
  if (finalizeOutput.length < 32) {
    throw ArgumentError('OPRF Finalize output must be at least 32 bytes');
  }
  return bytesToHex(finalizeOutput.sublist(0, 32));
}

Element _hashToGroup(List<int> input) {
  final dst = Uint8List.fromList([
    ...utf8.encode('HashToGroup-'),
    ...identityOprfContextString,
  ]);
  final uniform = expandMessageXmdSha512(input, dst, 64);
  return Element.newElement()..setUniformBytes(uniform);
}

Element _decodeElement(List<int> bytes) {
  if (bytes.length != 32) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'OPRF element must be 32 bytes',
    );
  }
  final element = Element.newElement();
  try {
    element.setCanonicalBytes(Uint8List.fromList(bytes));
  } catch (_) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'OPRF element is not a canonical ristretto255 encoding',
    );
  }
  if (element.equal(Element.newIdentityElement()) == 1) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'OPRF element is the identity',
    );
  }
  return element;
}

Uint8List _i2osp(int value, int length) {
  final out = Uint8List(length);
  var remaining = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = remaining & 0xff;
    remaining >>= 8;
  }
  return out;
}
