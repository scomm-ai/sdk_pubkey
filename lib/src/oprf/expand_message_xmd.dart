import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// `expand_message_xmd` with SHA-512 (RFC 9380).
Uint8List expandMessageXmdSha512(
  List<int> message,
  List<int> dst,
  int lengthInBytes,
) {
  const hashBytes = 64;
  const blockBytes = 128;
  if (lengthInBytes < 0 || lengthInBytes > 255 * hashBytes) {
    throw ArgumentError('expand_message_xmd length is out of range');
  }
  if (dst.length > 255) {
    throw ArgumentError('DST longer than 255 bytes is not used for identity OPRF');
  }
  final ell = (lengthInBytes + hashBytes - 1) ~/ hashBytes;
  final dstPrime = Uint8List(dst.length + 1)
    ..setRange(0, dst.length, dst)
    ..[dst.length] = dst.length;
  final msgPrime = BytesBuilder(copy: false)
    ..add(Uint8List(blockBytes))
    ..add(message)
    ..add(_i2osp(lengthInBytes, 2))
    ..addByte(0)
    ..add(dstPrime);
  final b0 = Uint8List.fromList(sha512.convert(msgPrime.toBytes()).bytes);
  var previous = Uint8List.fromList(
    sha512.convert([...b0, 1, ...dstPrime]).bytes,
  );
  final out = BytesBuilder(copy: false)..add(previous);
  for (var i = 2; i <= ell; i++) {
    previous = Uint8List.fromList(
      sha512.convert([..._xor(b0, previous), i, ...dstPrime]).bytes,
    );
    out.add(previous);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, lengthInBytes));
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

Uint8List _xor(List<int> a, List<int> b) {
  final out = Uint8List(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}
