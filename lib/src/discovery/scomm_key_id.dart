import 'dart:convert';
import 'dart:typed_data';

import '../protocol_digest.dart';

/// SComm key-id: last 8 octets of the key fingerprint, 16 uppercase hex digits.
///
/// OpenPGP material uses the OpenPGP fingerprint of the key packet Sequoia
/// uses (v4 SHA-1 or v6 SHA-256). Verify uses the primary key; encryption
/// uses the encryption subkey. That value is Sequoia's Key ID.
///
/// S/MIME and any other bytes use SHA-256 of the published material. The last
/// 8 octets of that digest are the key-id.
abstract final class ScommKeyId {
  ScommKeyId._();

  /// Derive from published public key material bytes.
  static String derive(
    List<int> publicMaterial, {
    String? purpose,
    String? algorithm,
  }) {
    final pgp = _openPgpKeyId(publicMaterial, purpose, algorithm);
    if (pgp != null) return pgp;
    final digest = ProtocolDigest.sha256(publicMaterial);
    return format(Uint8List.fromList(digest.sublist(digest.length - 8)));
  }

  /// Derive from UTF-8 text (e.g. armored key) when that is what was uploaded.
  static String deriveFromUtf8(
    String text, {
    String? purpose,
    String? algorithm,
  }) =>
      derive(utf8.encode(text), purpose: purpose, algorithm: algorithm);

  static String format(Uint8List eightBytes) {
    if (eightBytes.length != 8) {
      throw ArgumentError('SComm key-id requires exactly 8 octets');
    }
    return eightBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
  }

  /// Strip separators; uppercase. Empty → empty.
  static String normalize(String? raw) {
    if (raw == null) return '';
    return raw.trim().toUpperCase().replaceAll(RegExp(r'[\s:\-_]'), '');
  }

  static bool equals(String? a, String? b) {
    final na = normalize(a);
    final nb = normalize(b);
    if (na.isEmpty || nb.isEmpty) return false;
    return na == nb;
  }

  static final RegExp displayPattern = RegExp(r'^[0-9A-Fa-f]{16}$');

  static bool looksLikeDisplay(String? raw) =>
      raw != null && displayPattern.hasMatch(normalize(raw));
}

String? _openPgpKeyId(List<int> blob, String? purpose, String? algorithm) {
  final packets = _packets(blob);
  if (packets == null) return null;
  final keys = [
    for (final p in packets)
      if (p.tag == 6 || p.tag == 14) p,
  ];
  if (keys.isEmpty) return null;
  final encrypt = purpose == 'encryption' || purpose == 'key_agreement';
  _Packet bodyOwner;
  if (keys.length == 1) {
    bodyOwner = keys.first;
  } else if (encrypt) {
    final subs = keys.where((k) => k.tag == 14).toList();
    _Packet? matched;
    if (algorithm != null) {
      for (final k in subs) {
        if (_subkeyMatches(k.body, algorithm)) {
          matched = k;
          break;
        }
      }
    }
    bodyOwner = matched ?? (subs.isNotEmpty ? subs.first : keys.first);
  } else {
    bodyOwner = keys.firstWhere((k) => k.tag == 6, orElse: () => keys.first);
  }
  return _keyIdFromBody(bodyOwner.body);
}

class _Packet {
  _Packet(this.tag, this.body);
  final int tag;
  final Uint8List body;
}

List<_Packet>? _packets(List<int> blob) {
  final data = blob is Uint8List ? blob : Uint8List.fromList(blob);
  final out = <_Packet>[];
  var offset = 0;
  while (offset < data.length) {
    final first = data[offset];
    if ((first & 0x80) == 0) return null;
    int tag;
    int hdr = 1;
    int length;
    try {
      if ((first & 0x40) != 0) {
        tag = first & 0x3f;
        final parsed = _newLength(data, offset + 1);
        hdr += parsed.$2;
        length = parsed.$1;
      } else {
        tag = (first & 0x3c) >> 2;
        final lenType = first & 0x03;
        if (lenType == 0) {
          length = data[offset + 1];
          hdr += 1;
        } else if (lenType == 1) {
          length = (data[offset + 1] << 8) | data[offset + 2];
          hdr += 2;
        } else if (lenType == 2) {
          length = (data[offset + 1] << 24) |
              (data[offset + 2] << 16) |
              (data[offset + 3] << 8) |
              data[offset + 4];
          hdr += 4;
        } else {
          return null;
        }
      }
    } catch (_) {
      return null;
    }
    if (offset + hdr + length > data.length) return null;
    out.add(_Packet(tag, data.sublist(offset + hdr, offset + hdr + length)));
    offset += hdr + length;
  }
  return out;
}

(int, int) _newLength(Uint8List data, int offset) {
  final first = data[offset];
  if (first < 192) return (first, 1);
  if (first < 224) {
    return ((first - 192) * 256 + data[offset + 1] + 192, 2);
  }
  if (first == 255) {
    final len = (data[offset + 1] << 24) |
        (data[offset + 2] << 16) |
        (data[offset + 3] << 8) |
        data[offset + 4];
    return (len, 5);
  }
  throw StateError('partial OpenPGP length');
}

String? _keyIdFromBody(Uint8List body) {
  if (body.isEmpty) return null;
  final version = body[0];
  Uint8List digest;
  if (version == 4) {
    if (body.length > 0xffff) return null;
    final prefix = Uint8List(3);
    prefix[0] = 0x99;
    prefix[1] = (body.length >> 8) & 0xff;
    prefix[2] = body.length & 0xff;
    digest = _sha1(Uint8List.fromList([...prefix, ...body]));
  } else if (version == 6) {
    final prefix = Uint8List(5);
    prefix[0] = 0x9b;
    final n = body.length;
    prefix[1] = (n >> 24) & 0xff;
    prefix[2] = (n >> 16) & 0xff;
    prefix[3] = (n >> 8) & 0xff;
    prefix[4] = n & 0xff;
    digest = ProtocolDigest.sha256(Uint8List.fromList([...prefix, ...body]));
  } else {
    return null;
  }
  return ScommKeyId.format(digest.sublist(digest.length - 8));
}

bool _subkeyMatches(Uint8List body, String algorithmName) {
  if (body.isEmpty || (body[0] != 4 && body[0] != 6)) return false;
  var offset = 5;
  final algorithm = body[offset];
  offset += 1;
  if (body[0] == 6) offset += 4;
  if (algorithmName == 'openpgp-cv25519') {
    if (algorithm == 25) return true;
    if (algorithm == 18) {
      final oid = _oid(body, offset);
      return _eq(oid, [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]) ||
          _eq(oid, [0x2b, 0x65, 0x6e]);
    }
  }
  if (algorithmName == 'openpgp-cv448') {
    if (algorithm == 26) return true;
    if (algorithm == 18) return _eq(_oid(body, offset), [0x2b, 0x65, 0x6f]);
  }
  if (algorithmName == 'openpgp-mlkem768-x25519') return algorithm == 35;
  return false;
}

Uint8List? _oid(Uint8List body, int offset) {
  if (offset >= body.length) return null;
  final len = body[offset];
  final start = offset + 1;
  if (start + len > body.length) return null;
  return body.sublist(start, start + len);
}

bool _eq(Uint8List? a, List<int> b) {
  if (a == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List _sha1(Uint8List data) {
  final bitLen = data.length * 8;
  final padLen = ((data.length + 9 + 63) ~/ 64) * 64;
  final padded = Uint8List(padLen);
  padded.setRange(0, data.length, data);
  padded[data.length] = 0x80;
  final view = ByteData.sublistView(padded);
  view.setUint32(padLen - 8, bitLen ~/ 0x100000000, Endian.big);
  view.setUint32(padLen - 4, bitLen & 0xffffffff, Endian.big);
  var h0 = 0x67452301;
  var h1 = 0xEFCDAB89;
  var h2 = 0x98BADCFE;
  var h3 = 0x10325476;
  var h4 = 0xC3D2E1F0;
  int rotl(int n, int s) => ((n << s) | (n >>> (32 - s))) & 0xffffffff;
  final w = List<int>.filled(80, 0);
  for (var chunk = 0; chunk < padLen; chunk += 64) {
    for (var t = 0; t < 16; t++) {
      w[t] = view.getUint32(chunk + t * 4, Endian.big);
    }
    for (var t = 16; t < 80; t++) {
      w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4;
    for (var t = 0; t < 80; t++) {
      late int f;
      late int k;
      if (t < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      final temp = (rotl(a, 5) + (f & 0xffffffff) + e + k + w[t]) & 0xffffffff;
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = temp;
    }
    h0 = (h0 + a) & 0xffffffff;
    h1 = (h1 + b) & 0xffffffff;
    h2 = (h2 + c) & 0xffffffff;
    h3 = (h3 + d) & 0xffffffff;
    h4 = (h4 + e) & 0xffffffff;
  }
  final out = Uint8List(20);
  final o = ByteData.sublistView(out);
  o.setUint32(0, h0, Endian.big);
  o.setUint32(4, h1, Endian.big);
  o.setUint32(8, h2, Endian.big);
  o.setUint32(12, h3, Endian.big);
  o.setUint32(16, h4, Endian.big);
  return out;
}
