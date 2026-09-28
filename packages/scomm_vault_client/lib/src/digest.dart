import 'dart:typed_data';

/// SHA-256, SHA-512, and HMAC-SHA-256 installed by the host at startup.
abstract final class VaultDigest {
  static Uint8List Function(List<int> data)? _sha256;
  static Uint8List Function(List<int> data)? _sha512;
  static Uint8List Function(List<int> key, List<int> data)? _hmacSha256;

  static void install({
    required Uint8List Function(List<int> data) sha256,
    required Uint8List Function(List<int> data) sha512,
    required Uint8List Function(List<int> key, List<int> data) hmacSha256,
  }) {
    _sha256 = sha256;
    _sha512 = sha512;
    _hmacSha256 = hmacSha256;
  }

  static Uint8List sha256(List<int> data) {
    final fn = _sha256;
    if (fn == null) {
      throw StateError('VaultDigest.sha256 is not installed');
    }
    return fn(data);
  }

  static Uint8List sha512(List<int> data) {
    final fn = _sha512;
    if (fn == null) {
      throw StateError('VaultDigest.sha512 is not installed');
    }
    return fn(data);
  }

  static Uint8List hmacSha256(List<int> key, List<int> data) {
    final fn = _hmacSha256;
    if (fn == null) {
      throw StateError('VaultDigest.hmacSha256 is not installed');
    }
    return fn(key, data);
  }

  static String sha256Hex(List<int> data) {
    final digest = sha256(data);
    final hex = StringBuffer();
    for (final b in digest) {
      hex.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return hex.toString();
  }
}
