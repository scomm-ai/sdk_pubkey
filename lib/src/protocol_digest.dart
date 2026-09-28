import 'dart:typed_data';

/// SHA-256 and SHA-512 installed by the host at startup.
///
/// The library does not implement these hashes. [install] is called once
/// from the app's OpenSSL provider, and from SDK tests.
abstract final class ProtocolDigest {
  static Uint8List Function(List<int> data)? _sha256;
  static Uint8List Function(List<int> data)? _sha512;

  static void install({
    required Uint8List Function(List<int> data) sha256,
    required Uint8List Function(List<int> data) sha512,
  }) {
    _sha256 = sha256;
    _sha512 = sha512;
  }

  static Uint8List sha256(List<int> data) {
    final fn = _sha256;
    if (fn == null) {
      throw StateError('ProtocolDigest.sha256 is not installed');
    }
    return fn(data);
  }

  static Uint8List sha512(List<int> data) {
    final fn = _sha512;
    if (fn == null) {
      throw StateError('ProtocolDigest.sha512 is not installed');
    }
    return fn(data);
  }
}
