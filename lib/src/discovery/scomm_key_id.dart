import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// SComm content-addressable signing key-id helpers.
///
/// First 32 bits of `SHA-256(public_material)`, displayed as `XXXX-XXXX`.
abstract final class ScommKeyId {
  ScommKeyId._();

  /// Derive from published public key material bytes.
  static String derive(List<int> publicMaterial) {
    final digest = sha256.convert(publicMaterial).bytes;
    return format(Uint8List.fromList(digest.sublist(0, 4)));
  }

  /// Derive from UTF-8 text (e.g. armored key) when that is what was uploaded.
  static String deriveFromUtf8(String text) => derive(utf8.encode(text));

  static String format(Uint8List fourBytes) {
    if (fourBytes.length != 4) {
      throw ArgumentError('SComm key-id requires exactly 4 octets');
    }
    final hex = fourBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
    return '${hex.substring(0, 4)}-${hex.substring(4)}';
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

  static final RegExp displayPattern = RegExp(
    r'^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$',
  );

  static bool looksLikeDisplay(String? raw) =>
      raw != null && displayPattern.hasMatch(raw.trim());
}
