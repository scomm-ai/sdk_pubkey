import 'dart:convert';
import 'dart:typed_data';

import '../constants.dart';

/// RFC 9980 OpenPGP PQC helpers (catalog names + conservative packet probes).
abstract final class OpenPgpRfc9980 {
  static bool isPqcCatalogName(String? name) {
    if (name == null || name.isEmpty) return false;
    final n = name.trim().toLowerCase();
    return n == OpenPgpAlgorithms.mldsa65Ed25519 ||
        n == OpenPgpAlgorithms.mlkem768X25519;
  }

  /// True when [bytes] contain an RFC 9980 algorithm on a version this
  /// profile accepts. Algorithm 35 counts on version 4 or 6. Algorithms
  /// 30–34 and 36 count only on version 6. A version 3 PKESK is the
  /// version 4 key form.
  static bool looksLikeRfc9980(List<int> bytes) {
    return _acceptedRfc9980Ids(bytes).isNotEmpty;
  }

  /// LibrePGP experimental Kyber (IDs 105/106) — not RFC 9980; reject on import.
  static bool looksLikeLibrePgpKyber(List<int> bytes) {
    return _publicKeyAlgorithmIds(bytes).any(OpenPgpAlgorithms.isLibrePgpKyberId);
  }

  static bool messageLooksPqc({
    String? text,
    String? html,
    List<int>? binary,
  }) {
    if (binary != null && binary.isNotEmpty && looksLikeRfc9980(binary)) {
      return true;
    }
    for (final sample in [text, html]) {
      if (sample == null || sample.isEmpty) continue;
      final decoded = decodePgpArmor(sample);
      if (decoded != null && looksLikeRfc9980(decoded)) return true;
    }
    return false;
  }

  static Uint8List? decodePgpArmor(String source) {
    final begin = source.indexOf('-----BEGIN PGP ');
    if (begin < 0) return null;
    final headerEnd = source.indexOf('-----', begin + 5);
    if (headerEnd < 0) return null;
    final endMarker = source.indexOf('-----END PGP ', headerEnd);
    if (endMarker < 0) return null;
    var body = source.substring(headerEnd + 5, endMarker);
    final blank = body.indexOf('\n\n');
    if (blank >= 0) body = body.substring(blank + 2);
    final crc = body.indexOf('\n=');
    if (crc >= 0) body = body.substring(0, crc);
    final compact = body.replaceAll(RegExp(r'\s'), '');
    if (compact.isEmpty) return null;
    try {
      return Uint8List.fromList(base64Decode(compact));
    } catch (_) {
      return null;
    }
  }

  static Set<int> _publicKeyAlgorithmIds(List<int> bytes) {
    final ids = <int>{};
    var offset = 0;
    while (offset < bytes.length) {
      final parsed = _readPacket(bytes, offset);
      if (parsed == null) break;
      offset = parsed.next;
      final tag = parsed.tag;
      final body = parsed.body;
      if (body.isEmpty) continue;
      if (tag == 1) {
        // PKESK
        final version = body[0];
        if (version == 3 && body.length >= 10) {
          ids.add(body[9]);
        } else if (version == 6 && body.length >= 3) {
          final fpLen = body[1];
          final algoAt = 2 + fpLen;
          if (algoAt < body.length) ids.add(body[algoAt]);
        }
      } else if (tag == 2 && body.length >= 4) {
        if (body[0] == 4 || body[0] == 6) ids.add(body[2]);
      } else if ((tag == 5 || tag == 6 || tag == 7 || tag == 14) &&
          body.length >= 6) {
        if (body[0] == 4 || body[0] == 6) ids.add(body[5]);
      }
    }
    return ids;
  }

  static Set<int> _acceptedRfc9980Ids(List<int> bytes) {
    final ids = <int>{};
    var offset = 0;
    while (offset < bytes.length) {
      final parsed = _readPacket(bytes, offset);
      if (parsed == null) break;
      offset = parsed.next;
      final tag = parsed.tag;
      final body = parsed.body;
      if (body.isEmpty) continue;
      if (tag == 1) {
        final version = body[0];
        if (version == 3 && body.length >= 10) {
          _addIfAccepted(ids, 4, body[9]);
        } else if (version == 6 && body.length >= 3) {
          final fpLen = body[1];
          final algoAt = 2 + fpLen;
          if (algoAt < body.length) _addIfAccepted(ids, 6, body[algoAt]);
        }
      } else if (tag == 2 && body.length >= 4) {
        if (body[0] == 4 || body[0] == 6) {
          _addIfAccepted(ids, body[0], body[2]);
        }
      } else if ((tag == 5 || tag == 6 || tag == 7 || tag == 14) &&
          body.length >= 6) {
        if (body[0] == 4 || body[0] == 6) {
          _addIfAccepted(ids, body[0], body[5]);
        }
      }
    }
    return ids;
  }

  static void _addIfAccepted(Set<int> ids, int version, int algorithmId) {
    if (OpenPgpAlgorithms.acceptsRfc9980(
      version: version,
      algorithmId: algorithmId,
    )) {
      ids.add(algorithmId);
    }
  }

  static ({int tag, List<int> body, int next})? _readPacket(
    List<int> bytes,
    int offset,
  ) {
    if (offset >= bytes.length) return null;
    final first = bytes[offset];
    if ((first & 0x80) == 0) return null;
    if ((first & 0x40) != 0) {
      final tag = first & 0x3f;
      final len = _newFormatLength(bytes, offset + 1);
      if (len == null) return null;
      final start = len.bodyStart;
      final end = start + len.length;
      if (end > bytes.length) return null;
      return (tag: tag, body: bytes.sublist(start, end), next: end);
    }
    final tag = (first >> 2) & 0x0f;
    final lenType = first & 0x03;
    var header = offset + 1;
    int length;
    if (lenType == 0) {
      if (header >= bytes.length) return null;
      length = bytes[header];
      header += 1;
    } else if (lenType == 1) {
      if (header + 1 >= bytes.length) return null;
      length = (bytes[header] << 8) | bytes[header + 1];
      header += 2;
    } else if (lenType == 2) {
      if (header + 3 >= bytes.length) return null;
      length = (bytes[header] << 24) |
          (bytes[header + 1] << 16) |
          (bytes[header + 2] << 8) |
          bytes[header + 3];
      header += 4;
    } else {
      return null;
    }
    final end = header + length;
    if (end > bytes.length) return null;
    return (tag: tag, body: bytes.sublist(header, end), next: end);
  }

  static ({int length, int bodyStart})? _newFormatLength(
    List<int> bytes,
    int offset,
  ) {
    if (offset >= bytes.length) return null;
    final first = bytes[offset];
    if (first < 192) {
      return (length: first, bodyStart: offset + 1);
    }
    if (first < 224) {
      if (offset + 1 >= bytes.length) return null;
      final length = ((first - 192) << 8) + bytes[offset + 1] + 192;
      return (length: length, bodyStart: offset + 2);
    }
    if (first == 255) {
      if (offset + 4 >= bytes.length) return null;
      final length = (bytes[offset + 1] << 24) |
          (bytes[offset + 2] << 16) |
          (bytes[offset + 3] << 8) |
          bytes[offset + 4];
      return (length: length, bodyStart: offset + 5);
    }
    return null;
  }
}
