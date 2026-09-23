import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'errors.dart';

const int _maxEmailOctets = 254;
const int _maxLocalOctets = 64;
const int _maxDomainOctets = 255;
const int _maxLabelOctets = 63;

final _localChars = RegExp(
  r"^[\p{L}\p{N}\p{M}!#$%&'*+/=?^_`{|}~.-]+$",
  unicode: true,
);
final _domainLabelChars = RegExp(r'^[\p{L}\p{N}\p{M}-]+$', unicode: true);
final _disallowedInAddress = RegExp(r'[\s\p{Cc}\p{Cf}]', unicode: true);
final _digitsOnly = RegExp(r'^\d+$');
final _hasLetter = RegExp(r'\p{L}', unicode: true);

String _nfc(String value) => unorm.nfc(value);

String _foldUtf8(String value) => _nfc(value.toLowerCase());

int utf8ByteLength(String value) => utf8.encode(value).length;

String bytesToHex(List<int> bytes) {
  final out = StringBuffer();
  for (final byte in bytes) {
    out.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

Uint8List hexToBytes(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  if (clean.length.isOdd) {
    throw ArgumentError('hex string must have even length');
  }
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Public mailbox canonicalization. Must match pubkey `src/lib/emailTid.ts`.
///
/// `+` in the local part is identity-significant. RFC 5322 treats it as a
/// normal local-part character; RFC 5233 subaddressing is a per-provider
/// delivery convention, not a global alias. Stripping `+tag` would fold
/// distinct mailboxes (and Gmail plus-aliases) into one CKVF principal.
String normalizeEmail(String? email) {
  if (email == null) {
    return '';
  }
  final trimmed = _nfc(email.trim());
  final at = trimmed.lastIndexOf('@');
  if (at <= 0 || at == trimmed.length - 1) {
    return _foldUtf8(trimmed);
  }
  final local = _foldUtf8(trimmed.substring(0, at));
  final domain = _foldUtf8(trimmed.substring(at + 1));
  return '$local@$domain';
}

bool _isValidLocalPart(String local) {
  if (local.isEmpty ||
      local.startsWith('.') ||
      local.endsWith('.') ||
      local.contains('..')) {
    return false;
  }
  return _localChars.hasMatch(local);
}

bool _isValidDomain(String domain) {
  if (domain.startsWith('[') ||
      domain.endsWith(']') ||
      domain.startsWith('.') ||
      domain.endsWith('.') ||
      domain.contains('..')) {
    return false;
  }
  final labels = domain.split('.');
  if (labels.length < 2) {
    return false;
  }
  for (final label in labels) {
    if (label.isEmpty ||
        utf8ByteLength(label) > _maxLabelOctets ||
        label.startsWith('-') ||
        label.endsWith('-') ||
        !_domainLabelChars.hasMatch(label)) {
      return false;
    }
  }
  final tld = labels.last;
  if (tld.length < 2 || _digitsOnly.hasMatch(tld) || !_hasLetter.hasMatch(tld)) {
    return false;
  }
  return true;
}

bool isValidEmail(String? email) {
  if (email == null || email.isEmpty) {
    return false;
  }
  if (_disallowedInAddress.hasMatch(email) || email.contains('\u0000')) {
    return false;
  }
  final at = email.indexOf('@');
  if (at <= 0 || at != email.lastIndexOf('@') || at == email.length - 1) {
    return false;
  }
  final local = email.substring(0, at);
  final domain = email.substring(at + 1);
  if (utf8ByteLength(email) > _maxEmailOctets ||
      utf8ByteLength(local) > _maxLocalOctets ||
      utf8ByteLength(domain) > _maxDomainOctets) {
    return false;
  }
  return _isValidLocalPart(local) && _isValidDomain(domain);
}

/// Unsalted SHA-256 of the canonical mailbox, lowercase hex. Directory
/// locator only. Callers MUST pass a mailbox string; do not pre-hash.
String emailSha256Hex(String email) {
  final canonical = requireCanonicalEmail(normalizeEmail(email));
  return bytesToHex(sha256Bytes(canonical));
}

String requireCanonicalEmail(String? email) {
  if (email == null || email.isEmpty) {
    throw PubkeyException(ErrorCodes.invalidEmail, 'Valid email is required');
  }
  final canonical = normalizeEmail(email);
  if (email != canonical) {
    throw PubkeyException(
      ErrorCodes.emailNotCanonical,
      'Email must be sent in canonical form',
    );
  }
  if (!isValidEmail(canonical)) {
    throw PubkeyException(ErrorCodes.invalidEmail, 'Valid email is required');
  }
  return canonical;
}

/// UUID v8 from the last 16 bytes of a SHA-256 digest (RFC 9562 version + variant).
String sha256ToUuidV8(List<int> sha256) {
  if (sha256.length != 32) {
    throw ArgumentError('sha256 must be a 32-byte SHA-256 digest');
  }
  final bytes = Uint8List.fromList(sha256.sublist(16, 32));
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final hex = bytesToHex(bytes);
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-'
      '${hex.substring(20, 32)}';
}

Uint8List sha256Bytes(Object data) {
  final encoded = data is String ? utf8.encode(data) : data as List<int>;
  return Uint8List.fromList(sha256.convert(encoded).bytes);
}

String textToUuidV8(String value) => sha256ToUuidV8(sha256Bytes(value));

int uuidLast16Bits(String uuid) {
  final hex = uuid.replaceAll('-', '');
  return int.parse(hex.substring(28, 32), radix: 16);
}
