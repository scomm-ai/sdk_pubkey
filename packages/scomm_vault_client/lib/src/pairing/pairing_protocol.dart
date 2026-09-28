import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';

import '../digest.dart';

import '../errors.dart';

const String pairingCpaceSidInfo = 'SComm/Pubkey/pairing/cpace/v2';
const String pairingTekHkdfInfo = 'SComm/Pubkey/pairing/tek/v2';
const String pairingTranscriptHeader = 'SComm/Pubkey/pairing/transcript/v2';
const String pairingConfirmPlaintext = 'SComm/Pubkey/pairing/confirm/v2';
const String pairingUriScheme = 'scomm-pair';
const String pairingUriVersion = 'v2';

/// The host still requires a tier field; CKVF pairing always transfers the
/// VEK, so every paired device has full authority.
const String pairingTier = 'full';

const int pairingSessionIdBytes = 16;
const int pairingHighEntropyPasswordBytes = 16;
const int pairingTypedPasswordLength = 16;

const String _crockford = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/// `{iv, ciphertext}` with the 16-byte GCM tag appended to the ciphertext.
class PairingBox {
  const PairingBox({required this.iv, required this.ciphertext});

  factory PairingBox.fromJson(Map<String, dynamic> json) => PairingBox(
        iv: base64urlToBytes('${json['iv']}', 12),
        ciphertext: base64urlToBytes('${json['ciphertext']}'),
      );

  final Uint8List iv;
  final Uint8List ciphertext;

  Map<String, String> toJson() => {
        'iv': bytesToBase64url(iv),
        'ciphertext': bytesToBase64url(ciphertext),
      };

  String get wire => bytesToBase64url([...iv, ...ciphertext]);
}

/// `scomm-pair:v2?sid=…&pw=…`, shown as a QR code by the new device.
class PairingUri {
  const PairingUri({required this.sessionId, required this.password});

  final String sessionId;
  final Uint8List password;

  String toUriString() =>
      '$pairingUriScheme:$pairingUriVersion?sid=${Uri.encodeQueryComponent(sessionId)}'
      '&pw=${Uri.encodeQueryComponent(bytesToBase64url(password))}';

  static PairingUri? tryParse(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty) return null;
    final Uri uri;
    try {
      uri = Uri.parse(trimmed);
    } on FormatException {
      return null;
    }
    if (uri.scheme != pairingUriScheme) return null;
    final version = uri.path.isNotEmpty ? uri.path : uri.host;
    if (version != pairingUriVersion) return null;
    final sid = uri.queryParameters['sid'];
    final pw = uri.queryParameters['pw'];
    if (sid == null || sid.isEmpty || pw == null || pw.isEmpty) return null;
    final Uint8List password;
    try {
      password = base64urlToBytes(pw);
    } on Object {
      return null;
    }
    if (password.length < pairingHighEntropyPasswordBytes) return null;
    return PairingUri(sessionId: sid, password: password);
  }
}

abstract final class PairingProtocol {
  static String generateSessionId(CkvfCrypto crypto) => crypto
      .randomBytes(pairingSessionIdBytes)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  static Uint8List generateHighEntropyPassword(CkvfCrypto crypto) =>
      crypto.randomBytes(pairingHighEntropyPasswordBytes);

  /// 16 Crockford Base32 characters (80 bits) for typing on the other device.
  static String generateTypedPassword(CkvfCrypto crypto) {
    final bytes = crypto.randomBytes(10);
    var acc = 0;
    var bits = 0;
    var i = 0;
    final out = StringBuffer();
    while (out.length < pairingTypedPasswordLength) {
      if (bits < 5) {
        acc = ((acc << 8) | bytes[i++]) & 0xffff;
        bits += 8;
      }
      bits -= 5;
      out.write(_crockford[(acc >> bits) & 0x1f]);
    }
    return out.toString();
  }

  static Uint8List typedPasswordBytes(String typed) {
    final normalized = typed.trim().toUpperCase();
    if (normalized.length != pairingTypedPasswordLength ||
        normalized.split('').any((c) => !_crockford.contains(c))) {
      throw VaultClientException(
        'pairing_password_mismatch',
        'Typed pairing password must be $pairingTypedPasswordLength Crockford characters',
      );
    }
    return Uint8List.fromList(utf8.encode(normalized));
  }

  static Uint8List sid(String sessionId, String identityId) {
    final material = BytesBuilder(copy: false)
      ..add(utf8.encode(pairingCpaceSidInfo))
      ..addByte(0)
      ..add(utf8.encode(sessionId))
      ..addByte(0)
      ..add(utf8.encode(identityId))
      ..addByte(0)
      ..add(utf8.encode(pairingTier));
    return VaultDigest.sha256(material.toBytes());
  }

  static Uint8List ci(String identityId) =>
      Uint8List.fromList(utf8.encode(identityId));

  static Uint8List tek(
    List<int> isk, {
    required String sessionId,
    required List<int> ya,
    required List<int> yb,
    required String identityId,
  }) =>
      hkdfSha256(isk, [
        ...utf8.encode(pairingTekHkdfInfo),
        ...utf8.encode(sessionId),
        ...ya,
        ...yb,
        ...utf8.encode(identityId),
        ...utf8.encode(pairingTier),
        ...utf8.encode('v2'),
      ]);

  static Uint8List transcript({
    required String sessionId,
    required String identityId,
    required List<int> ya,
    required List<int> yb,
    required PairingBox confirmationTag,
  }) =>
      Uint8List.fromList(utf8.encode(
        '$pairingTranscriptHeader\n'
        'session_id=$sessionId\n'
        'identity=$identityId\n'
        'requested_tier=$pairingTier\n'
        'ya=${bytesToBase64url(ya)}\n'
        'yb=${bytesToBase64url(yb)}\n'
        'confirmation_tag=${confirmationTag.wire}\n',
      ));

  static Future<PairingBox> seal(
    CkvfCrypto crypto,
    List<int> key,
    List<int> plaintext,
  ) async {
    final iv = crypto.randomBytes(12);
    final enc = await crypto.aes256gcmEncrypt(key, iv, plaintext, const []);
    return PairingBox(
      iv: iv,
      ciphertext: Uint8List.fromList([...enc.ciphertext, ...enc.tag]),
    );
  }

  static Future<Uint8List> open(
    CkvfCrypto crypto,
    List<int> key,
    PairingBox box,
  ) async {
    final n = box.ciphertext.length;
    if (n < 16) {
      throw VaultClientException('pairing_protocol_error', 'box is truncated');
    }
    return crypto.aes256gcmDecrypt(
      key,
      box.iv,
      box.ciphertext.sublist(0, n - 16),
      box.ciphertext.sublist(n - 16),
      const [],
    );
  }
}

/// RFC 5869 HKDF-SHA-256; the default salt is 32 zero bytes.
Uint8List hkdfSha256(
  List<int> ikm,
  List<int> info, {
  int length = 32,
  List<int>? salt,
}) {
  final prk = VaultDigest.hmacSha256(salt ?? Uint8List(32), ikm);
  final out = BytesBuilder(copy: false);
  var t = <int>[];
  for (var i = 1; out.length < length; i++) {
    t = VaultDigest.hmacSha256(prk, [...t, ...info, i]);
    out.add(t);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, length));
}
