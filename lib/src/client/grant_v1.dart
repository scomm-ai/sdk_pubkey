import 'dart:convert';

/// Claims of a `Scomm/grant/v1` token (discovery-protocol
/// `spec/otp-grants.md` §3).
///
/// Clients read these to show expiry or route a grant to the right host.
/// They never verify the signature; the consuming host does.
class GrantV1Claims {
  const GrantV1Claims({
    required this.iss,
    required this.aud,
    required this.kid,
    required this.purpose,
    required this.identityId,
    required this.mskFingerprint,
    required this.amr,
    required this.idp,
    required this.exp,
    required this.jti,
  });

  final String iss;

  /// Audience origins.
  final List<String> aud;
  final String kid;
  final String purpose;
  final String identityId;

  /// Lowercase hex SHA-256 of the MSK public key, or empty.
  final String mskFingerprint;

  /// `otp` or `id_token`.
  final String amr;

  /// `google`, `microsoft`, or empty.
  final String idp;
  final DateTime exp;
  final String jti;

  bool isExpired([DateTime? now]) =>
      !(now ?? DateTime.now()).toUtc().isBefore(exp);
}

const String grantV1Header = 'Scomm/grant/v1';

const List<String> grantV1Fields = [
  'iss',
  'aud',
  'kid',
  'purpose',
  'identity_id',
  'msk_fingerprint',
  'amr',
  'idp',
  'exp',
  'jti',
];

final RegExp _hex64 = RegExp(r'^[0-9a-f]{64}$');
final RegExp _jti = RegExp(r'^[A-Za-z0-9_-]{22}$');

/// Returns the claims of a v1 token, or null when [token] is opaque (a
/// directory grant) or malformed.
GrantV1Claims? parseGrantV1(String token) {
  final dot = token.indexOf('.');
  if (dot <= 0) return null;
  final String text;
  try {
    text = utf8
        .decode(base64Url.decode(base64Url.normalize(token.substring(0, dot))));
  } on FormatException {
    return null;
  }
  return parseGrantV1Text(text);
}

/// Parses the signed text of a v1 grant.
GrantV1Claims? parseGrantV1Text(String text) {
  if (!text.endsWith('\n')) return null;
  final lines = text.substring(0, text.length - 1).split('\n');
  if (lines.first != grantV1Header ||
      lines.length != grantV1Fields.length + 1) {
    return null;
  }
  final claims = <String, String>{};
  for (var i = 0; i < grantV1Fields.length; i++) {
    final prefix = '${grantV1Fields[i]}=';
    final line = lines[i + 1];
    if (!line.startsWith(prefix)) return null;
    claims[grantV1Fields[i]] = line.substring(prefix.length);
  }
  final exp = int.tryParse(claims['exp']!);
  final msk = claims['msk_fingerprint']!;
  final amr = claims['amr']!;
  if (exp == null ||
      !_hex64.hasMatch(claims['identity_id']!) ||
      (msk.isNotEmpty && !_hex64.hasMatch(msk)) ||
      (amr != 'otp' && amr != 'id_token') ||
      !_jti.hasMatch(claims['jti']!) ||
      claims['iss']!.isEmpty ||
      claims['aud']!.isEmpty ||
      claims['kid']!.isEmpty ||
      claims['purpose']!.isEmpty) {
    return null;
  }
  return GrantV1Claims(
    iss: claims['iss']!,
    aud: claims['aud']!.split(' '),
    kid: claims['kid']!,
    purpose: claims['purpose']!,
    identityId: claims['identity_id']!,
    mskFingerprint: msk,
    amr: amr,
    idp: claims['idp']!,
    exp: DateTime.fromMillisecondsSinceEpoch(exp, isUtc: true),
    jti: claims['jti']!,
  );
}
