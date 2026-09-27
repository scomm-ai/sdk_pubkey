import 'dart:convert';

/// `Authorization` header for vault reads and pepper evaluation
/// (ckvf `profiles/vault-host.md` §4).
class VaultAuthorization {
  const VaultAuthorization._(this.header);

  /// Signed `Scomm/grant/v1` vault grant (`vault_backup`,
  /// `recovery_generation`, `recovery_envelope`). Single use.
  factory VaultAuthorization.otpGrant(String grant) =>
      VaultAuthorization._('OtpGrant $grant');

  /// Token from a pairing session. Single use.
  factory VaultAuthorization.pairingRead(String token) =>
      VaultAuthorization._('PairingRead $token');

  /// `oprf_token` returned with a grant-authorized read: up to five pepper
  /// evaluations for that `vault_id` within ten minutes.
  factory VaultAuthorization.oprfToken(String token) =>
      VaultAuthorization._('OprfToken $token');

  /// Base64url JSON envelope signed by an enrolled device key.
  factory VaultAuthorization.device(String envelopeB64) =>
      VaultAuthorization._('Device $envelopeB64');

  final String header;
}

/// Claims of a `Scomm/grant/v1` token. Clients read them to route a grant
/// and show expiry; the consuming host verifies the signature.
class GrantV1Claims {
  const GrantV1Claims({
    required this.iss,
    required this.aud,
    required this.purpose,
    required this.identityId,
    required this.mskFingerprint,
    required this.exp,
    required this.jti,
  });

  final String iss;
  final List<String> aud;
  final String purpose;
  final String identityId;
  final String mskFingerprint;
  final DateTime exp;
  final String jti;

  bool isExpired([DateTime? now]) =>
      !(now ?? DateTime.now()).toUtc().isBefore(exp);
}

const _fields = [
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

/// Null for opaque directory grants and malformed tokens.
GrantV1Claims? parseGrantV1(String token) {
  final dot = token.indexOf('.');
  if (dot <= 0) return null;
  final String text;
  try {
    text = utf8.decode(
      base64Url.decode(base64Url.normalize(token.substring(0, dot))),
    );
  } on FormatException {
    return null;
  }
  if (!text.endsWith('\n')) return null;
  final lines = text.substring(0, text.length - 1).split('\n');
  if (lines.first != 'Scomm/grant/v1' || lines.length != _fields.length + 1) {
    return null;
  }
  final c = <String, String>{};
  for (var i = 0; i < _fields.length; i++) {
    final prefix = '${_fields[i]}=';
    if (!lines[i + 1].startsWith(prefix)) return null;
    c[_fields[i]] = lines[i + 1].substring(prefix.length);
  }
  final exp = int.tryParse(c['exp']!);
  if (exp == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(c['identity_id']!)) {
    return null;
  }
  return GrantV1Claims(
    iss: c['iss']!,
    aud: c['aud']!.split(' '),
    purpose: c['purpose']!,
    identityId: c['identity_id']!,
    mskFingerprint: c['msk_fingerprint']!,
    exp: DateTime.fromMillisecondsSinceEpoch(exp, isUtc: true),
    jti: c['jti']!,
  );
}
