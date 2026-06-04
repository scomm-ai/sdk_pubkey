/// Client-side session after OTP verify or signed-key identity.
class PubkeySession {
  const PubkeySession({
    required this.email,
    this.fetchToken,
    this.fetchTokenExpiresIn,
    this.signingKeyId,
    this.sigFamily,
  });

  final String email;
  final String? fetchToken;
  final int? fetchTokenExpiresIn;

  /// Active signing key id from the server (stringified BIGINT).
  final String? signingKeyId;

  /// `openpgp` or `smime` for signed HTTP requests.
  final String? sigFamily;

  bool get hasFetchToken => fetchToken != null && fetchToken!.isNotEmpty;

  PubkeySession copyWith({
    String? email,
    String? fetchToken,
    int? fetchTokenExpiresIn,
    String? signingKeyId,
    String? sigFamily,
  }) {
    return PubkeySession(
      email: email ?? this.email,
      fetchToken: fetchToken ?? this.fetchToken,
      fetchTokenExpiresIn: fetchTokenExpiresIn ?? this.fetchTokenExpiresIn,
      signingKeyId: signingKeyId ?? this.signingKeyId,
      sigFamily: sigFamily ?? this.sigFamily,
    );
  }
}
