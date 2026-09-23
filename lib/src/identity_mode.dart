/// Email-blind pubkey identity (protocol v2).
///
/// Default is off so this client still speaks the current discovery server.
/// Set `--dart-define=PUBKEY_IDENTITY_V2=true` once the mailer and pubkey
/// dual-stack are live. Tests may assign [v2] directly.
abstract final class PubkeyIdentityMode {
  static bool v2 = const bool.fromEnvironment(
    'PUBKEY_IDENTITY_V2',
    defaultValue: false,
  );
}
