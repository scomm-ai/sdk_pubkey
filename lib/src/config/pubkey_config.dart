/// Compile-time pubkey server hosts (read vs write deploy split).
abstract final class PubkeyConfig {
  /// Read tier — GET discovery, list keys, VKS (`npm run start:read`).
  static const readBaseUrl = String.fromEnvironment(
    'PUBKEY_READ_BASE_URL',
    defaultValue: 'https://pubkey.scomm.ai',
  );

  /// Write tier — mutations, OTP (`npm run start:write`).
  static const writeBaseUrl = String.fromEnvironment(
    'PUBKEY_WRITE_BASE_URL',
    defaultValue: 'https://api.pubkey.scomm.ai',
  );
}
