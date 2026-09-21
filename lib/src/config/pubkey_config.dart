/// Compile-time pubkey server hosts (read vs write deploy split).
///
/// Missing dart-defines resolve to empty strings. Callers must [requireUrl]
/// rather than substituting a live host.
abstract final class PubkeyConfig {
  /// Read tier — GET discovery and key selection.
  static const readBaseUrl = String.fromEnvironment('PUBKEY_READ_BASE_URL');

  /// Write tier — MSK enroll/replace and signed mutations.
  static const writeBaseUrl = String.fromEnvironment('PUBKEY_WRITE_BASE_URL');

  /// Returns [value] when it is a non-empty origin; otherwise throws.
  ///
  /// Empty / omitted config must not fall back to a default host.
  static String requireUrl(String name, String? value) {
    final resolved = (value ?? '').trim();
    if (resolved.isEmpty) {
      throw StateError(
        '$name is required and must not be empty',
      );
    }
    return resolved;
  }
}
