class VaultClientException implements Exception {
  VaultClientException(this.code, [this.message, this.status, this.details]);

  /// Host error code (`unknown_vault`, `rate_limited`, …) or a client code:
  /// `invalid_evaluation` when a proof fails, `network_error`, `bad_response`,
  /// `device_removed` when this device's slot left the stored vault.
  final String code;
  final String? message;
  final int? status;

  /// Host `error.details` (for `generation_conflict`: the stored heads).
  final Map<String, dynamic>? details;

  @override
  String toString() =>
      'VaultClientException($code${status == null ? '' : ' $status'}'
      '${message == null ? '' : ': $message'})';
}
