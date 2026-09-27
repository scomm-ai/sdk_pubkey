class VaultClientException implements Exception {
  VaultClientException(this.code, [this.message, this.status]);

  /// Host error code (`unknown_vault`, `rate_limited`, …) or a client code:
  /// `invalid_evaluation` when a proof fails, `network_error`, `bad_response`.
  final String code;
  final String? message;
  final int? status;

  @override
  String toString() =>
      'VaultClientException($code${status == null ? '' : ' $status'}'
      '${message == null ? '' : ': $message'})';
}
