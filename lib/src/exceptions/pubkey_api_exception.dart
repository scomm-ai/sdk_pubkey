/// Error returned by the pubkey server as `{ "error": "...", "message": "..." }`.
class PubkeyApiException implements Exception {
  const PubkeyApiException({
    required this.statusCode,
    required this.code,
    required this.message,
  });

  final int statusCode;
  final String code;
  final String message;

  @override
  String toString() =>
      'PubkeyApiException($statusCode, $code): $message';
}
