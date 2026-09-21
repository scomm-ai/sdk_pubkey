import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/src/errors.dart';
import 'package:secmail_pubkey_sdk/src/http/http.dart';
import 'package:test/test.dart';

DioException _dio({
  required DioExceptionType type,
  Object? error,
  int? status,
}) {
  return DioException(
    requestOptions: RequestOptions(path: '/v1/keys/signing'),
    type: type,
    error: error,
    message: error?.toString(),
    response: status == null
        ? null
        : Response(
            requestOptions: RequestOptions(path: '/v1/keys/signing'),
            statusCode: status,
            data: {'message': 'nope'},
          ),
  );
}

void main() {
  test('TLS handshake is not a plain unreachable error', () {
    final err = _dio(
      type: DioExceptionType.unknown,
      error: 'HandshakeException: Connection terminated during handshake',
    );
    expect(isPubkeyTlsError(err), isTrue);
    expect(isPubkeyUnreachableError(err), isFalse);
  });

  test('connection refused is unreachable', () {
    final err = _dio(
      type: DioExceptionType.connectionError,
      error: 'SocketException: Connection refused',
    );
    expect(isPubkeyUnreachableError(err), isTrue);
    expect(isPubkeyTlsError(err), isFalse);
  });

  test('timeout is classified separately', () {
    final err = _dio(type: DioExceptionType.connectionTimeout);
    expect(isPubkeyTimeoutError(err), isTrue);
    expect(isPubkeyUnreachableError(err), isFalse);
  });

  test('HTTP 400 fromResponse keeps status', () {
    final parsed = PubkeyException.fromResponse(400, {
      'error': {'code': 'invalid_public_key', 'message': 'bad key'},
    });
    expect(parsed.status, 400);
    expect(parsed.code, 'invalid_public_key');
  });
}
