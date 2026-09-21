import 'dart:developer' as developer;

import 'package:dio/dio.dart';

import '../errors.dart';

const _connectionAttempts = 4;
const _connectionRetryDelay = Duration(milliseconds: 400);
const _unreachableMessage = 'The pubkey server could not be reached.';
const _httpsFailedMessage =
    'The pubkey server was reached but HTTPS could not be established.';
const _timeoutMessage = 'The pubkey server did not respond in time.';

/// Synthetic body returned when a signed write is retried after an uncertain
/// delivery and the server rejects the replay of the same nonce. The first
/// attempt almost certainly already applied; callers must not require
/// response-specific fields (e.g. a freshly minted `key_id`) from this body.
const Map<String, dynamic> reconciledFromReplayResponse = {
  'ok': true,
  'reconciled_from_replay': true,
};

String joinUrl(String base, String path) {
  return '${base.replaceAll(RegExp(r'/+$'), '')}$path';
}

bool isPubkeyTlsError(DioException error) {
  if (error.response != null) return false;
  if (error.type == DioExceptionType.badCertificate) return true;
  final text =
      '${error.type} ${error.message} ${error.error} ${error.error.runtimeType}'
          .toLowerCase();
  return text.contains('handshake') ||
      text.contains('certificate') ||
      text.contains('badcertificate') ||
      text.contains('certificate_verify_failed') ||
      text.contains('tls') ||
      text.contains('ssl');
}

bool isPubkeyTimeoutError(DioException error) {
  if (error.response != null) return false;
  return error.type == DioExceptionType.connectionTimeout ||
      error.type == DioExceptionType.receiveTimeout ||
      error.type == DioExceptionType.sendTimeout;
}

bool isPubkeyUnreachableError(DioException error) {
  if (error.response != null || isPubkeyTlsError(error)) return false;
  if (isPubkeyTimeoutError(error)) return false;
  if (error.type == DioExceptionType.connectionError) return true;
  final text = '${error.message} ${error.error}'.toLowerCase();
  return text.contains('connection failed') ||
      text.contains('connection refused') ||
      text.contains('connection reset') ||
      text.contains('socketexception') ||
      text.contains('failed host lookup');
}

/// Connection, timeout, or TLS — anything with no HTTP response.
bool isPubkeyConnectionError(DioException error) {
  return isPubkeyTlsError(error) ||
      isPubkeyTimeoutError(error) ||
      isPubkeyUnreachableError(error);
}

/// Shared HTTP helper for pubkey read/write URLs.
///
/// When [reconcileReplayAfterConnectionFailure] is true (MSK-signed writes),
/// a `nonce_replayed` / `replay_rejection` that arrives only after at least
/// one connection/timeout failure in this call is treated as success: the
/// server already accepted this exact signed envelope, and the client lost
/// the original response. Without this, transport retries of the same body
/// surface as user-visible failures even though the mutation applied.
Future<dynamic> pubkeyRequest(
  Dio dio,
  String url, {
  String method = 'GET',
  Object? body,
  bool reconcileReplayAfterConnectionFailure = false,
}) async {
  Object? lastError;
  var hadConnectionFailure = false;
  for (var attempt = 1; attempt <= _connectionAttempts; attempt++) {
    try {
      final response = await dio.request<dynamic>(
        url,
        data: body,
        options: Options(
          method: method,
          headers: {
            'Accept': 'application/json',
            if (body != null) 'Content-Type': 'application/json',
          },
        ),
      );
      return response.data;
    } on DioException catch (error) {
      lastError = error;
      if (isPubkeyTlsError(error)) {
        throw PubkeyException(
          ErrorCodes.httpsCouldNotBeEstablished,
          _httpsFailedMessage,
          status: 0,
        );
      }
      if (isPubkeyUnreachableError(error) || isPubkeyTimeoutError(error)) {
        hadConnectionFailure = true;
        if (attempt == _connectionAttempts) {
          break;
        }
        await Future<void>.delayed(_connectionRetryDelay);
        continue;
      }
      final parsed = PubkeyException.fromResponse(
        error.response?.statusCode ?? 0,
        error.response?.data ?? {'message': error.message},
      );
      if (reconcileReplayAfterConnectionFailure &&
          hadConnectionFailure &&
          parsed.isReplayRejection) {
        return Map<String, dynamic>.from(reconciledFromReplayResponse);
      }
      throw parsed;
    }
  }

  final error = lastError;
  if (error is DioException) {
    if (isPubkeyTlsError(error)) {
      throw PubkeyException(
        ErrorCodes.httpsCouldNotBeEstablished,
        _httpsFailedMessage,
        status: 0,
      );
    }
    if (isPubkeyTimeoutError(error)) {
      throw PubkeyException(
        ErrorCodes.requestTimeout,
        _timeoutMessage,
        status: 0,
      );
    }
    if (isPubkeyUnreachableError(error)) {
      throw PubkeyException(
        ErrorCodes.pubkeyUnreachable,
        _unreachableMessage,
        status: 0,
      );
    }
    throw PubkeyException.fromResponse(
      error.response?.statusCode ?? 0,
      error.response?.data ?? {'message': error.message},
    );
  }
  throw PubkeyException(
    ErrorCodes.pubkeyUnreachable,
    _unreachableMessage,
    status: 0,
  );
}

Dio createPubkeyDio() {
  final dio = Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Accept': 'application/json'},
    ),
  );
  dio.interceptors.add(_PubkeyHttpTraceInterceptor());
  return dio;
}

class _PubkeyHttpTraceInterceptor extends Interceptor {
  static const _tag = 'Crypto/PubkeyHttp';

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    final host = options.uri.host;
    final live = host.contains('scomm.ai');
    developer.log(
      'pubkey_http_request ${options.method} ${options.uri} liveHost=$live',
      name: _tag,
    );
    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    developer.log(
      'pubkey_http_response ${response.requestOptions.method} '
      '${response.requestOptions.uri} status=${response.statusCode}',
      name: _tag,
    );
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    developer.log(
      'pubkey_http_error ${err.requestOptions.method} '
      '${err.requestOptions.uri} type=${err.type} '
      'status=${err.response?.statusCode} message=${err.message}',
      name: _tag,
    );
    handler.next(err);
  }
}
