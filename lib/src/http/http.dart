import 'dart:async';
import 'dart:developer' as developer;
import 'dart:math';

import 'package:dio/dio.dart';

import '../errors.dart';
import 'trace.dart';

const _connectionAttempts = 4;
const _connectionRetryDelay = Duration(milliseconds: 400);
const _unreachableMessage = 'The Discovery Server could not be reached.';
const _httpsFailedMessage =
    'The Discovery Server was reached but HTTPS could not be established.';
const _timeoutMessage = 'The Discovery Server did not respond in time.';

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

/// Adds `Idempotency-Key` when the caller did not already set one.
///
/// The same map is reused across transport retries of one call, so a retry
/// repeats the key instead of minting a second one.
Map<String, String> withIdempotencyKey(Map<String, String>? headers) {
  final out = <String, String>{...?headers};
  final alreadySet = out.keys.any(
    (name) => name.toLowerCase() == 'idempotency-key',
  );
  if (!alreadySet) {
    out['Idempotency-Key'] = newIdempotencyKey();
  }
  return out;
}

String newIdempotencyKey() {
  final random = Random.secure();
  final bytes = List<int>.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
      '${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// Shared HTTP helper for pubkey read/write URLs.
///
/// When [reconcileReplayAfterConnectionFailure] is true (MSK-signed writes),
/// a `nonce_replayed` / `replay_rejection` that arrives only after at least
/// one connection/timeout failure in this call is treated as success: the
/// server already accepted this exact signed envelope, and the client lost
/// the original response. Without this, transport retries of the same body
/// surface as user-visible failures even though the mutation applied.
///
/// Sends `Idempotency-Key` unless [headers] already includes one.
Future<dynamic> pubkeyRequest(
  Dio dio,
  String url, {
  String method = 'GET',
  Object? body,
  Map<String, String>? headers,
  bool reconcileReplayAfterConnectionFailure = false,
}) async {
  final requestHeaders = withIdempotencyKey(headers);
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
            ...requestHeaders,
          },
        ),
      );
      _captureExchange(
        method: response.requestOptions.method,
        url: response.requestOptions.uri.toString(),
        requestHeaders: Map<dynamic, dynamic>.from(
          response.requestOptions.headers,
        ),
        requestBody: response.requestOptions.data,
        statusCode: response.statusCode,
        responseHeaders: Map<dynamic, dynamic>.from(response.headers.map),
        responseBody: response.data,
      );
      return response.data;
    } on DioException catch (error) {
      lastError = error;
      if (isPubkeyTlsError(error)) {
        _captureFromDio(error);
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
      _captureFromDio(error);
      final parsed = PubkeyException.fromResponse(
        error.response?.statusCode ?? 0,
        error.response?.data ?? {'message': error.message},
        http: _exchangeFromDio(error),
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
    _captureFromDio(error);
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
      http: _exchangeFromDio(error),
    );
  }
  throw PubkeyException(
    ErrorCodes.pubkeyUnreachable,
    _unreachableMessage,
    status: 0,
  );
}

void _captureFromDio(DioException error) {
  final exchange = _exchangeFromDio(error);
  if (exchange == null) return;
  _recordExchange(exchange);
}

PubkeyHttpExchange? _exchangeFromDio(DioException error) {
  final response = error.response;
  return PubkeyHttpExchange(
    method: error.requestOptions.method,
    url: error.requestOptions.uri.toString(),
    requestHeaders: normalizeHeaderMap(
      Map<dynamic, dynamic>.from(error.requestOptions.headers),
    ),
    requestBody: error.requestOptions.data,
    statusCode: response?.statusCode,
    responseHeaders: response == null
        ? const {}
        : normalizeHeaderMap(Map<dynamic, dynamic>.from(response.headers.map)),
    responseBody: response?.data,
    errorMessage: response == null ? error.message : null,
  );
}

void _captureExchange({
  required String method,
  required String url,
  required Map<dynamic, dynamic> requestHeaders,
  Object? requestBody,
  int? statusCode,
  Map<dynamic, dynamic> responseHeaders = const {},
  Object? responseBody,
  String? errorMessage,
}) {
  _recordExchange(
    PubkeyHttpExchange(
      method: method,
      url: url,
      requestHeaders: normalizeHeaderMap(requestHeaders),
      requestBody: requestBody,
      statusCode: statusCode,
      responseHeaders: normalizeHeaderMap(responseHeaders),
      responseBody: responseBody,
      errorMessage: errorMessage,
    ),
  );
}

void _recordExchange(PubkeyHttpExchange exchange) {
  final slot = Zone.current[pubkeyHttpTraceZoneKey];
  if (slot is List<PubkeyHttpExchange>) {
    slot.add(exchange);
  }
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
