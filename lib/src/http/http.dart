import 'package:dio/dio.dart';

import '../errors.dart';

const _connectionAttempts = 4;
const _connectionRetryDelay = Duration(milliseconds: 400);
const _unreachableMessage =
    'Cannot reach the pubkey server. Check that it is running.';

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

bool isPubkeyConnectionError(DioException error) {
  if (error.response != null) return false;
  if (error.type == DioExceptionType.connectionError ||
      error.type == DioExceptionType.connectionTimeout ||
      error.type == DioExceptionType.receiveTimeout ||
      error.type == DioExceptionType.sendTimeout) {
    return true;
  }
  final text = '${error.message} ${error.error}'.toLowerCase();
  return text.contains('connection failed') ||
      text.contains('connection refused') ||
      text.contains('connection reset') ||
      text.contains('socketexception') ||
      text.contains('failed host lookup');
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
      if (isPubkeyConnectionError(error)) {
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
    if (isPubkeyConnectionError(error)) {
      throw PubkeyException(
        ErrorCodes.providerUnavailable,
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
    ErrorCodes.providerUnavailable,
    _unreachableMessage,
    status: 0,
  );
}

Dio createPubkeyDio() {
  return Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Accept': 'application/json'},
    ),
  );
}
