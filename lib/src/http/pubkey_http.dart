import 'package:dio/dio.dart';

import '../config/pubkey_config.dart';
import '../exceptions/pubkey_api_exception.dart';

/// Shared dio error mapping for read and write clients.
PubkeyApiException mapDioError(DioException e) {
  final status = e.response?.statusCode ?? 0;
  final data = e.response?.data;
  if (data is Map) {
    return PubkeyApiException(
      statusCode: status,
      code: data['error']?.toString() ?? 'request_failed',
      message: data['message']?.toString() ?? e.message ?? 'Request failed',
    );
  }
  return PubkeyApiException(
    statusCode: status,
    code: 'request_failed',
    message: e.message ?? 'Request failed',
  );
}

Dio createPubkeyDio(String baseUrl) {
  final dio = Dio(
    BaseOptions(
      baseUrl: baseUrl,
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Content-Type': 'application/json'},
      validateStatus: (status) => status != null && status < 500,
    ),
  );

  dio.interceptors.add(
    InterceptorsWrapper(
      onError: (error, handler) async {
        final options = error.requestOptions;
        final retryCount = options.extra['pubkeyRetryCount'] as int? ?? 0;
        final shouldRetry = retryCount < 1 &&
            (error.type == DioExceptionType.connectionTimeout ||
                error.type == DioExceptionType.receiveTimeout ||
                error.type == DioExceptionType.connectionError ||
                error.response?.statusCode == 429);
        if (!shouldRetry) {
          return handler.next(error);
        }
        options.extra['pubkeyRetryCount'] = retryCount + 1;
        await Future<void>.delayed(const Duration(milliseconds: 500));
        try {
          final response = await dio.fetch<dynamic>(options);
          return handler.resolve(response);
        } catch (e) {
          return handler.next(error);
        }
      },
    ),
  );

  return dio;
}

Dio createReadDio() => createPubkeyDio(PubkeyConfig.readBaseUrl);

Dio createWriteDio() => createPubkeyDio(PubkeyConfig.writeBaseUrl);
