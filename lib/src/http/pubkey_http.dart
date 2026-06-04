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
  return Dio(
    BaseOptions(
      baseUrl: baseUrl,
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Content-Type': 'application/json'},
      validateStatus: (status) => status != null && status < 500,
    ),
  );
}

Dio createReadDio() => createPubkeyDio(PubkeyConfig.readBaseUrl);

Dio createWriteDio() => createPubkeyDio(PubkeyConfig.writeBaseUrl);
