import 'package:dio/dio.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import '../auth/pubkey_session.dart';
import '../auth/signed_request_builder.dart';
import '../exceptions/pubkey_api_exception.dart';
import 'pubkey_http.dart';

/// Executes pubkey signed HTTP requests (X-Auth-Payload / X-Auth-Signature).
class SignedRequestExecutor {
  SignedRequestExecutor({
    required Dio dio,
    required SignedRequestBuilder builder,
  })  : _dio = dio,
        _builder = builder;

  final Dio _dio;
  final SignedRequestBuilder _builder;

  Future<Map<String, dynamic>> requestJson({
    required PubkeySession session,
    required String method,
    required String path,
    required CryptoKey signingPrivateKey,
    String jsonBody = '',
    Map<String, dynamic>? queryParameters,
    String? passphrase,
    Map<String, String>? extraHeaders,
  }) async {
    final response = await request<Map<String, dynamic>>(
      session: session,
      method: method,
      path: path,
      signingPrivateKey: signingPrivateKey,
      jsonBody: jsonBody,
      queryParameters: queryParameters,
      passphrase: passphrase,
      extraHeaders: extraHeaders,
    );
    _throwIfError(response);
    return response.data ?? {};
  }

  Future<Response<T>> request<T>({
    required PubkeySession session,
    required String method,
    required String path,
    required CryptoKey signingPrivateKey,
    String jsonBody = '',
    Map<String, dynamic>? queryParameters,
    String? passphrase,
    Map<String, String>? extraHeaders,
  }) async {
    final authHeaders = await _builder.buildHeaders(
      session: session,
      method: method,
      path: path,
      jsonBody: jsonBody,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );

    final headers = {...authHeaders, ...?extraHeaders};
    final upper = method.toUpperCase();

    try {
      switch (upper) {
        case 'GET':
          return await _dio.get<T>(
            path,
            queryParameters: queryParameters,
            options: Options(headers: headers),
          );
        case 'POST':
          return await _dio.post<T>(
            path,
            data: jsonBody.isEmpty ? null : jsonBody,
            queryParameters: queryParameters,
            options: Options(
              headers: headers,
              contentType: 'application/json',
            ),
          );
        case 'PATCH':
          return await _dio.patch<T>(
            path,
            data: jsonBody,
            queryParameters: queryParameters,
            options: Options(
              headers: headers,
              contentType: 'application/json',
            ),
          );
        case 'PUT':
          return await _dio.put<T>(
            path,
            data: jsonBody,
            queryParameters: queryParameters,
            options: Options(
              headers: headers,
              contentType: 'application/json',
            ),
          );
        case 'DELETE':
          return await _dio.delete<T>(
            path,
            data: jsonBody.isEmpty ? null : jsonBody,
            queryParameters: queryParameters,
            options: Options(
              headers: headers,
              contentType: 'application/json',
            ),
          );
        default:
          throw ArgumentError('Unsupported HTTP method: $method');
      }
    } on DioException catch (e) {
      throw mapDioError(e);
    }
  }

  void _throwIfError(Response<dynamic> response) {
    final status = response.statusCode ?? 0;
    if (status >= 200 && status < 300) return;
    final data = response.data;
    if (data is Map) {
      throw PubkeyApiException(
        statusCode: status,
        code: data['error']?.toString() ?? 'request_failed',
        message: data['message']?.toString() ?? 'Request failed',
      );
    }
    throw PubkeyApiException(
      statusCode: status,
      code: 'request_failed',
      message: 'Request failed',
    );
  }
}
