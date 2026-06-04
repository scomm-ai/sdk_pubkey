import 'package:dio/dio.dart';

import '../exceptions/pubkey_api_exception.dart';
import '../http/pubkey_http.dart';
import '../models/account_check.dart';
import '../models/key_list_item.dart';
import '../auth/pubkey_session.dart';
import '../auth/signed_request_builder.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

/// GET-only client for the read deploy (`pubkey.scomm.ai`).
class PubkeyReadClient {
  PubkeyReadClient({Dio? dio}) : _dio = dio ?? createReadDio();

  final Dio _dio;

  Future<Map<String, dynamic>> health() => _getJson('/health');

  Future<AccountCheckResult> checkAccount(String email) async {
    final data = await _getJson(
      '/auth/check',
      queryParameters: {'email': email},
    );
    return AccountCheckResult.fromJson(data);
  }

  Future<Map<String, dynamic>> getPreference({
    required String email,
    String? usage,
  }) async {
    return _getJson(
      '/keys/preference',
      queryParameters: {
        'email': email,
        if (usage != null) 'usage': usage,
      },
    );
  }

  Future<Map<String, dynamic>> getRevoked({
    String? since,
    int? limit,
  }) async {
    return _getJson(
      '/keys/revoked',
      queryParameters: {
        if (since != null) 'since': since,
        if (limit != null) 'limit': limit,
      },
    );
  }

  Future<Response<dynamic>> vksByEmail(
    String email, {
    String? algorithm,
  }) {
    return _dio.get<dynamic>(
      '/vks/v1/by-email/$email',
      queryParameters: algorithm != null ? {'algorithm': algorithm} : null,
    );
  }

  Future<List<KeyListItem>> listKeys({
    required PubkeySession session,
    required CryptoKey signingPrivateKey,
    required SignedRequestBuilder signedRequestBuilder,
    String? passphrase,
  }) async {
    const path = '/keys';
    const jsonBody = '';
    final headers = await signedRequestBuilder.buildHeaders(
      session: session,
      method: 'GET',
      path: path,
      jsonBody: jsonBody,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );

    final response = await _dio.get<Map<String, dynamic>>(
      path,
      options: Options(headers: headers),
    );
    _throwIfError(response);
    final keys = response.data?['keys'] as List<dynamic>? ?? [];
    return keys
        .map((e) => KeyListItem.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<Map<String, dynamic>> _getJson(
    String path, {
    Map<String, dynamic>? queryParameters,
  }) async {
    try {
      final response = await _dio.get<Map<String, dynamic>>(
        path,
        queryParameters: queryParameters,
      );
      _throwIfError(response);
      return response.data ?? {};
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
