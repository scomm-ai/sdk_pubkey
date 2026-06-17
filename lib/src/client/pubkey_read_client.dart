import 'package:dio/dio.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import '../exceptions/pubkey_api_exception.dart';
import '../http/pubkey_http.dart';
import '../http/signed_request_executor.dart';
import '../models/account_check.dart';
import '../models/key_list_item.dart';
import '../models/preference_batch_entry.dart';
import '../auth/pubkey_session.dart';
import '../auth/signed_request_builder.dart';

/// GET-only client for the read deploy (`pubkey.scomm.ai`).
class PubkeyReadClient {
  PubkeyReadClient({
    Dio? dio,
    SignedRequestBuilder? signedRequestBuilder,
  })  : _dio = dio ?? createReadDio(),
        _signed = SignedRequestExecutor(
          dio: dio ?? createReadDio(),
          builder: signedRequestBuilder ??
              SignedRequestBuilder(
                payloadSigner: PubkeyPayloadSigner(CryptoSdk.initialize()),
              ),
        );

  final Dio _dio;
  final SignedRequestExecutor _signed;

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

  Future<List<PreferenceBatchEntry>> getPreferenceBatch({
    required List<String> emails,
  }) async {
    if (emails.isEmpty || emails.length > 50) {
      throw ArgumentError('Between 1 and 50 emails required');
    }
    final data = await _getJson(
      '/keys/preference',
      queryParameters: {'emails': emails.join(',')},
    );
    final list = data['results'] as List<dynamic>? ?? [];
    return list
        .map(
          (e) => PreferenceBatchEntry.fromJson(
            Map<String, dynamic>.from(e as Map),
          ),
        )
        .toList();
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

  Future<Map<String, dynamic>> getBlob({
    required PubkeySession session,
    required String keyId,
    CryptoKey? signingPrivateKey,
    String? passphrase,
  }) async {
    final path = '/keys/blob/$keyId';
    if (session.hasFetchToken) {
      return _getJson(
        path,
        extraHeaders: {
          'Authorization': 'FetchToken ${session.fetchToken}',
        },
      );
    }
    if (signingPrivateKey == null) {
      throw ArgumentError(
        'signingPrivateKey required when session has no fetchToken',
      );
    }
    return _signed.requestJson(
      session: session,
      method: 'GET',
      path: path,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<List<KeyListItem>> listRecoverableKeys({
    required PubkeySession session,
  }) async {
    if (!session.hasFetchToken) {
      throw ArgumentError('session.fetchToken is required');
    }
    final data = await _getJson(
      '/auth/bootstrap/recoverable',
      extraHeaders: {
        'Authorization': 'FetchToken ${session.fetchToken}',
      },
    );
    final keys = data['keys'] as List<dynamic>? ?? [];
    return keys
        .map((e) => KeyListItem.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<Map<String, dynamic>> _getJson(
    String path, {
    Map<String, dynamic>? queryParameters,
    Map<String, String>? extraHeaders,
  }) async {
    try {
      final response = await _dio.get<Map<String, dynamic>>(
        path,
        queryParameters: queryParameters,
        options: Options(headers: extraHeaders),
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
