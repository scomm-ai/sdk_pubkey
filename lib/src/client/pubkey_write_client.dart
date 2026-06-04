import 'dart:convert';

import 'package:dio/dio.dart';
import '../auth/pubkey_session.dart';
import '../exceptions/pubkey_api_exception.dart';
import '../http/pubkey_http.dart';

/// Mutation client for the write deploy (`api.pubkey.scomm.ai`).
class PubkeyWriteClient {
  PubkeyWriteClient({Dio? dio}) : _dio = dio ?? createWriteDio();

  final Dio _dio;

  Future<Map<String, dynamic>> health() => _getJson('/health');

  Future<Map<String, dynamic>> sendOtp(String email) async {
    return _postJson('/auth/bootstrap', body: {'email': email});
  }

  Future<PubkeySession> verifyOtp({
    required String email,
    required String otp,
  }) async {
    final data = await _postJson(
      '/auth/bootstrap/verify',
      body: {'email': email, 'otp': otp},
    );
    return PubkeySession(
      email: email.trim().toLowerCase(),
      fetchToken: data['fetchToken'] as String?,
      fetchTokenExpiresIn: data['expiresIn'] as int?,
    );
  }

  /// Registers a key using a FetchToken from [verifyOtp].
  Future<Map<String, dynamic>> uploadKeyWithFetchToken({
    required PubkeySession session,
    required String payloadJson,
    String? signatureBase64,
    String? proofType,
    String? challengeResponse,
  }) async {
    if (!session.hasFetchToken) {
      throw ArgumentError('session.fetchToken is required');
    }

    final body = <String, dynamic>{
      'payload': payloadJson,
      if (signatureBase64 != null) 'signature': signatureBase64,
      if (proofType != null) 'proofType': proofType,
      if (challengeResponse != null) 'challengeResponse': challengeResponse,
    };

    return _postJson(
      '/keys',
      body: body,
      extraHeaders: {
        'Authorization': 'FetchToken ${session.fetchToken}',
      },
    );
  }

  Future<Map<String, dynamic>> _postJson(
    String path, {
    required Map<String, dynamic> body,
    Map<String, String>? extraHeaders,
  }) async {
    try {
      final response = await _dio.post<Map<String, dynamic>>(
        path,
        data: body,
        options: Options(headers: extraHeaders),
      );
      _throwIfError(response);
      return response.data ?? {};
    } on DioException catch (e) {
      throw mapDioError(e);
    }
  }

  Future<Map<String, dynamic>> _getJson(String path) async {
    try {
      final response = await _dio.get<Map<String, dynamic>>(path);
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

/// Canonical JSON encoding for request bodies (stable key order not guaranteed;
/// use consistent map construction for signed bodyHash).
String canonicalJsonBody(Map<String, dynamic> body) {
  return jsonEncode(body);
}
