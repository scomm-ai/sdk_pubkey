import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import '../auth/pubkey_session.dart';
import '../auth/signed_request_builder.dart';
import '../exceptions/pubkey_api_exception.dart';
import '../http/pubkey_http.dart';
import '../http/signed_request_executor.dart';

/// Mutation client for the write deploy (`api.pubkey.scomm.ai`).
class PubkeyWriteClient {
  PubkeyWriteClient({
    Dio? dio,
    SignedRequestBuilder? signedRequestBuilder,
  })  : _dio = dio ?? createWriteDio(),
        _signed = SignedRequestExecutor(
          dio: dio ?? createWriteDio(),
          builder: signedRequestBuilder ??
              SignedRequestBuilder(
                payloadSigner: PubkeyPayloadSigner(CryptoSdk.initialize()),
              ),
        );

  final Dio _dio;
  final SignedRequestExecutor _signed;

  SignedRequestExecutor get signedExecutor => _signed;

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

  /// Registers or replaces a key using signed HTTP auth (existing device).
  Future<Map<String, dynamic>> uploadKeySigned({
    required PubkeySession session,
    required String payloadJson,
    required String signatureBase64,
    String? proofType,
    String? challengeResponse,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    final body = <String, dynamic>{
      'payload': payloadJson,
      if (signatureBase64.isNotEmpty) 'signature': signatureBase64,
      if (proofType != null) 'proofType': proofType,
      if (challengeResponse != null) 'challengeResponse': challengeResponse,
    };
    return _signed.requestJson(
      session: session,
      method: 'POST',
      path: '/keys',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  /// Issues a decrypt-challenge before uploading encrypt-only keys.
  Future<Map<String, dynamic>> issueUploadChallenge({
    required PubkeySession session,
    required Map<String, dynamic> body,
    CryptoKey? signingPrivateKey,
    String? passphrase,
  }) async {
    final jsonBody = canonicalJsonBody(body);
    if (session.hasFetchToken) {
      return _postJson(
        '/keys/upload-challenge',
        body: body,
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
      method: 'POST',
      path: '/keys/upload-challenge',
      jsonBody: jsonBody,
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> rotateKey({
    required PubkeySession session,
    required String rotationPayloadJson,
    required String signatureBase64,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    final body = {
      'rotationPayload': rotationPayloadJson,
      'signature': signatureBase64,
    };
    return _signed.requestJson(
      session: session,
      method: 'POST',
      path: '/keys/rotate',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> updateStatus({
    required PubkeySession session,
    required String keyId,
    required String status,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    return _signed.requestJson(
      session: session,
      method: 'PATCH',
      path: '/keys/$keyId/status',
      jsonBody: canonicalJsonBody({'status': status}),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> updatePreference({
    required PubkeySession session,
    required String keyId,
    required Map<String, dynamic> body,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    return _signed.requestJson(
      session: session,
      method: 'PATCH',
      path: '/keys/$keyId/preference',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> updateBlob({
    required PubkeySession session,
    required String keyId,
    required Map<String, dynamic> newBlob,
    required String payloadJson,
    required String signatureBase64,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    final body = {
      'newBlob': newBlob,
      'payload': payloadJson,
      'signature': signatureBase64,
    };
    return _signed.requestJson(
      session: session,
      method: 'PUT',
      path: '/keys/$keyId/blob',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> confirmRecoveryPhrase({
    required PubkeySession session,
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    return _signed.requestJson(
      session: session,
      method: 'PATCH',
      path: '/keys/$keyId/recovery-phrase',
      jsonBody: canonicalJsonBody({'confirmed': true}),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> deleteKey({
    required PubkeySession session,
    required String keyId,
    required String payloadJson,
    required String signatureBase64,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    final body = {
      'payload': payloadJson,
      'signature': signatureBase64,
    };
    return _signed.requestJson(
      session: session,
      method: 'DELETE',
      path: '/keys/$keyId',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> recoverKey({
    required PubkeySession session,
    required String keyId,
    CryptoKey? signingPrivateKey,
    String? passphrase,
  }) async {
    final body = {'keyId': keyId};
    if (session.hasFetchToken) {
      return _postJson(
        '/keys/recover',
        body: body,
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
      method: 'POST',
      path: '/keys/recover',
      jsonBody: canonicalJsonBody(body),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
    );
  }

  Future<Map<String, dynamic>> cancelRevocation({
    required PubkeySession session,
    required String keyId,
    required CryptoKey signingPrivateKey,
    String? passphrase,
  }) {
    return _signed.requestJson(
      session: session,
      method: 'POST',
      path: '/auth/bootstrap/cancel-revocation',
      jsonBody: canonicalJsonBody({'keyId': keyId}),
      signingPrivateKey: signingPrivateKey,
      passphrase: passphrase,
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
