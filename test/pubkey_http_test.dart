import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:secmail_pubkey_sdk/src/http/pubkey_http.dart';

void main() {
  test('mapDioError parses server error body', () {
    final err = DioException(
      requestOptions: RequestOptions(path: '/keys'),
      response: Response(
        requestOptions: RequestOptions(path: '/keys'),
        statusCode: 401,
        data: {'error': 'missing_auth_headers', 'message': 'Required'},
      ),
    );
    final ex = mapDioError(err);
    expect(ex.statusCode, 401);
    expect(ex.code, 'missing_auth_headers');
    expect(ex.message, 'Required');
  });
}
