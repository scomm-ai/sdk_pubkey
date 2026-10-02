import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/src/errors.dart';
import 'package:secmail_pubkey_sdk/src/http/http.dart';
import 'package:secmail_pubkey_sdk/src/http/trace.dart';
import 'package:test/test.dart';

class _ScriptedAdapter implements HttpClientAdapter {
  _ScriptedAdapter(this.handler);

  final Future<ResponseBody> Function(RequestOptions options) handler;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) {
    return handler(options);
  }

  @override
  void close({bool force = false}) {}
}

ResponseBody _json(Object body, int status) {
  return ResponseBody.fromString(
    jsonEncode(body),
    status,
    headers: {
      Headers.contentTypeHeader: ['application/json'],
    },
  );
}

String? _idempotencyKey(RequestOptions options) {
  for (final entry in options.headers.entries) {
    if ('${entry.key}'.toLowerCase() == 'idempotency-key') {
      return '${entry.value}';
    }
  }
  return null;
}

void main() {
  test('adds Idempotency-Key and records a not-found exchange', () async {
    RequestOptions? seen;
    final dio = Dio();
    dio.httpClientAdapter = _ScriptedAdapter((options) async {
      seen = options;
      return _json(
        {
          'error': {
            'code': 'capability_mismatch',
            'message': 'No mutually supported key',
          },
        },
        404,
      );
    });

    final trace = <PubkeyHttpExchange>[];
    PubkeyException? error;
    await runZoned(() async {
      try {
        await pubkeyRequest(dio, 'https://pubkey.test/v1/keys?sha256=abc');
      } on PubkeyException catch (caught) {
        error = caught;
      }
    }, zoneValues: {pubkeyHttpTraceZoneKey: trace});

    final key = _idempotencyKey(seen!);
    expect(key, isNotNull);
    expect(
      key,
      matches(
        RegExp(
          r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        ),
      ),
    );
    expect(error?.code, 'capability_mismatch');
    expect(error?.http?.statusCode, 404);
    expect(trace, hasLength(1));
    final text = trace.single.describe();
    expect(text, contains('GET https://pubkey.test/v1/keys?sha256=abc'));
    expect(text, contains('Idempotency-Key: $key'));
    expect(text, contains('HTTP 404'));
    expect(text, contains('No mutually supported key'));
  });

  test('keeps a caller-supplied Idempotency-Key', () async {
    RequestOptions? seen;
    final dio = Dio();
    dio.httpClientAdapter = _ScriptedAdapter((options) async {
      seen = options;
      return _json({'ok': true}, 200);
    });

    await pubkeyRequest(
      dio,
      'https://pubkey.test/v1/mailboxes/abc/challenges',
      method: 'POST',
      body: {'type': 'email_otp'},
      headers: {'idempotency-key': 'already-set'},
    );

    expect(_idempotencyKey(seen!), 'already-set');
    expect(
      seen!.headers.keys
          .where((name) => '$name'.toLowerCase() == 'idempotency-key')
          .length,
      1,
    );
  });

  test('retries reuse the same Idempotency-Key', () async {
    final keys = <String?>[];
    var calls = 0;
    final dio = Dio();
    dio.httpClientAdapter = _ScriptedAdapter((options) async {
      keys.add(_idempotencyKey(options));
      calls++;
      if (calls < 2) {
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.connectionError,
          message: 'connection refused',
        );
      }
      return _json({'ok': true}, 200);
    });

    await pubkeyRequest(dio, 'https://pubkey.test/v1/keys?sha256=abc');
    expect(keys, hasLength(2));
    expect(keys.first, isNotNull);
    expect(keys.last, keys.first);
  });
}
