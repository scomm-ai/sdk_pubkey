import 'dart:convert';
import 'dart:io';

import 'package:secmail_pubkey_sdk/src/client/grant_v1.dart';
import 'package:test/test.dart';

void main() {
  final doc = jsonDecode(
    File('conformance/fixtures/grant-vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  for (final raw in doc['valid'] as List) {
    final vector = raw as Map<String, dynamic>;
    final claims = vector['claims'] as Map<String, dynamic>;
    test('parses shared vector: ${vector['name']}', () {
      final parsed = parseGrantV1(vector['token'] as String);
      expect(parsed, isNotNull);
      expect(parsed!.iss, claims['iss']);
      expect(parsed.aud.join(' '), claims['aud']);
      expect(parsed.kid, claims['kid']);
      expect(parsed.purpose, claims['purpose']);
      expect(parsed.identityId, claims['identity_id']);
      expect(parsed.mskFingerprint, claims['msk_fingerprint']);
      expect(parsed.amr, claims['amr']);
      expect(parsed.idp, claims['idp']);
      expect(parsed.exp.millisecondsSinceEpoch,
          int.parse(claims['exp'] as String));
      expect(parsed.jti, claims['jti']);
      expect(
        parsed.isExpired(
          DateTime.fromMillisecondsSinceEpoch(doc['now_ms'] as int,
              isUtc: true),
        ),
        isFalse,
      );
    });
  }

  test('rejects a reordered grant', () {
    final format = (doc['invalid'] as List)
        .cast<Map<String, dynamic>>()
        .firstWhere((v) => v['reason'] == 'format');
    expect(parseGrantV1(format['token'] as String), isNull);
  });

  test('treats opaque directory grants as non-v1', () {
    expect(parseGrantV1('AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde'), isNull);
  });
}
