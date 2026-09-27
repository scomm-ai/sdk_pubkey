import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  final identity = 'ab' * 32;

  MailerClient clientWith(Map<String, dynamic> Function(RequestOptions) reply) {
    final dio = Dio();
    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          handler.resolve(
            Response<dynamic>(
              requestOptions: options,
              statusCode: 200,
              data: reply(options),
              headers: Headers.fromMap({
                'cache-control': ['max-age=120'],
              }),
            ),
          );
        },
      ),
    );
    return MailerClient(baseUrl: 'http://mailer.test', dio: dio);
  }

  test('config is cached for max-age', () async {
    var hits = 0;
    final client = clientWith((_) {
      hits += 1;
      return {
        'enabled': true,
        'providers': {
          'google': {
            'purposes': ['enroll'],
          },
        },
        'challenge_ttl_seconds': 300,
      };
    });
    final first = await client.fetchIdTokenConfig();
    final second = await client.fetchIdTokenConfig();
    expect(hits, 1);
    expect(first.enabled, isTrue);
    expect(second.supports(MailerIdTokenProvider.google, MailerOtpPurpose.enroll),
        isTrue);
    expect(
      second.supports(MailerIdTokenProvider.microsoft, MailerOtpPurpose.enroll),
      isFalse,
    );
  });

  test('challenge sends msk_jkt and verify parses the grant', () async {
    final publicKey = Uint8List(32)..[0] = 7;
    final expectedJkt = mailerMskJkt(publicKey);
    Map<String, dynamic>? challengeBody;
    final client = clientWith((options) {
      if (options.path.endsWith('/v1/idtoken/challenge')) {
        challengeBody = Map<String, dynamic>.from(options.data as Map);
        return {
          'challenge_id': 'chal',
          'nonce': 'nonce-value',
          'expires_in': 300,
        };
      }
      return {
        'identity_id': identity,
        'otp_grant': 'grant-token',
      };
    });
    final challenge = await client.createIdTokenChallenge(
      email: 'User@gmail.com',
      provider: MailerIdTokenProvider.google,
      purpose: MailerOtpPurpose.enroll,
      mskPublicKey: publicKey,
    );
    expect(challenge.challengeId, 'chal');
    expect(challenge.nonce, 'nonce-value');
    expect(challengeBody?['email'], 'user@gmail.com');
    expect(challengeBody?['msk_jkt'], expectedJkt);
    expect(expectedJkt, isNot(contains('=')));

    final grant = await client.verifyIdToken(
      challengeId: challenge.challengeId,
      provider: MailerIdTokenProvider.google,
      purpose: MailerOtpPurpose.enroll,
      idToken: 'header.payload.sig',
    );
    expect(grant.requireIdentityId, identity);
    expect(grant.otpGrant, 'grant-token');
    expect(grant, isA<MailerGrant>());
  });

  test('verify rejects a response that contains an email', () async {
    final client = clientWith((_) => {
          'identity_id': identity,
          'otp_grant': 'grant-token',
          'email': 'user@gmail.com',
        });
    expect(
      () => client.verifyIdToken(
        challengeId: 'chal',
        provider: MailerIdTokenProvider.google,
        purpose: MailerOtpPurpose.enroll,
        idToken: 'header.payload.sig',
      ),
      throwsA(
        isA<PubkeyException>().having(
          (error) => error.code,
          'code',
          ErrorCodes.invalidRequest,
        ),
      ),
    );
  });

  test('maps idtoken_email_mismatch from the mailer', () async {
    final dio = Dio();
    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          handler.reject(
            DioException(
              requestOptions: options,
              type: DioExceptionType.badResponse,
              response: Response<dynamic>(
                requestOptions: options,
                statusCode: 403,
                data: {
                  'code': ErrorCodes.idTokenEmailMismatch,
                  'message': 'Identity token does not match the requested mailbox',
                },
              ),
            ),
          );
        },
      ),
    );
    final client = MailerClient(baseUrl: 'http://mailer.test', dio: dio);
    expect(
      () => client.verifyIdToken(
        challengeId: 'chal',
        provider: MailerIdTokenProvider.google,
        purpose: MailerOtpPurpose.enroll,
        idToken: 'header.payload.sig',
      ),
      throwsA(
        isA<PubkeyException>().having(
          (error) => error.code,
          'code',
          ErrorCodes.idTokenEmailMismatch,
        ),
      ),
    );
  });

  test('error codes are listed for user-facing mapping', () {
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenNotSupported));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenChallengeInvalid));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenInvalid));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenReplayed));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenEmailUnverified));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenEmailMismatch));
    expect(ErrorCodes.all, contains(ErrorCodes.idTokenSubjectMismatch));
  });
}
