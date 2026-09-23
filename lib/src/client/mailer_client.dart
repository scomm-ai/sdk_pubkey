import 'package:dio/dio.dart';

import '../errors.dart';
import '../http/http.dart';
import '../identity.dart';

/// Mailer OTP purposes. The mailer is the only host that may see a mailbox
/// address. Vault purposes return `identity_id` and `otp_grant`. Directory
/// enroll returns `otp_grant` only.
abstract final class MailerOtpPurpose {
  static const enroll = 'enroll';
  static const replaceMsk = 'replace_msk';
  static const recoveryEnvelope = 'recovery_envelope';
  static const recoveryGeneration = 'recovery_generation';
  static const vaultBackup = 'vault_backup';
}

class MailerOtpGrant {
  const MailerOtpGrant({this.identityId, required this.otpGrant});

  /// Present for vault-consumed purposes. Absent for directory enroll.
  final String? identityId;
  final String otpGrant;

  String get requireIdentityId {
    final id = identityId;
    if (id == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(id)) {
      throw PubkeyException(
        ErrorCodes.otpGrantInvalid,
        'Mailer verify did not return identity_id',
      );
    }
    return id;
  }
}

/// App-facing OTP mailer. Request bodies contain the canonical mailbox.
/// Responses never need to be forwarded to pubkey except `identity_id` and
/// `otp_grant`, which contain no address.
class MailerClient {
  MailerClient({
    required String baseUrl,
    Dio? dio,
  })  : baseUrl = baseUrl.trim(),
        dio = dio ?? Dio();

  final String baseUrl;
  final Dio dio;

  /// Always treats a uniform success as "a code was sent if this mailbox
  /// can be used." Does not distinguish unknown vs enrolled.
  Future<void> requestOtp({
    required String email,
    required String purpose,
  }) async {
    _requireBaseUrl();
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/otp/request'),
      method: 'POST',
      body: {
        'email': canonical,
        'purpose': purpose,
      },
    );
  }

  Future<MailerOtpGrant> verifyOtp({
    required String email,
    required String otp,
    required String purpose,
  }) async {
    _requireBaseUrl();
    final sha256 = emailSha256Hex(email);
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/otp/verify'),
      method: 'POST',
      body: {
        'sha256': sha256,
        'otp': otp.trim(),
        'purpose': purpose,
      },
    );
    if (result is! Map) {
      throw PubkeyException(
        ErrorCodes.otpInvalid,
        'Mailer verify response was not a JSON object',
      );
    }
    final identityId = result['identity_id'];
    final otpGrant = result['otp_grant'];
    final vaultPurpose = purpose != MailerOtpPurpose.enroll;
    if (otpGrant is! String || otpGrant.isEmpty) {
      throw PubkeyException(
        ErrorCodes.otpGrantInvalid,
        'Mailer verify did not return otp_grant',
      );
    }
    if (identityId != null &&
        (identityId is! String ||
            !RegExp(r'^[0-9a-f]{64}$').hasMatch(identityId))) {
      throw PubkeyException(
        ErrorCodes.otpGrantInvalid,
        'Mailer verify identity_id is not 64 hex characters',
      );
    }
    if (vaultPurpose && identityId is! String) {
      throw PubkeyException(
        ErrorCodes.otpGrantInvalid,
        'Mailer verify did not return identity_id and otp_grant',
      );
    }
    if (result.containsKey('email') || result.containsKey('mailbox')) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Mailer verify must not return a mailbox address',
      );
    }
    return MailerOtpGrant(
      identityId: identityId is String ? identityId : null,
      otpGrant: otpGrant,
    );
  }

  void _requireBaseUrl() {
    if (baseUrl.isEmpty) {
      throw StateError(
        'PUBKEY_MAILER_BASE_URL is required and must not be empty',
      );
    }
  }
}
