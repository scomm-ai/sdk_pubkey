import 'dart:convert';

import 'package:crypto/crypto.dart';
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
  static const vaultOpen = 'vault_open';
  static const recoveryEnvelope = 'recovery_envelope';
  static const recoveryGeneration = 'recovery_generation';
  static const vaultBackup = 'vault_backup';
}

/// Same object the OTP and ID-token verify calls return.
typedef MailerGrant = MailerOtpGrant;

/// OIDC providers the mailer accepts as mailbox-ownership proof.
abstract final class MailerIdTokenProvider {
  static const google = 'google';
  static const microsoft = 'microsoft';
}

class MailerIdTokenChallenge {
  const MailerIdTokenChallenge({
    required this.challengeId,
    required this.nonce,
    required this.expiresIn,
  });

  final String challengeId;
  final String nonce;
  final int expiresIn;
}

class MailerIdTokenProviderConfig {
  const MailerIdTokenProviderConfig({required this.purposes});

  final List<String> purposes;
}

class MailerIdTokenConfig {
  const MailerIdTokenConfig({
    required this.enabled,
    required this.providers,
    required this.challengeTtlSeconds,
  });

  final bool enabled;
  final Map<String, MailerIdTokenProviderConfig> providers;
  final int challengeTtlSeconds;

  bool supports(String provider, String purpose) {
    final entry = providers[provider];
    if (!enabled || entry == null) return false;
    return entry.purposes.contains(purpose);
  }
}

/// `base64url(sha256(raw MSK public key))` without padding.
String mailerMskJkt(List<int> mskPublicKey) {
  final digest = sha256.convert(mskPublicKey).bytes;
  return base64Url.encode(digest).replaceAll('=', '');
}

class MailerOtpGrant {
  const MailerOtpGrant({
    this.identityId,
    required this.otpGrant,
    this.vaultGrant,
  });

  /// Present for vault-consumed purposes. Absent for directory enroll.
  final String? identityId;
  final String otpGrant;

  /// `replace_msk` only: signed vault grant for the rebind after the
  /// directory arms the new MSK. Null when the vault identity was unavailable.
  final String? vaultGrant;

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

  MailerIdTokenConfig? _idTokenConfig;
  DateTime? _idTokenConfigUntil;

  /// Always treats a uniform success as "a code was sent if this mailbox
  /// can be used." Does not distinguish unknown vs enrolled.
  ///
  /// [mskPublicKey] is required for `enroll` and `replace_msk`: the grant
  /// names that key (`msk_jkt`) and can arm no other.
  Future<void> requestOtp({
    required String email,
    required String purpose,
    List<int>? mskPublicKey,
  }) async {
    _requireBaseUrl();
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    _requireArmingKey(purpose, mskPublicKey);
    await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/otp/request'),
      method: 'POST',
      body: {
        'email': canonical,
        'purpose': purpose,
        if (mskPublicKey != null) 'msk_jkt': mailerMskJkt(mskPublicKey),
      },
    );
  }

  static void _requireArmingKey(String purpose, List<int>? mskPublicKey) {
    final arming = purpose == MailerOtpPurpose.enroll ||
        purpose == MailerOtpPurpose.replaceMsk;
    if (arming && (mskPublicKey == null || mskPublicKey.length != 32)) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'mskPublicKey is required for $purpose',
      );
    }
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
    final vaultPurpose = purpose == MailerOtpPurpose.vaultOpen ||
        purpose == MailerOtpPurpose.recoveryEnvelope ||
        purpose == MailerOtpPurpose.recoveryGeneration ||
        purpose == MailerOtpPurpose.vaultBackup;
    return _parseGrant(result, vaultPurpose: vaultPurpose);
  }

  /// Public, cacheable. Honors `Cache-Control: max-age` from the mailer.
  Future<MailerIdTokenConfig> fetchIdTokenConfig() async {
    _requireBaseUrl();
    final cached = _idTokenConfig;
    final until = _idTokenConfigUntil;
    if (cached != null && until != null && DateTime.now().isBefore(until)) {
      return cached;
    }
    final url = joinUrl(baseUrl, '/v1/idtoken/config');
    late final Response<dynamic> response;
    try {
      response = await dio.get<dynamic>(
        url,
        options: Options(headers: const {'Accept': 'application/json'}),
      );
    } on DioException catch (error) {
      throw PubkeyException.fromResponse(
        error.response?.statusCode ?? 0,
        error.response?.data ?? {'message': error.message},
      );
    }
    final data = response.data;
    if (data is! Map) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Mailer ID token config was not a JSON object',
      );
    }
    final providers = <String, MailerIdTokenProviderConfig>{};
    final rawProviders = data['providers'];
    if (rawProviders is Map) {
      for (final entry in rawProviders.entries) {
        final value = entry.value;
        if (value is! Map) continue;
        final purposes = value['purposes'];
        providers[entry.key.toString()] = MailerIdTokenProviderConfig(
          purposes: purposes is List
              ? purposes.map((item) => item.toString()).toList()
              : const [],
        );
      }
    }
    final config = MailerIdTokenConfig(
      enabled: data['enabled'] == true,
      providers: providers,
      challengeTtlSeconds: data['challenge_ttl_seconds'] is int
          ? data['challenge_ttl_seconds'] as int
          : 300,
    );
    _idTokenConfig = config;
    _idTokenConfigUntil = DateTime.now().add(
      Duration(
          seconds: _maxAgeSeconds(response.headers.value('cache-control'))),
    );
    return config;
  }

  /// Starts an ID-token mailbox proof. [mskPublicKey] is required by the
  /// mailer for `enroll` and `replace_msk`; it is sent as `msk_jkt`.
  Future<MailerIdTokenChallenge> createIdTokenChallenge({
    required String email,
    required String provider,
    required String purpose,
    List<int>? mskPublicKey,
  }) async {
    _requireBaseUrl();
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    _requireArmingKey(purpose, mskPublicKey);
    final body = <String, dynamic>{
      'email': canonical,
      'provider': provider,
      'purpose': purpose,
      if (mskPublicKey != null) 'msk_jkt': mailerMskJkt(mskPublicKey),
    };
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/idtoken/challenge'),
      method: 'POST',
      body: body,
    );
    if (result is! Map) {
      throw PubkeyException(
        ErrorCodes.idTokenChallengeInvalid,
        'Mailer challenge response was not a JSON object',
      );
    }
    final challengeId = result['challenge_id'];
    final nonce = result['nonce'];
    final expiresIn = result['expires_in'];
    if (challengeId is! String ||
        challengeId.isEmpty ||
        nonce is! String ||
        nonce.isEmpty ||
        expiresIn is! int) {
      throw PubkeyException(
        ErrorCodes.idTokenChallengeInvalid,
        'Mailer challenge response is missing challenge_id, nonce, or expires_in',
      );
    }
    if (result.containsKey('email') || result.containsKey('mailbox')) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Mailer challenge must not return a mailbox address',
      );
    }
    return MailerIdTokenChallenge(
      challengeId: challengeId,
      nonce: nonce,
      expiresIn: expiresIn,
    );
  }

  /// Verifies an OIDC ID token and returns the same grant shape as [verifyOtp].
  Future<MailerOtpGrant> verifyIdToken({
    required String challengeId,
    required String provider,
    required String purpose,
    required String idToken,
    String? graphAccessToken,
  }) async {
    _requireBaseUrl();
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/idtoken/verify'),
      method: 'POST',
      body: {
        'challenge_id': challengeId,
        'provider': provider,
        'purpose': purpose,
        'id_token': idToken,
        if (graphAccessToken != null && graphAccessToken.isNotEmpty)
          'graph_access_token': graphAccessToken,
      },
    );
    if (result is! Map) {
      throw PubkeyException(
        ErrorCodes.idTokenInvalid,
        'Mailer verify response was not a JSON object',
      );
    }
    final vaultPurpose = purpose == MailerOtpPurpose.vaultOpen ||
        purpose == MailerOtpPurpose.recoveryEnvelope ||
        purpose == MailerOtpPurpose.recoveryGeneration ||
        purpose == MailerOtpPurpose.vaultBackup;
    return _parseGrant(result, vaultPurpose: vaultPurpose);
  }

  MailerOtpGrant _parseGrant(Map result, {required bool vaultPurpose}) {
    final identityId = result['identity_id'];
    final otpGrant = result['otp_grant'];
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
    final vaultGrant = result['vault_grant'];
    return MailerOtpGrant(
      identityId: identityId is String ? identityId : null,
      otpGrant: otpGrant,
      vaultGrant:
          vaultGrant is String && vaultGrant.isNotEmpty ? vaultGrant : null,
    );
  }

  int _maxAgeSeconds(String? cacheControl) {
    if (cacheControl == null) return 300;
    final match = RegExp(r'max-age=(\d+)').firstMatch(cacheControl);
    if (match == null) return 300;
    return int.tryParse(match.group(1) ?? '') ?? 300;
  }

  void _requireBaseUrl() {
    if (baseUrl.isEmpty) {
      throw StateError(
        'PUBKEY_MAILER_BASE_URL is required and must not be empty',
      );
    }
  }
}
