import 'dart:convert';

import '../protocol_digest.dart';
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
  final digest = ProtocolDigest.sha256(mskPublicKey);
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
  final Map<String, String> _otpChallengeIds = {};
  final Map<String, String> _challengeMailboxes = {};

  static const _emailOtpType =
      'https://discovery.scomm.ai/challenges/email-otp/v1';
  static const _oidcType =
      'https://discovery.scomm.ai/challenges/oidc-id-token/v1';

  static const _purposeUris = {
    MailerOtpPurpose.enroll:
        'https://discovery.scomm.ai/operations/msk/enroll/v1',
    MailerOtpPurpose.replaceMsk:
        'https://discovery.scomm.ai/operations/msk/replace/v1',
    MailerOtpPurpose.vaultOpen:
        'https://discovery.scomm.ai/operations/vault/open/v1',
    MailerOtpPurpose.vaultBackup:
        'https://discovery.scomm.ai/operations/vault/backup-fetch/v1',
    MailerOtpPurpose.recoveryEnvelope:
        'https://discovery.scomm.ai/operations/recovery/envelope-fetch/v1',
    MailerOtpPurpose.recoveryGeneration:
        'https://discovery.scomm.ai/operations/recovery/generation/v1',
  };

  static String _purposeUri(String purpose) {
    final uri = _purposeUris[purpose];
    if (uri == null) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Unknown mailer purpose $purpose',
      );
    }
    return uri;
  }

  /// Always treats a uniform success as "a code was sent if this mailbox
  /// can be used." Does not distinguish unknown vs enrolled.
  ///
  /// [mskPublicKey] is required for `enroll` and `replace_msk`: the grant
  /// names that key (`msk_jkt`) and can arm no other.
  /// Returns the challenge id. The OTP itself is not in the response.
  Future<String> requestOtp({
    required String email,
    required String purpose,
    List<int>? mskPublicKey,
  }) async {
    _requireBaseUrl();
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    _requireArmingKey(purpose, mskPublicKey);
    final sha = emailSha256Hex(canonical);
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/mailboxes/$sha/challenges'),
      method: 'POST',
      body: {
        'type': _emailOtpType,
        'email': canonical,
        'purpose': _purposeUri(purpose),
        if (mskPublicKey != null) 'msk_jkt': mailerMskJkt(mskPublicKey),
      },
    );
    if (result is! Map || result['id'] is! String) {
      throw PubkeyException(
        ErrorCodes.otpInvalid,
        'Mailer challenge response did not return an id',
      );
    }
    final challengeId = result['id'] as String;
    _otpChallengeIds['$sha:$purpose'] = challengeId;
    return challengeId;
  }

  static void _requireArmingKey(String purpose, List<int>? mskPublicKey) {
    final arming = purpose == MailerOtpPurpose.enroll ||
        purpose == MailerOtpPurpose.replaceMsk;
    final length = mskPublicKey?.length;
    if (arming && length != 32 && length != 1984) {
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
    final challengeId = _otpChallengeIds['$sha256:$purpose'];
    if (challengeId == null) {
      throw PubkeyException(
        ErrorCodes.otpInvalid,
        'Call requestOtp before verifyOtp',
      );
    }
    final result = await pubkeyRequest(
      dio,
      joinUrl(
        baseUrl,
        '/v1/mailboxes/$sha256/challenges/$challengeId/responses',
      ),
      method: 'POST',
      body: {
        'response': {'code': otp.trim()},
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
    final url = joinUrl(baseUrl, '/v1/challenges/config');
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
    final sha = emailSha256Hex(canonical);
    final body = <String, dynamic>{
      'type': _oidcType,
      'email': canonical,
      'provider': provider,
      'purpose': _purposeUri(purpose),
      if (mskPublicKey != null) 'msk_jkt': mailerMskJkt(mskPublicKey),
    };
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/mailboxes/$sha/challenges'),
      method: 'POST',
      body: body,
    );
    if (result is! Map) {
      throw PubkeyException(
        ErrorCodes.idTokenChallengeInvalid,
        'Mailer challenge response was not a JSON object',
      );
    }
    final challengeId = result['id'];
    final nonce = result['nonce'];
    final expiresAt = result['expiresAt'];
    final expiresIn = expiresAt is String
        ? DateTime.parse(expiresAt).difference(DateTime.now()).inSeconds
        : null;
    if (challengeId is! String ||
        challengeId.isEmpty ||
        nonce is! String ||
        nonce.isEmpty ||
        expiresIn == null) {
      throw PubkeyException(
        ErrorCodes.idTokenChallengeInvalid,
        'Mailer challenge response is missing id, nonce, or expiresAt',
      );
    }
    _challengeMailboxes[challengeId] = sha;
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
    if (provider.isEmpty || purpose.isEmpty) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'provider and purpose are required',
      );
    }
    final sha = _challengeMailboxes[challengeId];
    if (sha == null) {
      throw PubkeyException(
        ErrorCodes.idTokenInvalid,
        'Call createIdTokenChallenge before verifyIdToken',
      );
    }
    final result = await pubkeyRequest(
      dio,
      joinUrl(baseUrl, '/v1/mailboxes/$sha/challenges/$challengeId/responses'),
      method: 'POST',
      body: {
        'response': {
          'id_token': idToken,
          if (graphAccessToken != null && graphAccessToken.isNotEmpty)
            'graph_access_token': graphAccessToken,
        },
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
