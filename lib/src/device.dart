import 'constants.dart';
import 'errors.dart';
import 'jcs.dart';

Map<String, dynamic> deviceAuthorizationPayload({
  int version = deviceAuthorizationVersion,
  required String principalId,
  required String deviceId,
  required String devicePublicKey,
  String algorithm = deviceKeyAlgorithm,
  required int createdAt,
  required String nonce,
  String? deviceName,
}) {
  if (version != deviceAuthorizationVersion) {
    throw PubkeyException(
      ErrorCodes.unsupportedStructureVersion,
      'Unsupported DeviceAuthorization version',
    );
  }
  final payload = <String, dynamic>{
    'version': version,
    'principal_id': principalId,
    'device_id': deviceId,
    'device_public_key': devicePublicKey,
    'device_key_algorithm': algorithm,
    'created_at': createdAt,
    'nonce': nonce,
  };
  if (deviceName != null) payload['device_name'] = deviceName;
  return payload;
}

String canonicalizeDeviceAuthorization(Map<String, dynamic> authorization) {
  return canonicalizeJson(
    deviceAuthorizationPayload(
      version: authorization['version'] as int? ?? deviceAuthorizationVersion,
      principalId: authorization['principalId'] as String? ??
          authorization['principal_id'] as String,
      deviceId: authorization['deviceId'] as String? ??
          authorization['device_id'] as String,
      devicePublicKey: authorization['devicePublicKey'] as String? ??
          authorization['device_public_key'] as String,
      algorithm: authorization['deviceKeyAlgorithm'] as String? ??
          authorization['device_key_algorithm'] as String? ??
          deviceKeyAlgorithm,
      createdAt: authorization['createdAt'] as int? ??
          authorization['created_at'] as int,
      nonce: authorization['nonce'] as String,
      deviceName: authorization['deviceName'] as String? ??
          authorization['device_name'] as String?,
    ),
  );
}

bool mustNotGenerateMsk({
  required bool principalExists,
  required bool localMsk,
  required bool explicitRecovery,
}) {
  return principalExists && !localMsk && !explicitRecovery;
}

String resolveIdentityUxState({
  required bool principalExists,
  bool localMsk = false,
  bool? deviceAuthorized,
  String? enrollmentState,
  String? recoveryState,
  bool vaultSyncing = false,
  bool? historicalKeysAvailable,
}) {
  if (recoveryState == 'OTP_SENT' || recoveryState == 'RECOVERY_REQUESTED') {
    return IdentityUxStates.otpRequired;
  }
  if (recoveryState == 'OTP_VERIFIED' || recoveryState == 'NEW_MSK_SUBMITTED') {
    return IdentityUxStates.newMskCreating;
  }
  if (recoveryState == 'COMPLETE') {
    return historicalKeysAvailable == false
        ? IdentityUxStates.historicalKeysUnavailable
        : IdentityUxStates.identityRecovered;
  }
  if (enrollmentState == 'EXPIRED') return IdentityUxStates.enrollmentExpired;
  if (enrollmentState == 'REJECTED') return IdentityUxStates.enrollmentRejected;
  if (enrollmentState == 'WAITING_FOR_APPROVAL' ||
      enrollmentState == 'QR_CREATED') {
    return IdentityUxStates.waitingForApproval;
  }
  if (enrollmentState != null && enrollmentState != 'ACTIVE') {
    return IdentityUxStates.enrollmentPending;
  }
  if (!principalExists) return IdentityUxStates.noIdentity;
  if (!localMsk && deviceAuthorized != true) {
    return IdentityUxStates.unauthorized;
  }
  if (deviceAuthorized == false) return IdentityUxStates.unauthorized;
  if (vaultSyncing) return IdentityUxStates.vaultSyncing;
  return IdentityUxStates.authorized;
}
