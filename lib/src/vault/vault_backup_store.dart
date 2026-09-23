import 'dart:convert';
import 'dart:typed_data';

import '../client/mailer_client.dart';
import '../client/pubkey_client.dart';
import '../crypto/provider.dart';
import '../errors.dart';
import 'vault_export.dart';

/// Host-chosen destination for a password-wrapped [scomm-vault-export] blob.
///
/// Wrap crypto stays in [VaultExport] / [PubkeyRuntime.exportVaultOffline].
/// Stores only persist or retrieve the already-wrapped JSON.
abstract class VaultBackupStore {
  Future<void> put({
    required String identity,
    required Map<String, dynamic> blob,
  });

  Future<Map<String, dynamic>?> get({
    required String identity,
    String? otp,
  });

  Future<void> delete({required String identity});
}

/// Bytes the host writes to a user-chosen path (file, USB, etc.).
class LocalFileBackupStore implements VaultBackupStore {
  LocalFileBackupStore({
    required this.writeBytes,
    required this.readBytes,
    this.deleteBytes,
  });

  final Future<void> Function(String identity, Uint8List bytes) writeBytes;
  final Future<Uint8List?> Function(String identity) readBytes;
  final Future<void> Function(String identity)? deleteBytes;

  @override
  Future<void> put({
    required String identity,
    required Map<String, dynamic> blob,
  }) {
    final bytes = Uint8List.fromList(utf8.encode(jsonEncode(blob)));
    return writeBytes(identity, bytes);
  }

  @override
  Future<Map<String, dynamic>?> get({
    required String identity,
    String? otp,
  }) async {
    final bytes = await readBytes(identity);
    if (bytes == null || bytes.isEmpty) return null;
    final decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Local backup is not a vault export object',
      );
    }
    return Map<String, dynamic>.from(decoded);
  }

  @override
  Future<void> delete({required String identity}) async {
    await deleteBytes?.call(identity);
  }
}

/// Hosted opaque slot on the write host. Put is MSK-signed; get is OTP-gated.
class DiscoveryBackupStore implements VaultBackupStore {
  DiscoveryBackupStore(this.client, {required this.mailer, this.mskKey});

  final PubkeyClient client;
  final MailerClient mailer;
  KeyRef? mskKey;

  Future<void> requestOtp({required String identity}) {
    return mailer.requestOtp(
      email: identity,
      purpose: MailerOtpPurpose.vaultBackup,
    );
  }

  @override
  Future<void> put({
    required String identity,
    required Map<String, dynamic> blob,
  }) async {
    final parsed = VaultExport.parseExportFile(blob);
    if (!parsed.hasSecrets) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Hosted backup must include a password-wrapped VEK envelope',
      );
    }
    final key = mskKey;
    if (key == null) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'An authorized device is required to store a hosted vault backup',
      );
    }
    await client.setVaultBackup(
      email: identity,
      mskKey: key,
      backupJson: jsonEncode(blob),
    );
  }

  @override
  Future<Map<String, dynamic>?> get({
    required String identity,
    String? otp,
  }) async {
    if (otp == null || otp.isEmpty) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Mailbox OTP is required to fetch a hosted vault backup',
      );
    }
    final grant = await mailer.verifyOtp(
      email: identity,
      otp: otp,
      purpose: MailerOtpPurpose.vaultBackup,
    );
    return client.fetchVaultBackupWithGrant(
      identityId: grant.identityId,
      otpGrant: grant.otpGrant,
    );
  }

  @override
  Future<void> delete({required String identity}) async {
    final key = mskKey;
    if (key == null) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'An authorized device is required to delete a hosted vault backup',
      );
    }
    await client.deleteVaultBackup(email: identity, mskKey: key);
  }
}
