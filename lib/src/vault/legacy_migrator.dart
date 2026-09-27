import 'dart:typed_data';

import 'package:scomm_vault_client/scomm_vault_client.dart';

import '../canonical.dart';
import '../crypto/dart_crypto.dart';
import '../crypto/provider.dart';
import 'legacy_decode.dart';

/// Result of [LegacyVaultMigrator.migrate].
class LegacyMigrationResult {
  const LegacyMigrationResult({
    required this.vault,
    required this.importedKeyIds,
    this.recoveryCode,
  });

  final KeyVault vault;
  final List<String> importedKeyIds;

  /// Present when a recovery-code slot was created during migration.
  final String? recoveryCode;
}

/// Opens a legacy SDK vault ciphertext and uploads generation 1 as a CKVF
/// container through [scomm_vault_client].
///
/// Read-only with respect to the legacy format: it never writes the old
/// record shape. Device, password-oprf, and recovery-code-oprf slots are
/// attached on the new container when the corresponding secrets are supplied.
abstract final class LegacyVaultMigrator {
  /// Decrypts [legacyRecord] with [vek]/[aek], creates a local [KeyVault]
  /// generation-1 container, imports recoverable keys, optionally adds
  /// pepper slots, and [KeyVault.push]es when [binding] is set.
  static Future<LegacyMigrationResult> migrate({
    required Map<String, dynamic> legacyRecord,
    required Uint8List vek,
    required Uint8List aek,
    required LocalVaultStore store,
    required VaultDevice device,
    required String email,
    CryptoProvider? crypto,
    VaultHostBinding? binding,
    String? backupPassword,
    bool generateRecoveryCode = false,
    PepperOprf? pepper,
    PepperKey? pepperKey,
    bool push = true,
  }) async {
    final provider = crypto ?? DartCryptoProvider();
    final contents = await LegacyVaultDecode.open(
      crypto: provider,
      record: legacyRecord,
      vek: vek,
      aek: aek,
    );

    // Build locally first so imports do not push intermediate generations.
    final vault = KeyVault(store);
    await vault.create(
      email: email,
      device: device,
      mskSeed: contents.mskSeed,
    );

    final imported = <String>[];
    for (final key in contents.keys) {
      if (key.privateKey.isEmpty) continue;
      final purposes = <String>[
        key.purpose == 'signing' ? 'sign' : key.purpose,
      ];
      try {
        final id = await vault.importKey(
          family: key.family,
          encoding: key.encoding ??
              (key.family == 'openpgp' ? 'openpgp-tsk' : 'pkcs8'),
          algorithm: key.algorithm ?? 'unknown',
          purpose: purposes,
          privateKey: key.privateKey,
          publicKey: key.publicKey ??
              (key.family == 'openpgp' ? key.privateKey : Uint8List(0)),
          meta: {
            if (key.fingerprint != null) 'fingerprint': key.fingerprint,
            if (key.locator != null) 'locator': key.locator,
            if (key.certificate != null)
              'certificate': encodeBase64Url(key.certificate!),
          },
          status: key.status == 'revoked' ? 'revoked' : key.status,
          createdAt: key.createdAt == null
              ? null
              : DateTime.fromMillisecondsSinceEpoch(key.createdAt!)
                  .toUtc()
                  .toIso8601String(),
          push: false,
        );
        imported.add(id);
        final prefPurpose =
            purposes.contains('sign') ? 'sign' : 'encrypt';
        await vault.setPreferred(key.family, prefPurpose, id);
      } catch (_) {
        // Skip keys the CKVF importer rejects (unknown encoding, etc.).
      }
    }

    String? recoveryCode;
    if (pepper != null && pepperKey != null) {
      if (backupPassword != null && backupPassword.isNotEmpty) {
        await vault.setBackupPassword(
          backupPassword,
          pepper: pepper,
          key: pepperKey,
        );
      }
      if (generateRecoveryCode) {
        recoveryCode = await vault.addRecoveryCode(
          pepper: pepper,
          key: pepperKey,
        );
      }
    }

    vault.binding = binding;
    if (push && binding != null) {
      await vault.push();
    }

    return LegacyMigrationResult(
      vault: vault,
      importedKeyIds: imported,
      recoveryCode: recoveryCode,
    );
  }
}
