import 'dart:convert';
import 'dart:typed_data';

import '../canonical.dart';
import '../constants.dart';
import '../crypto/provider.dart';
import '../errors.dart';

/// One private key recovered from a legacy SDK vault plaintext.
class LegacyVaultKey {
  const LegacyVaultKey({
    required this.family,
    required this.purpose,
    required this.privateKey,
    this.publicKey,
    this.algorithm,
    this.fingerprint,
    this.locator,
    this.status = 'active',
    this.createdAt,
    this.certificate,
    this.encoding,
  });

  /// CKVF family (`openpgp` or `smime`).
  final String family;
  final String purpose;
  final Uint8List privateKey;
  final Uint8List? publicKey;
  final String? algorithm;
  final String? fingerprint;
  final String? locator;
  final String status;
  final int? createdAt;
  final Uint8List? certificate;

  /// CKVF encoding hint (`openpgp-tsk`, `pkcs8`, …). Null when unknown.
  final String? encoding;
}

/// Decrypted contents of a legacy `secmail_pubkey_sdk` vault record.
class LegacyVaultContents {
  const LegacyVaultContents({
    required this.principal,
    required this.mskSeed,
    required this.mskPublicKey,
    required this.keys,
    this.generation = 0,
    this.currentSigningKeyId,
    this.currentEncryptionKeyId,
  });

  final String? principal;
  final Uint8List mskSeed;
  final Uint8List? mskPublicKey;
  final List<LegacyVaultKey> keys;
  final int generation;
  final String? currentSigningKeyId;
  final String? currentEncryptionKeyId;
}

/// Read-only helpers for the pre-CKVF SDK vault ciphertext format.
abstract final class LegacyVaultDecode {
  /// Decrypts [record] (`vault_format_version` / AEAD ciphertext) with [vek],
  /// then unwraps the MSK envelope with [aek].
  static Future<LegacyVaultContents> open({
    required CryptoProvider crypto,
    required Map<String, dynamic> record,
    required Uint8List vek,
    required Uint8List aek,
  }) async {
    final encryption = record['encryption'];
    final ciphertext = record['ciphertext'];
    if (encryption is! Map || ciphertext is! String) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Legacy vault record is missing encryption/ciphertext',
      );
    }
    final iv = encryption['iv'];
    if (iv is! String) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Legacy vault record is missing encryption.iv',
      );
    }
    late final Uint8List plaintext;
    try {
      plaintext = await crypto.decryptAead(
        vek,
        decodeBase64Url(iv),
        decodeBase64Url(ciphertext),
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.vaultAuthenticationFailure,
        'Legacy vault authentication failed',
      );
    }
    return fromPlaintext(crypto: crypto, plaintext: plaintext, aek: aek);
  }

  /// Parses VEK-decrypted vault plaintext JSON and unwraps the MSK with [aek].
  static Future<LegacyVaultContents> fromPlaintext({
    required CryptoProvider crypto,
    required Uint8List plaintext,
    required Uint8List aek,
  }) async {
    final parsed = jsonDecode(utf8.decode(plaintext));
    if (parsed is! Map) {
      throw PubkeyException(ErrorCodes.vaultCorrupt, 'Invalid vault plaintext');
    }
    final map = Map<String, dynamic>.from(parsed);
    if (map['vault_format_version'] != vaultFormatVersion) {
      throw PubkeyException(
        ErrorCodes.protocolVersionMismatch,
        'Unsupported vault format ${map['vault_format_version']}',
      );
    }
    final envelope = map['msk_envelope'];
    if (envelope is! Map) {
      throw PubkeyException(
        ErrorCodes.mskEnvelopeMissing,
        'Legacy vault has no MSK envelope',
      );
    }
    final env = Map<String, dynamic>.from(envelope);
    final envIv = env['iv'];
    final encryptedMsk = env['encrypted_msk'];
    if (envIv is! String || encryptedMsk is! String) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'MSK envelope is missing iv/encrypted_msk',
      );
    }
    late final Uint8List mskSeed;
    try {
      mskSeed = await crypto.decryptAead(
        aek,
        decodeBase64Url(envIv),
        decodeBase64Url(encryptedMsk),
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'This device does not hold authority (AEK) for this identity',
      );
    }
    final pubRaw = env['public_key'];
    return LegacyVaultContents(
      principal: map['principal'] as String?,
      mskSeed: mskSeed,
      mskPublicKey: pubRaw is String ? decodeBase64Url(pubRaw) : null,
      generation: map['generation'] as int? ?? 0,
      currentSigningKeyId: _keyIdPointer(map['current_signing_key_id']),
      currentEncryptionKeyId: _keyIdPointer(map['current_encryption_key_id']),
      keys: _keysFromPlaintext(map),
    );
  }

  static String? _keyIdPointer(Object? value) {
    if (value == null) return null;
    if (value is String) return value.isEmpty ? null : value;
    if (value is int) return value.toString();
    return null;
  }

  static List<LegacyVaultKey> _keysFromPlaintext(Map<String, dynamic> map) {
    final out = <LegacyVaultKey>[];
    void addOpenPgp(List? raw) {
      if (raw == null) return;
      for (final item in raw) {
        if (item is! Map) continue;
        final j = Map<String, dynamic>.from(item);
        final priv = j['private_key'];
        if (priv is! String) continue;
        out.add(LegacyVaultKey(
          family: 'openpgp',
          purpose: j['type'] == 'signing' ? Purposes.signing : Purposes.encryption,
          privateKey: decodeBase64Url(priv),
          algorithm: j['algorithm'] as String?,
          fingerprint: j['fingerprint'] as String?,
          locator: j['locator'] as String?,
          status: _statusFromSpec(j['status'] as String? ?? 'active'),
          createdAt: j['created_at'] as int?,
          encoding: 'openpgp-tsk',
        ));
      }
    }

    void addSmime(List? raw) {
      if (raw == null) return;
      for (final item in raw) {
        if (item is! Map) continue;
        final j = Map<String, dynamic>.from(item);
        final priv = j['private_key'];
        if (priv is! String) continue;
        final cert = j['certificate'];
        out.add(LegacyVaultKey(
          family: 'smime',
          purpose: Purposes.encryption,
          privateKey: decodeBase64Url(priv),
          certificate: cert is String ? decodeBase64Url(cert) : null,
          algorithm: j['algorithm'] as String?,
          fingerprint: j['fingerprint'] as String?,
          locator: j['locator'] as String?,
          status: _statusFromSpec(j['status'] as String? ?? 'active'),
          createdAt: j['created_at'] as int?,
          encoding: 'pkcs8',
        ));
      }
    }

    void addSigning(List? raw) {
      if (raw == null) return;
      for (final item in raw) {
        if (item is! Map) continue;
        final j = Map<String, dynamic>.from(item);
        final priv = j['private_key'];
        if (priv is! String) continue;
        out.add(LegacyVaultKey(
          family: 'smime',
          purpose: Purposes.signing,
          privateKey: decodeBase64Url(priv),
          algorithm: j['algorithm'] as String?,
          fingerprint: j['fingerprint'] as String?,
          locator: j['locator'] as String?,
          status: _statusFromSpec(j['status'] as String? ?? 'active'),
          createdAt: j['created_at'] as int?,
          encoding: 'pkcs8',
        ));
      }
    }

    addOpenPgp(map['openpgp_keys'] as List?);
    addSmime(map['smime_keys'] as List?);
    addSigning(map['signing_keys'] as List?);

    final legacy = map['legacy_entries'];
    if (legacy is List) {
      for (final item in legacy) {
        if (item is! Map) continue;
        final j = Map<String, dynamic>.from(item);
        final priv = j['private_material'] ?? j['private_key'];
        if (priv is! String) continue;
        final family = '${j['family'] ?? ''}';
        final ckvfFamily = family == Families.pgp || family == 'openpgp'
            ? 'openpgp'
            : family == Families.smime
                ? 'smime'
                : null;
        if (ckvfFamily == null) continue;
        out.add(LegacyVaultKey(
          family: ckvfFamily,
          purpose: '${j['purpose'] ?? Purposes.encryption}',
          privateKey: decodeBase64Url(priv),
          algorithm: j['algorithm'] as String?,
          fingerprint: j['fingerprint'] as String?,
          locator: j['locator'] as String?,
          status: _statusFromSpec(j['status'] as String? ?? 'active'),
          createdAt: j['created_at'] as int?,
          encoding: ckvfFamily == 'openpgp' ? 'openpgp-tsk' : 'pkcs8',
        ));
      }
    }
    return out;
  }

  static String _statusFromSpec(String status) =>
      status == 'historical' ? 'retired' : status;
}
