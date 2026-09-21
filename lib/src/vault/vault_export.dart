import 'dart:convert';
import 'dart:typed_data';

import '../canonical.dart';
import '../constants.dart';
import '../crypto/provider.dart';
import '../errors.dart';
import 'key_hierarchy.dart';

// CKVF offline vault export/import.
//
// This file only wires the structural rules of the export file format onto
// the existing [CryptoProvider] primitives (Argon2id via `deriveArgon2id`,
// AEAD via `encryptAead`/`decryptAead`, CSPRNG via `random`) — it does not
// implement any new cryptographic primitive itself.
// It is a pure, stateless helper (no I/O, no HTTP), mirroring
// `device_pairing.dart`'s structure: the actual orchestration (fetching a
// fresh generation from the server, persisting DKEK-wrapped envelopes
// locally, performing the device-add mutation for a full-tier import) lives
// in `PubkeyRuntime.exportVaultOffline`/`importVaultOffline`, one layer up.
//
// EEK (Export Encryption Key) is derived from a user-supplied
// export passphrase — distinct from the file's own recovery-code (REK,
// not yet built) and never itself stored in the exported file
// ("The passphrase itself must never be embedded in the
// exported file").
//
// Deliberately distinct from `package:ckvf` (ckvf/packages/dart)
// — a separate, pre-existing, unrelated container format already used by
// this app's `KeyManagerController.exportLocalVault`/`importLocalVault` (see
// that file's doc comments). [vaultExportKind] exists so a user's two kinds
// of exported file are never confused with each other.

/// A CKVF-spec offline export file's `vek_envelope`/`aek_envelope` shape:
/// `AEAD_Encrypt(EEK, secret)`, plus the Argon2id parameters needed to
/// re-derive EEK from the passphrase on the importing side. The passphrase
/// itself is never present here.
class ExportEnvelope {
  const ExportEnvelope({
    required this.kdf,
    required this.salt,
    required this.memory,
    required this.iterations,
    required this.parallelism,
    required this.wrapped,
  });

  final String kdf;
  final Uint8List salt;
  final int memory;
  final int iterations;
  final int parallelism;
  final WrappedKey wrapped;

  Map<String, dynamic> toJson() => {
        'kdf': kdf,
        'kdf_params': {
          'memory': memory,
          'iterations': iterations,
          'parallelism': parallelism,
        },
        'salt': encodeBase64Url(salt),
        'iv': encodeBase64Url(wrapped.iv),
        'ciphertext': encodeBase64Url(wrapped.ciphertext),
      };

  factory ExportEnvelope.fromJson(Map<String, dynamic> json) {
    final kdf = json['kdf'];
    final saltRaw = json['salt'];
    final ivRaw = json['iv'];
    final ciphertextRaw = json['ciphertext'];
    final params = json['kdf_params'];
    if (kdf is! String ||
        saltRaw is! String ||
        ivRaw is! String ||
        ciphertextRaw is! String ||
        params is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Export envelope is missing required fields',
      );
    }
    return ExportEnvelope(
      kdf: kdf,
      salt: decodeBase64Url(saltRaw),
      memory: (params['memory'] as num?)?.toInt() ?? argon2idDefaultMemoryKib,
      iterations:
          (params['iterations'] as num?)?.toInt() ?? argon2idDefaultIterations,
      parallelism:
          (params['parallelism'] as num?)?.toInt() ?? argon2idDefaultParallelism,
      wrapped: WrappedKey(iv: decodeBase64Url(ivRaw), ciphertext: decodeBase64Url(ciphertextRaw)),
    );
  }
}

/// The result of [VaultExport.parseExportFile] — a validated, typed view of
/// an offline export file. `aek` fields are only present for a
/// `tier: "full"` export. [vekEnvelope] itself is only present when the
/// export was password-protected — see [hasSecrets].
class ParsedVaultExportFile {
  const ParsedVaultExportFile({
    required this.identity,
    required this.tier,
    required this.createdAt,
    this.vekEnvelope,
    this.aekEnvelope,
    required this.generation,
    required this.ciphertext,
    required this.nonce,
    required this.ciphertextHash,
    this.previousGenerationHash,
  });

  final String identity;

  /// `"full"` or `"limited"` (the device tiers).
  final String tier;
  final int createdAt;

  /// `null` for a vault-only export (no password protection chosen at
  /// export time) — see [hasSecrets].
  final ExportEnvelope? vekEnvelope;
  final ExportEnvelope? aekEnvelope;

  final int generation;
  final Uint8List ciphertext;
  final Uint8List nonce;
  final Uint8List ciphertextHash;

  /// Only populated when the exporting device happened to already know the
  /// prior generation's hash — see [VaultExport.buildExportFile]'s doc
  /// comment for why this is best-effort, not authoritative.
  final Uint8List? previousGenerationHash;

  bool get isFullTier => tier == 'full';

  /// Whether this file bundles password-wrapped VEK/AEK envelopes at all.
  /// `false` means the export was created without password protection — it
  /// carries only the (still VEK-encrypted) vault ciphertext, with no way to
  /// unlock it from this file alone. The importing UI should offer "sync
  /// secrets from another device" (device pairing) instead of a
  /// passphrase prompt in that case.
  bool get hasSecrets => vekEnvelope != null;
}

/// Offline vault export/import file-format and crypto call sites. Every
/// cryptographic operation is delegated to [CryptoProvider] —
/// this class only encodes which key wraps which, and the file's JSON shape,
/// not the AEAD/Argon2id/CSPRNG primitives themselves.
abstract final class VaultExport {
  /// `EEK = Argon2id(passphrase, salt)`. [salt] should be
  /// freshly generated (`crypto.random(eekSaltBytes)`) for every export —
  /// never reused across exports, even for the same identity/passphrase.
  static Future<Uint8List> deriveEek(
    CryptoProvider crypto,
    String passphrase,
    Uint8List salt, {
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int parallelism = argon2idDefaultParallelism,
  }) {
    return crypto.deriveArgon2id(
      utf8EncodePassphrase(passphrase),
      salt,
      memory: memory,
      iterations: iterations,
      parallelism: parallelism,
      length: vekKeyLengthBytes,
    );
  }

  /// `AEAD_Encrypt(EEK, secret)` (`ExportVEKEnvelope =
  /// AEAD_Encrypt(EEK, VEK)` — the same wrap is reused verbatim for AEK on a
  /// full-tier export). [salt]/[memory]/[iterations]/[parallelism] are
  /// bundled alongside the ciphertext so the importing device can re-derive
  /// the identical EEK from just the passphrase (never itself stored).
  static Future<ExportEnvelope> wrapWithEek(
    CryptoProvider crypto,
    Uint8List eek,
    Uint8List secret, {
    required Uint8List salt,
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int parallelism = argon2idDefaultParallelism,
  }) async {
    final wrapped = await crypto.encryptAead(eek, secret);
    return ExportEnvelope(
      kdf: eekKdf,
      salt: salt,
      memory: memory,
      iterations: iterations,
      parallelism: parallelism,
      wrapped: WrappedKey(iv: wrapped.iv, ciphertext: wrapped.ciphertext),
    );
  }

  /// Inverse of [wrapWithEek] — re-derives EEK from [envelope]'s own salt/kdf
  /// params and [passphrase], then unwraps. A failed unwrap means either a
  /// wrong passphrase or tampering — throws
  /// [ErrorCodes.envelopeAuthenticationFailure] with no weaker fallback
  /// (mirrors [KeyHierarchy.unwrapWithDkek]/[DevicePairing.unwrapTransfer]).
  static Future<Uint8List> unwrapWithEek(
    CryptoProvider crypto,
    String passphrase,
    ExportEnvelope envelope,
  ) async {
    final eek = await deriveEek(
      crypto,
      passphrase,
      envelope.salt,
      memory: envelope.memory,
      iterations: envelope.iterations,
      parallelism: envelope.parallelism,
    );
    try {
      return await crypto.decryptAead(
        eek,
        envelope.wrapped.iv,
        envelope.wrapped.ciphertext,
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to unwrap export envelope: wrong passphrase or tampering',
      );
    }
  }

  /// Assembles the offline export file's JSON structure.
  ///
  /// [vekEnvelope] is `null` for a vault-only export — the user chose not to
  /// password-protect the backup, so no VEK/AEK envelope is bundled at all,
  /// only the (still VEK-encrypted) vault ciphertext. [aekEnvelope] must
  /// then also be `null`, since AEK can only be wrapped alongside VEK.
  ///
  /// [previousGenerationHash] is best-effort only: the exporting device
  /// knows the hash of its own *current* synced generation
  /// (`Vault.lastCiphertextHash`), not the hash of the generation before it
  /// (the server's `VaultRecord.previous_generation_hash` for that
  /// generation) — fetching that would need a new raw-record-read client
  /// call this step doesn't otherwise need, so this field is included when
  /// the caller has it and omitted (`null`) otherwise. Its absence does not
  /// impede import: the importing device's first future mutation self-heals
  /// via the existing conflict-retry path
  /// (`PubkeyRuntime.mutateAndUpload`) regardless.
  static Map<String, dynamic> buildExportFile({
    required String identity,
    required String tier,
    required int createdAt,
    ExportEnvelope? vekEnvelope,
    ExportEnvelope? aekEnvelope,
    required int generation,
    required Uint8List ciphertext,
    required Uint8List nonce,
    required Uint8List ciphertextHash,
    Uint8List? previousGenerationHash,
  }) {
    if (tier != 'full' && tier != 'limited') {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'tier must be "full" or "limited"',
      );
    }
    if (aekEnvelope != null && vekEnvelope == null) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'An aek_envelope requires a vek_envelope',
      );
    }
    if (tier == 'full' && vekEnvelope != null && aekEnvelope == null) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'A full-tier, password-protected export requires an aek_envelope',
      );
    }
    return {
      'kind': vaultExportKind,
      'header': {
        'format_version': vaultExportFormatVersion,
        'identity': identity,
        'created_at': createdAt,
        'tier': tier,
      },
      'vault_ciphertext': {
        'generation': generation,
        'ciphertext': encodeBase64Url(ciphertext),
        'nonce': encodeBase64Url(nonce),
        'previous_generation_hash': previousGenerationHash == null
            ? null
            : encodeBase64Url(previousGenerationHash),
        'ciphertext_hash': encodeBase64Url(ciphertextHash),
      },
      if (vekEnvelope != null) 'vek_envelope': vekEnvelope.toJson(),
      if (aekEnvelope != null) 'aek_envelope': aekEnvelope.toJson(),
    };
  }

  /// Inverse of [buildExportFile]. Throws
  /// [ErrorCodes.vaultExportFormatUnsupported] if [json] isn't a recognized
  /// export file (wrong `kind`, unsupported `format_version`, or
  /// missing required fields) — including, deliberately, a `package:ckvf`
  /// container (which uses a different top-level shape entirely and will
  /// fail this same way, never silently misparsed).
  static ParsedVaultExportFile parseExportFile(Map<String, dynamic> json) {
    if (json['kind'] != vaultExportKind) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Not a Scomm.AI vault export file (unrecognized or missing "kind")',
      );
    }
    final header = json['header'];
    final vaultCiphertext = json['vault_ciphertext'];
    if (header is! Map || vaultCiphertext is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Vault export file is missing required sections',
      );
    }
    if (header['format_version'] != vaultExportFormatVersion) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Unsupported vault export format version ${header['format_version']}',
      );
    }
    final identity = header['identity'];
    final tier = header['tier'];
    if (identity is! String || (tier != 'full' && tier != 'limited')) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Vault export header is missing identity/tier',
      );
    }
    // Absent entirely for a vault-only export (no password protection
    // chosen at export time) — see [ParsedVaultExportFile.hasSecrets].
    final vekEnvelopeRaw = json['vek_envelope'];
    final aekEnvelopeRaw = json['aek_envelope'];
    if (vekEnvelopeRaw != null && vekEnvelopeRaw is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Vault export file\'s vek_envelope is malformed',
      );
    }
    if (tier == 'full' && vekEnvelopeRaw is Map && aekEnvelopeRaw is! Map) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'A full-tier, password-protected vault export file is missing its '
        'aek_envelope',
      );
    }
    final generation = vaultCiphertext['generation'];
    final ciphertext = vaultCiphertext['ciphertext'];
    final nonce = vaultCiphertext['nonce'];
    final ciphertextHash = vaultCiphertext['ciphertext_hash'];
    if (generation is! int || ciphertext is! String || nonce is! String || ciphertextHash is! String) {
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'Vault export file\'s vault_ciphertext is missing required fields',
      );
    }
    final previousHashRaw = vaultCiphertext['previous_generation_hash'];
    return ParsedVaultExportFile(
      identity: identity,
      tier: tier,
      createdAt: (header['created_at'] as num?)?.toInt() ?? 0,
      vekEnvelope: vekEnvelopeRaw is Map
          ? ExportEnvelope.fromJson(Map<String, dynamic>.from(vekEnvelopeRaw))
          : null,
      aekEnvelope: aekEnvelopeRaw is Map
          ? ExportEnvelope.fromJson(Map<String, dynamic>.from(aekEnvelopeRaw))
          : null,
      generation: generation,
      ciphertext: decodeBase64Url(ciphertext),
      nonce: decodeBase64Url(nonce),
      ciphertextHash: decodeBase64Url(ciphertextHash),
      previousGenerationHash:
          previousHashRaw is String ? decodeBase64Url(previousHashRaw) : null,
    );
  }
}

/// UTF-8 encodes a passphrase for KDF input — a tiny named helper so
/// [VaultExport.deriveEek]'s call sites read as "encode the passphrase," not
/// a bare `utf8.encode`.
List<int> utf8EncodePassphrase(String passphrase) => utf8.encode(passphrase);
