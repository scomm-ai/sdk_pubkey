import 'dart:convert';
import 'dart:typed_data';

import '../constants.dart';
import '../crypto/provider.dart';
import '../errors.dart';
import '../identity.dart' show sha256Bytes;
import 'bip39_wordlist.dart';
import 'key_hierarchy.dart';
import 'vault_export.dart';

// CKVF recovery via recovery code.
//
// This file only wires the structural rules of the recovery-code
// mechanism onto the existing [CryptoProvider] primitives (Argon2id via
// `deriveArgon2id`, AEAD via `encryptAead`/`decryptAead`, CSPRNG via
// `random`) — it does not implement any new cryptographic primitive itself.
// It is a pure, stateless helper (no I/O, no HTTP),
// mirroring `vault_export.dart`'s structure closely: the actual
// orchestration (uploading the setup envelope, fetching it back during
// recovery, decrypting the current vault, registering the new device) lives
// in `PubkeyRuntime.setupRecoveryCode`/`recoverWithCode`, one layer up.
//
// REK (Recovery Encryption Key) is derived from a user-held
// recovery code — a CSPRNG-generated secret (BIP39 word list or random
// alphanumeric code, the user's choice at setup time — Boundary B1: never a
// low-entropy human-chosen passphrase) — the same "derive a symmetric key
// from a human-held secret via Argon2id" shape [VaultExport.deriveEek]
// already uses for EEK, so [ExportEnvelope] is reused verbatim as the
// recovery envelope's wire shape rather than inventing a parallel type.
//
// The recovery code itself is never transmitted to the server
// and is never persisted anywhere client-side either — it exists
// only transiently in memory during setup (to derive REK and hand back to
// the caller exactly once for display) and during recovery (to derive REK
// and immediately unwrap).

/// [RecoveryCode.generateBip39Words]'s supported word counts — 12 words
/// (128 bits of entropy) or 24 words (256 bits), matching BIP39's own
/// `strength` parameter (`128`/`256` bits respectively).
const Map<int, int> _bip39StrengthByWordCount = {12: 128, 24: 256};

/// CSPRNG byte length for [RecoveryCode.generateRandomCode] — 20 bytes = 160
/// bits, deliberately higher than [pairingSessionCodeLength]'s 40 bits
/// (the pairing code is a short-lived, 5-minute session secret;
/// this is a durable secret with no expiry, so it needs a much larger
/// security margin).
const int recoveryRandomCodeLengthBytes = 20;

/// Crockford base32 alphabet (excludes the visually ambiguous I/L/O/U) —
/// same alphabet `device_pairing.dart` uses for its (much shorter) pairing
/// code, for the same transcription-friendliness reason.
const String _crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/// Recovery-code crypto call sites and generation. Every
/// cryptographic operation is delegated to [CryptoProvider] — this class
/// only encodes which key wraps which and how the user-facing secret is
/// generated/normalized, not the AEAD/Argon2id/CSPRNG primitives themselves.
abstract final class RecoveryCode {
  /// Generates a fresh BIP39 mnemonic ([wordCount] of 12 or 24 words) as the
  /// recovery secret — CSPRNG-backed via [crypto]'s own `random` (the same
  /// entropy source every other CSPRNG call site in this SDK uses).
  /// Space-separated, lowercase, the standard 2048-word English BIP-39
  /// wordlist ([bip39EnglishWordlist]) — never a non-standard wordlist.
  ///
  /// Implements the standard BIP-39 algorithm directly (entropy ||
  /// SHA-256(entropy) checksum bits, sliced into 11-bit word indices) rather
  /// than depending on the `bip39` pub package: that package pins
  /// `pointycastle ^3.x`, which conflicts with this app's `enough_mail`
  /// dependency (`pointycastle ^4.x`) — confirmed via `flutter pub get`, a
  /// real version-solver conflict, not a style preference. This is not a new
  /// cryptographic primitive — it's the same public,
  /// standardized bit-slicing algorithm every BIP-39 implementation uses,
  /// built on this SDK's existing CSPRNG and SHA-256 (`sha256Bytes`,
  /// already used elsewhere in this package) rather than inventing anything.
  static String generateBip39Words(CryptoProvider crypto, {int wordCount = 24}) {
    final strengthBits = _bip39StrengthByWordCount[wordCount];
    if (strengthBits == null) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'wordCount must be 12 or 24',
      );
    }
    final entropy = crypto.random(strengthBits ~/ 8);
    final checksumBitLength = strengthBits ~/ 32;
    final hash = sha256Bytes(entropy);
    final bits = StringBuffer()
      ..write(_bytesToBinary(entropy))
      ..write(_bytesToBinary(hash).substring(0, checksumBitLength));
    final bitString = bits.toString();
    final words = <String>[];
    for (var i = 0; i < bitString.length; i += 11) {
      final chunk = bitString.substring(i, i + 11);
      words.add(bip39EnglishWordlist[int.parse(chunk, radix: 2)]);
    }
    return words.join(' ');
  }

  static String _bytesToBinary(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(2).padLeft(8, '0')).join();

  /// Generates a fresh random alphanumeric recovery code:
  /// [lengthBytes] * 8 bits of CSPRNG output, Crockford base32-encoded
  /// (uppercase, transcription-friendly — same alphabet as
  /// `DevicePairing.generateSessionCode`, just much longer since this is a
  /// durable secret rather than a 5-minute session code).
  static String generateRandomCode(
    CryptoProvider crypto, {
    int lengthBytes = recoveryRandomCodeLengthBytes,
  }) {
    final bytes = crypto.random(lengthBytes);
    final totalBits = bytes.length * 8;
    final symbolCount = (totalBits / 5).ceil();
    var bitBuffer = 0;
    var bitsInBuffer = 0;
    var byteIndex = 0;
    final buffer = StringBuffer();
    while (buffer.length < symbolCount) {
      if (bitsInBuffer < 5 && byteIndex < bytes.length) {
        bitBuffer = (bitBuffer << 8) | bytes[byteIndex++];
        bitsInBuffer += 8;
      }
      final shift = bitsInBuffer - 5;
      final index = shift >= 0
          ? (bitBuffer >> shift) & 0x1f
          : (bitBuffer << -shift) & 0x1f;
      buffer.write(_crockfordAlphabet[index]);
      bitsInBuffer -= 5;
    }
    return buffer.toString();
  }

  /// Normalizes user-entered recovery code input before deriving REK or
  /// comparing/validating it, so trivial formatting differences (surrounding
  /// whitespace, a user typing a random code in lowercase, extra spaces
  /// between BIP39 words) don't produce a different REK than the one used at
  /// setup time. [format] is [RecoveryCodeFormats.bip39] or
  /// [RecoveryCodeFormats.random].
  static String normalize(String input, {required String format}) {
    final collapsed = input.trim().replaceAll(RegExp(r'\s+'), ' ');
    if (format == RecoveryCodeFormats.random) {
      return collapsed.replaceAll(' ', '').toUpperCase();
    }
    return collapsed.toLowerCase();
  }

  /// `REK = Argon2id(recovery_code, salt)` — reuses [CryptoProvider.deriveArgon2id] directly, the
  /// same call site [VaultExport.deriveEek] uses for EEK. [salt] should be
  /// freshly generated for every new recovery-code setup — never reused
  /// across setups, even for the same identity.
  static Future<Uint8List> deriveRek(
    CryptoProvider crypto,
    String recoveryCode,
    Uint8List salt, {
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int parallelism = argon2idDefaultParallelism,
  }) {
    return crypto.deriveArgon2id(
      utf8.encode(recoveryCode),
      salt,
      memory: memory,
      iterations: iterations,
      parallelism: parallelism,
      length: vekKeyLengthBytes,
    );
  }

  /// `AEAD_Encrypt(REK, secret)` (structurally
  /// identical to [VaultExport.wrapWithEek] — reuses [ExportEnvelope] as the
  /// wire shape rather than inventing a parallel type). Called once for VEK
  /// and, for a full-scope setup, once more for AEK — both under the same
  /// REK/salt (see [VaultExport.wrapWithEek]'s doc comment for why reusing
  /// one derivation for two AEAD calls with independent IVs is safe).
  static Future<ExportEnvelope> wrapForRecovery(
    CryptoProvider crypto,
    Uint8List rek,
    Uint8List secret, {
    required Uint8List salt,
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int parallelism = argon2idDefaultParallelism,
  }) async {
    final wrapped = await crypto.encryptAead(rek, secret);
    return ExportEnvelope(
      kdf: eekKdf,
      salt: salt,
      memory: memory,
      iterations: iterations,
      parallelism: parallelism,
      wrapped: WrappedKey(iv: wrapped.iv, ciphertext: wrapped.ciphertext),
    );
  }

  /// Inverse of [wrapForRecovery] — re-derives REK from [envelope]'s own
  /// salt/kdf params and [recoveryCode], then unwraps. A failed unwrap means
  /// either a wrong recovery code or tampering — throws
  /// [ErrorCodes.envelopeAuthenticationFailure] with no weaker fallback
  /// (mirrors [VaultExport.unwrapWithEek]/[KeyHierarchy.unwrapWithDkek]).
  static Future<Uint8List> unwrapRecovery(
    CryptoProvider crypto,
    String recoveryCode,
    ExportEnvelope envelope,
  ) async {
    final rek = await deriveRek(
      crypto,
      recoveryCode,
      envelope.salt,
      memory: envelope.memory,
      iterations: envelope.iterations,
      parallelism: envelope.parallelism,
    );
    try {
      return await crypto.decryptAead(
        rek,
        envelope.wrapped.iv,
        envelope.wrapped.ciphertext,
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to unwrap recovery envelope: wrong recovery code or tampering',
      );
    }
  }
}
