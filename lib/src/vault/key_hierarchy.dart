import 'dart:typed_data';

import '../canonical.dart';
import '../crypto/provider.dart';
import '../errors.dart';

// SComm key hierarchy (VEK / AEK / DKEK).
//
// AEK, VEK, and DKEK are always raw CSPRNG symmetric keys — never derived
// from a password, OTP, or email (Boundary B1) — and move between devices
// only as AEAD-wrapped envelopes, never in raw form (B2/B3). This file only
// wires those structural rules onto the existing [CryptoProvider] AEAD/CSPRNG
// primitives; it does not implement any new encryption primitive itself.

const int aekKeyLengthBytes = 32;
const int vekKeyLengthBytes = 32;
const int dkekKeyLengthBytes = 32;

/// An AEAD-wrapped key or private-key blob. Opaque bytes only — safe to
/// store on a device, or (once placed in a `VaultRecord` envelope) upload to
/// the server, since it can only be opened with the wrapping key.
class WrappedKey {
  const WrappedKey({required this.iv, required this.ciphertext});

  final Uint8List iv;
  final Uint8List ciphertext;

  Map<String, dynamic> toJson() => {
        'iv': encodeBase64Url(iv),
        'ciphertext': encodeBase64Url(ciphertext),
      };

  factory WrappedKey.fromJson(Map<String, dynamic> json) => WrappedKey(
        iv: decodeBase64Url(json['iv'] as String),
        ciphertext: decodeBase64Url(json['ciphertext'] as String),
      );
}

/// Generation and wrap/unwrap call sites for the CKVF key hierarchy
/// (MSK/AEK/VEK/DKEK). Every cryptographic operation is delegated to
/// [CryptoProvider] — this class only encodes the structural rule for which
/// key wraps which, not the AEAD/CSPRNG primitives themselves.
abstract final class KeyHierarchy {
  /// AEK: 256-bit CSPRNG. Wraps the MSK private key inside the vault.
  /// Possessing AEK = possessing root identity authority.
  static Uint8List generateAek(CryptoProvider crypto) =>
      crypto.random(aekKeyLengthBytes);

  /// VEK: 256-bit CSPRNG. Wraps the entire vault payload.
  static Uint8List generateVek(CryptoProvider crypto) =>
      crypto.random(vekKeyLengthBytes);

  /// DKEK: 256-bit CSPRNG, one per device. Wraps this device's local copy of
  /// VEK (and AEK, on full-authority devices). Persistence in secure
  /// hardware/storage is out of scope here.
  static Uint8List generateDkek(CryptoProvider crypto) =>
      crypto.random(dkekKeyLengthBytes);

  /// `DeviceEnvelope = Encrypt(DKEK, VEK)` / `AuthorityEnvelope = Encrypt(DKEK, AEK)`.
  static Future<WrappedKey> wrapWithDkek(
    CryptoProvider crypto,
    Uint8List dkek,
    Uint8List keyToWrap,
  ) async {
    final wrapped = await crypto.encryptAead(dkek, keyToWrap);
    return WrappedKey(iv: wrapped.iv, ciphertext: wrapped.ciphertext);
  }

  /// Recovers VEK or AEK from a device-local envelope. A failed unwrap means
  /// either the wrong DKEK or tampering —
  /// callers must not fall back to any weaker path on failure.
  static Future<Uint8List> unwrapWithDkek(
    CryptoProvider crypto,
    Uint8List dkek,
    WrappedKey envelope,
  ) async {
    try {
      return await crypto.decryptAead(dkek, envelope.iv, envelope.ciphertext);
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to unwrap device envelope: wrong DKEK or tampering',
      );
    }
  }

  /// `encrypted_msk_private_key = AEAD_Encrypt(AEK, msk_private_key_bytes)`
  /// A device holding only VEK (no AEK) must never be able to
  /// reverse this step (Boundary B4) — enforced structurally: this call
  /// requires the raw AEK, which a VEK-only device never has.
  static Future<WrappedKey> wrapMskWithAek(
    CryptoProvider crypto,
    Uint8List aek,
    Uint8List mskPrivateKeyBytes,
  ) async {
    final wrapped = await crypto.encryptAead(aek, mskPrivateKeyBytes);
    return WrappedKey(iv: wrapped.iv, ciphertext: wrapped.ciphertext);
  }

  static Future<Uint8List> unwrapMskWithAek(
    CryptoProvider crypto,
    Uint8List aek,
    WrappedKey envelope,
  ) async {
    try {
      return await crypto.decryptAead(aek, envelope.iv, envelope.ciphertext);
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to unwrap MSK envelope: wrong AEK or tampering',
      );
    }
  }

  /// `VaultCiphertext = AEAD_Encrypt(VEK, Serialize(VaultPlaintext))`.
  static Future<WrappedKey> encryptVaultPlaintextWithVek(
    CryptoProvider crypto,
    Uint8List vek,
    Uint8List serializedPlaintext,
  ) async {
    final wrapped = await crypto.encryptAead(vek, serializedPlaintext);
    return WrappedKey(iv: wrapped.iv, ciphertext: wrapped.ciphertext);
  }

  static Future<Uint8List> decryptVaultCiphertextWithVek(
    CryptoProvider crypto,
    Uint8List vek,
    WrappedKey ciphertext,
  ) async {
    try {
      return await crypto.decryptAead(
        vek,
        ciphertext.iv,
        ciphertext.ciphertext,
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to decrypt vault ciphertext: wrong VEK or tampering',
      );
    }
  }
}
