import 'dart:typed_data';

import '../crypto/provider.dart';

/// Persistence for a locked Vault ciphertext. Platform-specific.
abstract class VaultStore {
  Future<Map<String, dynamic>?> load();

  Future<void> save(Map<String, dynamic> record);

  Future<void> clear();
}

class MemoryVaultStore extends VaultStore {
  Map<String, dynamic>? record;

  @override
  Future<Map<String, dynamic>?> load() async => record;

  @override
  Future<void> save(Map<String, dynamic> record) async {
    this.record = record;
  }

  @override
  Future<void> clear() async {
    record = null;
  }
}

/// Device-local key storage required by `PubkeyRuntime`, beyond the plain
/// Vault-ciphertext persistence [VaultStore] already covers.
///
/// Extends [VaultStore] because the runtime needs both: the locked Vault
/// blob itself, and the device's local key material (DKEK-wrapped VEK/AEK,
/// device id, full-authority status) used to unlock it. Platform-specific
/// implementations (e.g. secure-storage-backed) implement this directly;
/// [MemoryDeviceKeyStore] is the pure-Dart fake for tests and standalone use.
abstract class DeviceKeyStore implements VaultStore {
  /// Returns this device's DKEK, generating and persisting one on first use.
  Future<Uint8List> ensureDkek(CryptoProvider crypto);

  /// Recovers VEK from this device's DKEK-wrapped envelope, or `null` if
  /// this device has never been paired.
  Future<Uint8List?> getVek(CryptoProvider crypto);

  /// Stores VEK as a fresh DKEK-wrapped envelope.
  Future<void> setVek(CryptoProvider crypto, Uint8List vek);

  /// Recovers AEK from this device's DKEK-wrapped envelope, or `null` if
  /// this device is limited-tier (no authority).
  Future<Uint8List?> getAek(CryptoProvider crypto);

  /// Stores AEK as a fresh DKEK-wrapped envelope. Only call for
  /// full-authority devices.
  Future<void> setAek(CryptoProvider crypto, Uint8List aek);

  /// Durably stages a VEK/AEK rotation **without** replacing the live
  /// envelopes. [PubkeyRuntime] uploads the new generation, then
  /// [commitPendingEnvelopeRotation]. If the process dies between those
  /// steps, [loadPendingEnvelopeRotation] still has the only copy of the
  /// new key.
  Future<void> stagePendingEnvelopeRotation(
    CryptoProvider crypto, {
    Uint8List? vek,
    Uint8List? aek,
  });

  /// Staged VEK/AEK from an in-flight envelope rotation, or `null`.
  Future<PendingEnvelopeRotation?> loadPendingEnvelopeRotation(
    CryptoProvider crypto,
  );

  /// Copies staged VEK/AEK into the live slots, then drops the pending
  /// record. Safe to retry: a later success still overwrites live with the
  /// same staged bytes.
  Future<void> commitPendingEnvelopeRotation(CryptoProvider crypto);

  /// Drops a staged rotation that never landed on the server.
  Future<void> discardPendingEnvelopeRotation();

  /// Whether this device holds an AEK envelope — the structural definition
  /// of "full-authority".
  Future<bool> isFullAuthority();

  /// Returns this device's local id, generating and persisting one on first
  /// use (idempotent).
  Future<String> ensureDeviceId(CryptoProvider crypto);

  /// OPRF `identity_id` (64 hex). Null until enroll verify or rebind.
  Future<String?> getIdentityId();

  Future<void> setIdentityId(String identityId);

  /// Random public vault locator. Null until enroll verify or rebind.
  Future<String?> getVaultId();

  Future<void> setVaultId(String vaultId);

  /// Local record that a recovery envelope was stored. v2 does not probe
  /// pubkey for existence.
  Future<bool> hasLocalRecoveryEnvelope();

  Future<void> setLocalRecoveryEnvelope(bool present);
}

/// Staged VEK and/or AEK waiting to replace the live device envelopes
/// after a server-accepted vault rotation.
class PendingEnvelopeRotation {
  const PendingEnvelopeRotation({this.vek, this.aek});

  final Uint8List? vek;
  final Uint8List? aek;
}

/// Pure-Dart, in-memory [DeviceKeyStore] — for tests and standalone use
/// outside a Flutter host app. Not persisted across process restarts.
class MemoryDeviceKeyStore extends MemoryVaultStore implements DeviceKeyStore {
  Uint8List? _dkek;
  Uint8List? _vek;
  Uint8List? _aek;
  PendingEnvelopeRotation? _pendingRotation;
  String? _deviceId;
  String? _identityId;
  String? _vaultId;
  bool _localRecoveryEnvelope = false;

  @override
  Future<Uint8List> ensureDkek(CryptoProvider crypto) async {
    return _dkek ??= crypto.random(32);
  }

  @override
  Future<Uint8List?> getVek(CryptoProvider crypto) async => _vek;

  @override
  Future<void> setVek(CryptoProvider crypto, Uint8List vek) async {
    _vek = vek;
  }

  @override
  Future<Uint8List?> getAek(CryptoProvider crypto) async => _aek;

  @override
  Future<void> setAek(CryptoProvider crypto, Uint8List aek) async {
    _aek = aek;
  }

  @override
  Future<void> stagePendingEnvelopeRotation(
    CryptoProvider crypto, {
    Uint8List? vek,
    Uint8List? aek,
  }) async {
    _pendingRotation = PendingEnvelopeRotation(vek: vek, aek: aek);
  }

  @override
  Future<PendingEnvelopeRotation?> loadPendingEnvelopeRotation(
    CryptoProvider crypto,
  ) async =>
      _pendingRotation;

  @override
  Future<void> commitPendingEnvelopeRotation(CryptoProvider crypto) async {
    final pending = _pendingRotation;
    if (pending == null) return;
    if (pending.vek != null) _vek = pending.vek;
    if (pending.aek != null) _aek = pending.aek;
    _pendingRotation = null;
  }

  @override
  Future<void> discardPendingEnvelopeRotation() async {
    _pendingRotation = null;
  }

  @override
  Future<bool> isFullAuthority() async => _aek != null;

  @override
  Future<String> ensureDeviceId(CryptoProvider crypto) async {
    if (_deviceId != null) return _deviceId!;
    final bytes = crypto.random(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return _deviceId =
        '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-'
        '${hex.substring(16, 20)}-${hex.substring(20, 32)}';
  }

  @override
  Future<String?> getIdentityId() async => _identityId;

  @override
  Future<void> setIdentityId(String identityId) async {
    _identityId = identityId;
  }

  @override
  Future<String?> getVaultId() async => _vaultId;

  @override
  Future<void> setVaultId(String vaultId) async {
    _vaultId = vaultId;
  }

  @override
  Future<bool> hasLocalRecoveryEnvelope() async => _localRecoveryEnvelope;

  @override
  Future<void> setLocalRecoveryEnvelope(bool present) async {
    _localRecoveryEnvelope = present;
  }

  @override
  Future<void> clear() async {
    await super.clear();
    _dkek = null;
    _vek = null;
    _aek = null;
    _pendingRotation = null;
    _deviceId = null;
    _identityId = null;
    _vaultId = null;
    _localRecoveryEnvelope = false;
  }
}
