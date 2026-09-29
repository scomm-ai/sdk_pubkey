/// Device-local storage for a [KeyVault]. Values are strings; the device KEK
/// is secret and belongs in platform secure storage.
abstract interface class LocalVaultStore {
  Future<String?> read(String key);

  /// A null [value] deletes [key].
  Future<void> write(String key, String? value);
}

/// Keys a [KeyVault] reads and writes.
abstract final class LocalVaultKeys {
  /// CKVF container JSON (JCS).
  static const container = 'container';

  /// Base64url 32-byte KEK of this device's `device-wrap-a256gcm` slot.
  static const deviceKek = 'device_kek';
  static const deviceSlotId = 'device_slot_id';

  /// `generation_hash` of the container last confirmed stored on the host.
  static const syncedHash = 'synced_hash';

  /// Container JSON of that same generation, used as the merge base.
  static const syncedContainer = 'synced_container';

  /// Base64url public key of the MSK this device last accepted.
  static const pinnedMsk = 'pinned_msk';

  static const all = [
    container,
    deviceKek,
    deviceSlotId,
    syncedHash,
    syncedContainer,
    pinnedMsk,
  ];
}

class MemoryLocalVaultStore implements LocalVaultStore {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String? value) async {
    if (value == null) {
      values.remove(key);
    } else {
      values[key] = value;
    }
  }
}
