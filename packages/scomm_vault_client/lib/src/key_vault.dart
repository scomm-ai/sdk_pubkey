import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';

import 'authorization.dart';
import 'errors.dart';
import 'host_pepper_oprf.dart';
import 'local_vault_store.dart';
import 'signing.dart';
import 'vault_host_client.dart';
import 'vault_sync.dart';

/// App metadata for devices, by `slot_id` of their device slot.
const String devicesExtensionId = 'priv:scomm.devices';

/// App metadata for keys, by `absolute_key_id`, sharded over 16 extensions
/// so no single extension approaches the CKVF 64 KB limit.
const String keyMetaExtensionPrefix = 'priv:scomm.keys.';

String keyMetaExtensionId(String absoluteKeyId) =>
    '$keyMetaExtensionPrefix${(absoluteKeyId.codeUnitAt(0) % 16).toRadixString(16)}';

/// A device that holds a slot in the vault.
class VaultDevice {
  const VaultDevice({
    required this.deviceId,
    required this.name,
    this.slotId,
    this.addedAt,
  });

  factory VaultDevice.fromJson(String slotId, Map<String, dynamic> json) =>
      VaultDevice(
        slotId: slotId,
        deviceId: '${json['device_id'] ?? ''}',
        name: '${json['name'] ?? ''}',
        addedAt: json['added_at'] as String?,
      );

  final String deviceId;
  final String name;
  final String? slotId;
  final String? addedAt;

  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        'name': name,
        if (addedAt != null) 'added_at': addedAt,
      };
}

/// Where and as whom a [KeyVault] syncs.
class VaultHostBinding {
  VaultHostBinding({
    required this.host,
    required this.identityId,
    required this.authorize,
    this.licenseDeviceId,
  });

  /// Reads signed by this device's enrolled read key.
  factory VaultHostBinding.device({
    required VaultHostClient host,
    required String identityId,
    required List<int> deviceSeed,
    String? licenseDeviceId,
    required CkvfCrypto crypto,
  }) =>
      VaultHostBinding(
        host: host,
        identityId: identityId,
        licenseDeviceId: licenseDeviceId,
        authorize: (vaultId, operation) => deviceReadAuthorization(
          deviceSeed: deviceSeed,
          identityId: identityId,
          vaultId: vaultId,
          operation: operation,
          crypto: crypto,
        ),
      );

  final VaultHostClient host;

  /// 64-hex identity OPRF output (the host principal).
  final String identityId;
  final Future<VaultAuthorization> Function(String vaultId, String operation)
      authorize;
  final String? licenseDeviceId;
}

/// A local-first CKVF vault opened with this device's slot. Every change is
/// a new generation persisted to [store]; [push] and [pull] converge with
/// the host through `mergeOnto` (SPEC §12), never last-writer-wins.
class KeyVault {
  KeyVault(this.store, {required this.crypto, this.binding});

  final LocalVaultStore store;
  final CkvfCrypto crypto;
  VaultHostBinding? binding;

  /// User-controlled generation store. When set, [pull] and [push] use it
  /// instead of [binding].
  VaultSyncStore? syncStore;

  UnlockedVault? _vault;
  Future<void> _lock = Future.value();

  /// Conflicts from the last [pull], [push], or [sync].
  List<MergeConflict> lastConflicts = const [];

  bool get isOpen => _vault != null;

  UnlockedVault get vault =>
      _vault ?? (throw StateError('KeyVault is not open'));

  String get vaultId => vault.container.vaultId;
  int get generation => vault.container.generation;

  bool get mskIsHybrid =>
      vault.payload.msk.current.algorithm == 'mldsa65-ed25519';

  /// 32-byte Ed25519 seed, or 64-byte `mldsa65_seed || ed25519_seed`.
  Uint8List get mskSeed {
    final current = vault.payload.msk.current;
    final privateKey = current.privateKey;
    if (privateKey is Map) {
      final mldsa = base64urlToBytes('${privateKey['mldsa65_seed']}', 32);
      final ed = base64urlToBytes('${privateKey['ed25519_seed']}', 32);
      return Uint8List.fromList([...mldsa, ...ed]);
    }
    if (privateKey is! String) {
      throw StateError('msk private key');
    }
    final raw = base64urlToBytes(privateKey);
    if (mskIsHybrid && raw.length == 64) return raw;
    return base64urlToBytes(privateKey, 32);
  }

  Uint8List get mskPublicKey => base64urlToBytes(
        vault.payload.msk.current.publicKey,
        mskIsHybrid ? 1984 : 32,
      );
  MskSigner get signer => MskSigner(mskSeed, crypto: crypto);

  List<KeyRecord> get keys => List.unmodifiable(vault.payload.keys);

  KeyRecord? key(String absoluteKeyId) => getKey(vault, absoluteKeyId);

  Map<String, dynamic>? keyMeta(String absoluteKeyId) {
    final data =
        _extensionData(vault.payload, keyMetaExtensionId(absoluteKeyId));
    final meta = data[absoluteKeyId];
    return meta is Map ? Map<String, dynamic>.from(meta) : null;
  }

  String? preferredKey(String family, String purpose) =>
      vault.payload.preferredKeys[family]?[purpose];

  /// Devices whose slot is still in the vault.
  List<VaultDevice> get devices {
    final slots = {for (final s in vault.container.unlockSlots) s.slotId};
    final data = _extensionData(vault.payload, devicesExtensionId);
    return [
      for (final e in data.entries)
        if (slots.contains(e.key) && e.value is Map)
          VaultDevice.fromJson(
              e.key, Map<String, dynamic>.from(e.value as Map)),
    ];
  }

  Future<T> _locked<T>(Future<T> Function() body) {
    final result = _lock.then((_) => body());
    _lock = result.then((_) {}, onError: (_) {});
    return result;
  }

  // -------------------------------------------------------------------------
  // Local lifecycle.

  Future<bool> hasLocalVault() async =>
      await store.read(LocalVaultKeys.container) != null;

  /// Generation 1 with a device slot for this device.
  Future<void> create({
    required String email,
    required VaultDevice device,
    List<int>? mskSeed,
    String? now,
  }) =>
      _locked(() async {
        final kek = crypto.randomBytes(32);
        final slotId = bytesToBase64url(crypto.randomBytes(16));
        final ts = rfc3339(now);
        final v = await createVault(CreateVaultOptions(
          identityType: 'email',
          identityValue: email,
          crypto: crypto,
          mskSeed: mskSeed,
          now: ts,
          slots: (vaultId, vek) async => [
            await wrapDeviceSlot(crypto,
                vaultId: vaultId, vek: vek, kek: kek, slotId: slotId, now: ts),
          ],
          extensions: [
            Extension(
              id: devicesExtensionId,
              critical: false,
              data: {slotId: _deviceJson(device, ts)},
            ),
          ],
        ));
        await _writeDevice(kek, slotId);
        await store.write(LocalVaultKeys.syncedHash, null);
        await _persist(v);
      });

  /// Opens the stored container with this device's slot. False when this
  /// device has no vault.
  Future<bool> open() => _locked(() async {
        final json = await store.read(LocalVaultKeys.container);
        if (json == null) return false;
        _vault = await _openWithDeviceSlot(json);
        return true;
      });

  /// Takes over [opened] (from pairing, recovery, or a backup file): adds a
  /// device slot for this device and persists. Pass [storedOnHost] when
  /// [opened] is the host's current generation.
  Future<void> adopt(
    UnlockedVault opened, {
    required VaultDevice device,
    bool storedOnHost = false,
    String? now,
  }) =>
      _locked(() async {
        final kek = crypto.randomBytes(32);
        final slotId = bytesToBase64url(crypto.randomBytes(16));
        final ts = rfc3339(now);
        final slot = await wrapDeviceSlot(crypto,
            vaultId: opened.container.vaultId,
            vek: opened.vek,
            kek: kek,
            slotId: slotId,
            now: ts);
        final withDevice = UnlockedVault(
          container: opened.container,
          payload: _withExtensionEntry(
            opened.payload,
            devicesExtensionId,
            slotId,
            _deviceJson(device, ts),
          ),
          vek: opened.vek,
        );
        final v = await commitUnlockSlots(
          withDevice,
          crypto,
          [...opened.container.unlockSlots, slot],
        );
        await _writeDevice(kek, slotId);
        await store.write(
          LocalVaultKeys.syncedHash,
          storedOnHost ? opened.container.generationHash : null,
        );
        await _persist(v);
      });

  /// Replaces the Ed25519 MSK with `mldsa65-ed25519` and seals container 1.1.
  ///
  /// [seeds] is `mldsa65_seed || ed25519_seed` (64 bytes). [publicKey] is the
  /// 1,984-byte concatenation those seeds derive.
  Future<void> rotateToHybridMsk({
    required List<int> seeds,
    required List<int> publicKey,
  }) =>
      _locked(() async {
        if (!isOpen) throw StateError('KeyVault is not open');
        if (mskIsHybrid) return;
        final next = await replaceMskHybrid(
          vault,
          crypto,
          publicKey: publicKey,
          mldsaSeed: seeds.sublist(0, 32),
          edSeed: seeds.sublist(32, 64),
        );
        await _persist(next);
      });

  /// Forgets the local vault on this device (the host copy is untouched).
  Future<void> clear() => _locked(() async {
        for (final k in LocalVaultKeys.all) {
          await store.write(k, null);
        }
        _vault = null;
      });

  /// Clears this device's local vault store (same as [clear]). Does not rotate
  /// the host vault; use [revokeDevice] when another device must lose access.
  Future<void> forgetThisDevice() => clear();

  /// Applies [change] as the next local generation, then pushes when bound.
  /// Network failures leave the generation local for a later [sync].
  Future<void> commit(
    Future<UnlockedVault> Function(UnlockedVault current) change, {
    bool push = true,
  }) async {
    await _locked(() async => _persist(await change(vault)));
    if (push) await _pushQuietly();
  }

  // -------------------------------------------------------------------------
  // Keys.

  /// Imports a private key, or updates [meta] when it is already present.
  /// Returns its `absolute_key_id`.
  Future<String> importKey({
    required String family,
    required String encoding,
    required String algorithm,
    required List<String> purpose,
    required List<int> privateKey,
    required List<int> publicKey,
    Map<String, dynamic>? meta,
    String? createdAt,
    String? status,
    bool push = true,
  }) async {
    if ((encoding == 'pkcs8' || encoding == 'pkcs12') &&
        _bytesEqual(publicKey, privateKey)) {
      throw VaultClientException(
        'invalid_public_key',
        'public key must not be the private key',
      );
    }
    late String id;
    await commit((v) async {
      var next = v;
      try {
        next = await importPrivateKey(v,
            crypto: crypto,
            family: family,
            encoding: encoding,
            algorithm: algorithm,
            purpose: purpose,
            privateKey: privateKey,
            publicKey: publicKey,
            createdAt: createdAt);
        id = next.payload.keys.last.absoluteKeyId;
      } on CkvfException catch (e) {
        if (e.code != 'ERR_KEY_ID') rethrow;
        final ids = await keyIds(
          encoding == 'openpgp-tsk'
              ? canonicalOpenPgpPublicKey(publicKey, privateKey)
              : publicKey,
          crypto,
        );
        id = ids.absoluteKeyId;
      }
      if (status == 'retired' && getKey(next, id)?.status == 'active') {
        next = await retireKey(next, crypto, id);
      } else if (status == 'revoked' && getKey(next, id)?.status != 'revoked') {
        next = await revokeKey(next, crypto, id);
      }
      if (meta != null) next = await _setMeta(next, id, meta);
      return next;
    }, push: push);
    return id;
  }

  Future<void> setKeyMeta(String absoluteKeyId, Map<String, dynamic> meta) =>
      commit((v) => _setMeta(v, absoluteKeyId, meta));

  Future<void> retire(String absoluteKeyId) =>
      commit((v) => retireKey(v, crypto, absoluteKeyId));

  Future<void> revoke(String absoluteKeyId) =>
      commit((v) => revokeKey(v, crypto, absoluteKeyId));

  /// Destroys the private key; the public record and a tombstone remain.
  Future<void> deletePrivate(String absoluteKeyId,
          {String reason = 'user-requested'}) =>
      commit((v) => deletePrivateKey(v, crypto, absoluteKeyId, reason: reason));

  /// Retire a signing key and optionally point the preferred signing key at
  /// [newPreferredId]. Does not destroy private material. Call [deletePrivate]
  /// for that, as a separate authorized step.
  Future<void> rotateSigningKey(
    String absoluteKeyId, {
    String? newPreferredId,
    String family = 'smime',
    String reason = 'policy',
  }) =>
      commit((v) async {
        final key = getKey(v, absoluteKeyId);
        if (key == null) {
          throw VaultClientException(
              'key_not_found', 'no key $absoluteKeyId');
        }
        var next = v;
        if (key.status == 'active') {
          next = await retireKey(next, crypto, absoluteKeyId);
        }
        if (newPreferredId != null) {
          next = await setPreferredKey(next, crypto,
              family: family, purpose: 'sign', absoluteKeyId: newPreferredId);
        }
        return next;
      });

  Future<void> setPreferred(
          String family, String purpose, String? absoluteKeyId) =>
      commit((v) => setPreferredKey(v, crypto,
          family: family, purpose: purpose, absoluteKeyId: absoluteKeyId));

  Future<UnlockedVault> _setMeta(
    UnlockedVault v,
    String absoluteKeyId,
    Map<String, dynamic> meta,
  ) {
    final payload = _withExtensionEntry(
      v.payload,
      keyMetaExtensionId(absoluteKeyId),
      absoluteKeyId,
      meta,
    );
    return updateExtensions(v, crypto, payload.extensions);
  }

  // -------------------------------------------------------------------------
  // Devices and slots.

  /// Drops a device's slot. Its host read key should also be revoked
  /// (`revoke_device`); without a container it cannot use the old VEK.
  Future<void> removeDevice(String slotId) => commit((v) async {
        final next = await removeUnlockSlot(v, crypto, slotId);
        final data = _extensionData(next.payload, devicesExtensionId)
          ..remove(slotId);
        return updateExtensions(
          next,
          crypto,
          _replaceExtension(next.payload.extensions, devicesExtensionId, data),
        );
      });

  /// Compromised-device response: new VEK wrapped to remaining
  /// `device-hpke-x25519` recipients (public key from `priv:scomm.devices` when
  /// present; otherwise that slot is skipped), this device's local wrap kept,
  /// pepper slots dropped, and a fresh Ed25519 MSK sealed into the payload.
  ///
  /// [replaceMsk] receives the new MSK public key so the app can arm it at
  /// Discovery before [push]. Local VEK/slot/MSK changes are persisted first;
  /// if Discovery cannot be updated yet, [replaceMsk] may throw after that.
  Future<void> revokeDevice(
    String slotId, {
    required Future<void> Function(List<int> publicKey) replaceMsk,
  }) async {
    late Uint8List newMskPublic;
    await commit((v) async {
      final mySlotId = await _deviceSlotId();
      final myKek = await _deviceKek();
      if (slotId == mySlotId) {
        throw VaultClientException(
          'device_removed',
          'cannot revoke this device slot; use forgetThisDevice',
        );
      }
      final deviceData = _extensionData(v.payload, devicesExtensionId);
      final rotated = await rotateVek(v, crypto, (vaultId, vek) async {
        final next = <UnlockSlot>[
          await wrapDeviceSlot(
            crypto,
            vaultId: vaultId,
            vek: vek,
            kek: myKek,
            slotId: mySlotId,
          ),
        ];
        final wrapped = <String>{mySlotId};
        for (final slot in v.container.unlockSlots) {
          if (slot.slotId == slotId || wrapped.contains(slot.slotId)) continue;
          if (slot.method == passwordOprfMethod ||
              slot.method == recoveryCodeOprfMethod) {
            continue;
          }
          final pk = _deviceHpkePublicKey(deviceData[slot.slotId]);
          if (pk == null) continue;
          next.add(await wrapDeviceHpkeSlot(
            crypto,
            vaultId: vaultId,
            vek: vek,
            recipientPublicKey: pk,
            slotId: slot.slotId,
          ));
          wrapped.add(slot.slotId);
        }
        for (final e in deviceData.entries) {
          if (e.key == slotId || wrapped.contains(e.key)) continue;
          final pk = _deviceHpkePublicKey(e.value);
          if (pk == null) continue;
          next.add(await wrapDeviceHpkeSlot(
            crypto,
            vaultId: vaultId,
            vek: vek,
            recipientPublicKey: pk,
            slotId: e.key,
          ));
          wrapped.add(e.key);
        }
        return next;
      });
      final data = _extensionData(rotated.payload, devicesExtensionId)
        ..remove(slotId);
      final withDevices = await updateExtensions(
        rotated,
        crypto,
        _replaceExtension(
          rotated.payload.extensions,
          devicesExtensionId,
          data,
        ),
      );
      // Library helper: the [replaceMsk] parameter shadows CKVF's function.
      final withMsk = await _ckvfReplaceMsk(withDevices, crypto);
      newMskPublic = base64urlToBytes(
        withMsk.payload.msk.current.publicKey,
        32,
      );
      await store.write(
        LocalVaultKeys.pinnedMsk,
        withMsk.payload.msk.current.publicKey,
      );
      return withMsk;
    }, push: false);
    await replaceMsk(newMskPublic);
  }

  /// Wraps the current VEK with [secret] in a `password-argon2id` slot.
  /// No vault host and no pepper evaluation.
  Future<void> addOfflineSecret(String secret) => commit((v) async {
        return addUnlockSlot(v, crypto, secret);
      });

  /// Adds a `recovery-code-oprf-argon2id` slot and returns the code to show
  /// once. Earlier recovery-code slots are removed.
  Future<String> addRecoveryCode({
    required PepperOprf pepper,
    required PepperKey key,
  }) async {
    final code = generateRecoveryCode(crypto);
    await _replacePepperSlot(recoveryCodeOprfMethod, code, pepper, key);
    return code;
  }

  /// Sets the `password-oprf-argon2id` backup slot, replacing any earlier.
  Future<void> setBackupPassword(
    String password, {
    required PepperOprf pepper,
    required PepperKey key,
  }) =>
      _replacePepperSlot(passwordOprfMethod, password, pepper, key);

  Future<void> removeBackupSlots(String method) => commit((v) async {
        final kept =
            v.container.unlockSlots.where((s) => s.method != method).toList();
        if (kept.length == v.container.unlockSlots.length) return v;
        return commitUnlockSlots(v, crypto, kept);
      });

  bool hasSlot(String method) =>
      vault.container.unlockSlots.any((s) => s.method == method);

  Future<void> _replacePepperSlot(
    String method,
    String secret,
    PepperOprf pepper,
    PepperKey key,
  ) =>
      commit((v) async {
        final slot = await wrapPepperSlot(crypto,
            vaultId: v.container.vaultId,
            vek: v.vek,
            method: method,
            secret: secret,
            pepper: pepper,
            key: key);
        return commitUnlockSlots(v, crypto, [
          ...v.container.unlockSlots.where((s) => s.method != method),
          slot,
        ]);
      });

  /// New VEK; only this device's slot survives. Other devices must pair
  /// again and pepper slots must be set again (compromise response).
  Future<void> rotateVekToThisDevice() => commit((v) async {
        final kek = await _deviceKek();
        final slotId = await _deviceSlotId();
        final rotated = await rotateVek(
            v,
            crypto,
            (vaultId, vek) async => [
                  await wrapDeviceSlot(crypto,
                      vaultId: vaultId, vek: vek, kek: kek, slotId: slotId),
                ]);
        final data = _extensionData(rotated.payload, devicesExtensionId);
        data.removeWhere((k, _) => k != slotId);
        return updateExtensions(
          rotated,
          crypto,
          _replaceExtension(
              rotated.payload.extensions, devicesExtensionId, data),
        );
      });

  // -------------------------------------------------------------------------
  // Offline export / import.

  /// A detached container under a fresh VEK with one password slot. With
  /// [keyIds], only those keys (and their metadata) are included.
  Future<String> exportWithPassword(
    String password, {
    Set<String>? keyIds,
    Argon2idParams kdf = recommendedArgon2id,
  }) async {
    final v = vault;
    final tempKek = crypto.randomBytes(32);
    final rotated = await rotateVek(
        v,
        crypto,
        (vaultId, vek) async => [
              await wrapDeviceSlot(crypto,
                  vaultId: vaultId, vek: vek, kek: tempKek),
            ]);
    final tempSlot = rotated.container.unlockSlots.single.slotId;
    var payload = rotated.payload;
    payload = VaultPayload(
      identity: payload.identity,
      msk: payload.msk,
      keys: keyIds == null
          ? payload.keys
          : payload.keys
              .where((k) => keyIds.contains(k.absoluteKeyId))
              .toList(),
      preferredKeys: keyIds == null
          ? payload.preferredKeys
          : {
              for (final f in payload.preferredKeys.entries)
                f.key: {
                  for (final p in f.value.entries)
                    if (keyIds.contains(p.value)) p.key: p.value,
                },
            }
        ..removeWhere((_, m) => m.isEmpty),
      metadata: payload.metadata,
      tombstones: keyIds == null ? payload.tombstones : const [],
      extensions: [
        for (final e in payload.extensions)
          if (keyIds == null)
            e
          else if (e.id.startsWith(keyMetaExtensionPrefix) && e.data is Map)
            Extension(
              id: e.id,
              critical: false,
              data: {
                for (final m in (e.data as Map).entries)
                  if (keyIds.contains(m.key)) '${m.key}': m.value,
              },
            ),
      ],
      criticalExtensions: const [],
    );
    final withPassword = await addUnlockSlot(
      UnlockedVault(
          container: rotated.container, payload: payload, vek: rotated.vek),
      crypto,
      password,
      kdf: kdf,
    );
    final sealed = await removeUnlockSlot(withPassword, crypto, tempSlot);
    return serializeContainer(sealed.container);
  }

  /// Opens a file from [exportWithPassword].
  Future<UnlockedVault> openExport(String json, String password) =>
      openVault(json, password: password, crypto: crypto);

  /// Merges keys and metadata from an opened export into this vault. The
  /// export must belong to the same identity.
  Future<List<MergeConflict>> importExport(UnlockedVault exported) async {
    var conflicts = <MergeConflict>[];
    await commit((v) async {
      if (exported.payload.identity.identityId !=
          v.payload.identity.identityId) {
        throw VaultClientException(
            'identity_mismatch', 'export is for another identity');
      }
      final incoming = UnlockedVault(
        container: v.container,
        payload: exported.payload,
        vek: v.vek,
      );
      final merged = await _mergeNormalized(v, incoming, null);
      conflicts = merged.conflicts;
      return merged.vault;
    });
    return conflicts;
  }

  // -------------------------------------------------------------------------
  // Host sync.

  /// [pull] then [push].
  Future<void> sync() async {
    await pull();
    await push();
  }

  /// Fetches the host's current generation. With no local changes it
  /// replaces the local copy; otherwise the local copy is merged onto it.
  /// Returns whether the local vault changed.
  Future<bool> pull() => _locked(() async {
        if (syncStore != null) return _pullSync();
        final b = binding;
        if (b == null) return false;
        final read = await b.host.currentRecord(
          vaultId,
          await b.authorize(vaultId, VaultOperations.vaultGetCurrent),
        );
        final record = read.record;
        if (record == null) return false;
        final local = vault;
        if (record.generationHash == local.container.generationHash) {
          await store.write(LocalVaultKeys.syncedHash, record.generationHash);
          return false;
        }
        if (record.generation < await _syncedGeneration()) {
          throw VaultClientException(
            'generation_rollback',
            'the host returned an older generation',
          );
        }
        final head = await _openRecord(record, b.identityId);
        await _acceptMsk(head);
        final synced = await store.read(LocalVaultKeys.syncedHash);
        if (synced == local.container.generationHash) {
          await _markSynced(head);
          await _persist(head);
        } else {
          final merged = await _mergeNormalized(head, local, await _base());
          lastConflicts = merged.conflicts;
          await _persist(merged.vault);
        }
        return true;
      });

  /// Stores the local generation on the host. On `generation_conflict` it
  /// rechains onto the head this device last synced (local work advanced
  /// several generations), merges onto a head another device wrote, or
  /// restarts at generation 1 on an empty host.
  Future<void> push() => _locked(() async {
        if (syncStore != null) {
          await _pushSync();
          return;
        }
        final b = binding;
        if (b == null) return;
        for (var attempt = 0; attempt < 4; attempt++) {
          final local = vault;
          final hash = local.container.generationHash;
          if (await store.read(LocalVaultKeys.syncedHash) == hash) return;
          try {
            await b.host.putRecord(
              identityId: b.identityId,
              container: local.container,
              signer: signer,
              licenseDeviceId: b.licenseDeviceId,
            );
            await _markSynced(local);
            return;
          } on VaultClientException catch (e) {
            if (e.code != 'generation_conflict') rethrow;
            final headGeneration = e.details?['head_generation'];
            if (headGeneration == 0) {
              await _persist(await rechain(local, crypto,
                  generation: 1, previousGenerationHash: null));
              continue;
            }
            final read = await b.host.currentRecord(
              vaultId,
              await b.authorize(vaultId, VaultOperations.vaultGetCurrent),
            );
            final record = read.record;
            if (record == null) {
              await _persist(await rechain(local, crypto,
                  generation: 1, previousGenerationHash: null));
              continue;
            }
            if (record.generationHash ==
                await store.read(LocalVaultKeys.syncedHash)) {
              await _persist(await rechain(local, crypto,
                  generation: record.generation + 1,
                  previousGenerationHash: record.generationHash));
              continue;
            }
            if (record.generation < await _syncedGeneration()) {
              throw VaultClientException(
                'generation_rollback',
                'the host returned an older generation',
              );
            }
            final head = await _openRecord(record, b.identityId);
            await _acceptMsk(head);
            final merged =
                await _mergeNormalized(head, local, await _base());
            lastConflicts = merged.conflicts;
            await _persist(merged.vault);
          }
        }
        throw VaultClientException(
          'generation_conflict',
          'the host head kept moving; try again',
        );
      });

  /// Signs `/v1/mutate` [operation] with the vault MSK.
  Future<Map<String, dynamic>> hostMutation(
    String operation, [
    Map<String, dynamic> payload = const {},
  ]) async {
    final b = binding ??
        (throw VaultClientException('not_bound', 'no vault host binding'));
    return b.host.mutate(await signer.envelope(
      principal: b.identityId,
      operation: operation,
      payload: payload,
    ));
  }

  /// Registers this device's host read key (`authorize_device`).
  Future<Map<String, dynamic>> authorizeDevice({
    required String deviceId,
    required String deviceName,
    required List<int> devicePublicKey,
  }) =>
      hostMutation(VaultOperations.authorizeDevice, {
        'version': 1,
        'device_id': deviceId,
        'device_name': deviceName,
        'device_public_key': bytesToBase64url(devicePublicKey),
      });

  Future<void> _pushQuietly() async {
    if (binding == null && syncStore == null) return;
    try {
      await push();
    } on VaultClientException catch (e) {
      if (e.code != 'network_error') rethrow;
    }
  }

  Future<bool> _pullSync() async {
    final remote = syncStore!;
    final head = await remote.getHead(vaultId);
    if (head == null) return false;
    if (head.vaultId != vaultId) {
      throw VaultClientException('sync_head', 'vault id mismatch');
    }
    final local = vault;
    if (head.generationHash == local.container.generationHash) {
      await store.write(LocalVaultKeys.syncedHash, head.generationHash);
      return false;
    }
    if (head.generation < await _syncedGeneration()) {
      throw VaultClientException(
        'generation_rollback',
        'sync storage returned an older generation',
      );
    }
    final raw = await remote.getGeneration(vaultId, head.generation);
    if (raw == null) {
      throw VaultClientException('sync_missing', 'head generation is missing');
    }
    final opened = await _openWithDeviceSlot(raw);
    if (opened.container.generationHash != head.generationHash) {
      throw VaultClientException(
        'sync_tamper',
        'generation hash does not match the head',
      );
    }
    final synced = await store.read(LocalVaultKeys.syncedHash);
    if (synced == local.container.generationHash) {
      await _markSynced(opened);
      await _persist(opened);
    } else {
      final merged = await _mergeNormalized(opened, local, await _base());
      lastConflicts = merged.conflicts;
      await _persist(merged.vault);
    }
    return true;
  }

  Future<void> _pushSync() async {
    final remote = syncStore!;
    for (var attempt = 0; attempt < 4; attempt++) {
      final local = vault;
      final hash = local.container.generationHash;
      if (await store.read(LocalVaultKeys.syncedHash) == hash) return;
      final head = await remote.getHead(vaultId);
      if (head != null && head.generationHash == hash) {
        await _markSynced(local);
        return;
      }
      if (head != null &&
          head.generation < await _syncedGeneration() &&
          head.generationHash != local.container.previousGenerationHash) {
        throw VaultClientException(
          'generation_rollback',
          'sync storage returned an older generation',
        );
      }
      final parentMatches = head == null
          ? local.container.generation == 1
          : local.container.previousGenerationHash == head.generationHash;
      if (parentMatches) {
        await remote.putIfAbsent(
          vaultId,
          local.container.generation,
          serializeContainer(local.container),
        );
        final ok = await remote.compareAndSwapHead(
          next: VaultHead(
            vaultId: vaultId,
            generation: local.container.generation,
            generationHash: hash,
          ),
          expectedHash: head?.generationHash,
        );
        if (!ok) continue;
        await _markSynced(local);
        return;
      }
      if (head == null) {
        await _persist(await rechain(
          local,
          crypto,
          generation: 1,
          previousGenerationHash: null,
        ));
        continue;
      }
      final raw = await remote.getGeneration(vaultId, head.generation);
      if (raw == null) {
        throw VaultClientException('sync_missing', 'head generation is missing');
      }
      if (head.generationHash == await store.read(LocalVaultKeys.syncedHash)) {
        await _persist(await rechain(
          local,
          crypto,
          generation: head.generation + 1,
          previousGenerationHash: head.generationHash,
        ));
        continue;
      }
      final opened = await _openWithDeviceSlot(raw);
      final merged = await _mergeNormalized(opened, local, await _base());
      lastConflicts = merged.conflicts;
      await _persist(merged.vault);
    }
    throw VaultClientException(
      'generation_conflict',
      'the sync head kept moving; try again',
    );
  }

  // -------------------------------------------------------------------------
  // Internals.

  Future<UnlockedVault> _openRecord(
      VaultRecord record, String identityId) async {
    final UnlockedVault head;
    try {
      head = await _openWithDeviceSlot(record.container);
    } on CkvfException catch (e) {
      if (e.code == 'ERR_SLOT_ID') {
        throw VaultClientException(
          'device_removed',
          'this device no longer has a slot in the stored vault',
        );
      }
      rethrow;
    }
    await verifyRecordSignature(record, head, identityId, crypto);
    return head;
  }

  Future<UnlockedVault> _openWithDeviceSlot(Object container) async =>
      openVaultWithDeviceKek(
        container,
        slotId: await _deviceSlotId(),
        kek: await _deviceKek(),
        crypto: crypto,
      );

  Future<Uint8List> _deviceKek() async {
    final raw = await store.read(LocalVaultKeys.deviceKek);
    if (raw == null) {
      throw VaultClientException(
          'device_removed', 'no device key on this device');
    }
    return base64urlToBytes(raw, 32);
  }

  Future<String> _deviceSlotId() async {
    final id = await store.read(LocalVaultKeys.deviceSlotId);
    if (id == null) {
      throw VaultClientException(
          'device_removed', 'no device slot on this device');
    }
    return id;
  }

  Future<void> _writeDevice(List<int> kek, String slotId) async {
    await store.write(LocalVaultKeys.deviceKek, bytesToBase64url(kek));
    await store.write(LocalVaultKeys.deviceSlotId, slotId);
  }

  Future<void> _persist(UnlockedVault v) async {
    await store.write(
        LocalVaultKeys.container, serializeContainer(v.container));
    _vault = v;
  }

  /// Unions map-valued `priv:scomm.*` extensions (entries from [local] win)
  /// so the SPEC §12 merge sees no extension conflict for app metadata.
  Future<int> _syncedGeneration() async {
    final raw = await store.read(LocalVaultKeys.syncedContainer);
    if (raw == null) return 0;
    try {
      final decoded = jsonDecode(raw);
      final generation = decoded is Map ? decoded['generation'] : null;
      if (generation is int && generation > 0) return generation;
    } catch (_) {}
    return 0;
  }

  Future<UnlockedVault?> _base() async {
    final raw = await store.read(LocalVaultKeys.syncedContainer);
    if (raw == null) return null;
    try {
      return await _openWithDeviceSlot(raw);
    } catch (_) {
      return null;
    }
  }

  Future<void> _markSynced(UnlockedVault v) async {
    await store.write(LocalVaultKeys.syncedHash, v.container.generationHash);
    await store.write(
      LocalVaultKeys.syncedContainer,
      serializeContainer(v.container),
    );
    await store.write(
      LocalVaultKeys.pinnedMsk,
      v.payload.msk.current.publicKey,
    );
  }

  Future<void> _acceptMsk(UnlockedVault opened) async {
    final pinned = await store.read(LocalVaultKeys.pinnedMsk);
    final current = opened.payload.msk.current.publicKey;
    if (pinned != null && pinned != current) {
      throw VaultClientException(
        'msk_changed',
        'the stored MSK changed; confirm it with Discovery before syncing',
      );
    }
  }

  Future<({UnlockedVault vault, List<MergeConflict> conflicts})>
      _mergeNormalized(
    UnlockedVault head,
    UnlockedVault local,
    UnlockedVault? base,
  ) {
    final ids = {
      for (final e in [...head.payload.extensions, ...local.payload.extensions])
        if (e.id.startsWith('priv:scomm.')) e.id,
    };
    var headPayload = head.payload;
    var localPayload = local.payload;
    for (final id in ids) {
      final merged = {
        ..._extensionData(head.payload, id),
        ..._extensionData(local.payload, id),
      };
      headPayload = _withExtensions(
          headPayload, _replaceExtension(headPayload.extensions, id, merged));
      localPayload = _withExtensions(
          localPayload, _replaceExtension(localPayload.extensions, id, merged));
    }
    return mergeOnto(
      UnlockedVault(
          container: head.container, payload: headPayload, vek: head.vek),
      UnlockedVault(
          container: local.container, payload: localPayload, vek: local.vek),
      crypto,
      null,
      base,
    );
  }

  static Map<String, dynamic> _deviceJson(VaultDevice device, String ts) => {
        'device_id': device.deviceId,
        'name': device.name,
        'added_at': device.addedAt ?? ts,
      };
}

/// Recovery on a device without a slot: reads the host's current container
/// with [authorization] (a `recovery_generation` or `vault_backup` grant)
/// and opens its [method] slot with [secret] through the returned
/// `oprf_token`. Adopt the result with [KeyVault.adopt] (`storedOnHost`).
Future<UnlockedVault> openHostVaultWithSecret({
  required VaultHostClient host,
  required String vaultId,
  required String identityId,
  required VaultAuthorization authorization,
  required String secret,
  String method = recoveryCodeOprfMethod,
  required CkvfCrypto crypto,
}) async {
  final c = crypto;
  final read = await host.currentRecord(vaultId, authorization);
  final record = read.record;
  final token = read.oprfToken;
  if (record == null) {
    throw VaultClientException('vault_not_synced', 'the host stores no vault');
  }
  if (token == null) {
    throw VaultClientException('bad_response', 'no oprf_token with the read');
  }
  final opened = await openVaultWithPepper(
    record.container,
    secret: secret,
    pepper: HostPepperOprf(host, VaultAuthorization.oprfToken(token)),
    crypto: c,
    method: method,
  );
  await verifyRecordSignature(record, opened, identityId, c);
  return opened;
}

/// Checks a stored record's `msk_signature` against the MSKs inside the
/// decrypted payload (current, then history).
Future<void> verifyRecordSignature(
  VaultRecord record,
  UnlockedVault opened,
  String identityId,
  CkvfCrypto crypto,
) async {
  final text = utf8.encode(vaultRecordsSigningText(
    identityId: identityId,
    vaultId: record.container.vaultId,
    generation: record.generation,
    generationHash: record.generationHash,
  ));
  final pk = opened.payload.msk.current.publicKey;
  if (await verifyArmedMsk(
    publicKey: base64urlToBytes(pk),
    message: text,
    signature: record.mskSignature,
  )) {
    return;
  }
  throw VaultClientException(
      'invalid_signature', 'record msk_signature is invalid');
}

Map<String, dynamic> _extensionData(VaultPayload payload, String id) {
  for (final e in payload.extensions) {
    if (e.id == id && e.data is Map)
      return Map<String, dynamic>.from(e.data as Map);
  }
  return <String, dynamic>{};
}

List<Extension> _replaceExtension(
  List<Extension> extensions,
  String id,
  Map<String, dynamic> data,
) {
  final out = [
    for (final e in extensions)
      if (e.id != id) e
  ];
  if (data.isNotEmpty) out.add(Extension(id: id, critical: false, data: data));
  out.sort((a, b) => a.id.compareTo(b.id));
  return out;
}

VaultPayload _withExtensions(VaultPayload p, List<Extension> extensions) =>
    VaultPayload(
      identity: p.identity,
      msk: p.msk,
      keys: p.keys,
      preferredKeys: p.preferredKeys,
      metadata: p.metadata,
      tombstones: p.tombstones,
      extensions: extensions,
      criticalExtensions: p.criticalExtensions,
    );

VaultPayload _withExtensionEntry(
  VaultPayload p,
  String id,
  String key,
  Map<String, dynamic> value,
) {
  final data = _extensionData(p, id)..[key] = value;
  return _withExtensions(p, _replaceExtension(p.extensions, id, data));
}

Future<UnlockedVault> _ckvfReplaceMsk(
  UnlockedVault unlocked,
  CkvfCrypto crypto, [
  String? now,
]) =>
    replaceMsk(unlocked, crypto, now);

Uint8List? _deviceHpkePublicKey(Object? entry) {
  if (entry is! Map) return null;
  final raw = entry['public_key'];
  if (raw is! String || raw.isEmpty) return null;
  try {
    return base64urlToBytes(raw, 32);
  } catch (_) {
    return null;
  }
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
