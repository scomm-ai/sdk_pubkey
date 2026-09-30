import 'openssl_ckvf.dart';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

import 'fake_host.dart';

const identityId =
    'abababababababababababababababababababababababababababababababab';

void main() {
  final crypto = OpensslCkvfCrypto();
  late FakeVaultHost host;

  VaultHostBinding bind() => VaultHostBinding(
        host: host,
        identityId: identityId,
        authorize: (_, __) async => VaultAuthorization.device('test'),
      );

  Future<KeyVault> newVault({String name = 'Laptop'}) async {
    final v =
        KeyVault(MemoryLocalVaultStore(), crypto: crypto, binding: bind());
    await v.create(
      email: 'alice@example.com',
      device: VaultDevice(deviceId: 'dev-$name', name: name),
    );
    return v;
  }

  Future<String> addKey(KeyVault v, {Map<String, dynamic>? meta}) async {
    final pair = await crypto.ed25519Generate();
    return v.importKey(
      family: 'smime',
      encoding: 'pkcs8',
      algorithm: 'Ed25519',
      purpose: const ['sign'],
      privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
      publicKey: buildSpkiEd25519(pair.publicKey),
      meta: meta,
    );
  }

  /// A second device that opened the host copy through a pepper-free path.
  Future<KeyVault> secondDevice(KeyVault first) async {
    final other =
        KeyVault(MemoryLocalVaultStore(), crypto: crypto, binding: bind());
    final head = await openVaultWith(
      host.records.last['container'] as Map<String, dynamic>,
      crypto: crypto,
      unwrap: (_) async => Uint8List.fromList(first.vault.vek),
    );
    await other.adopt(
      head,
      device: const VaultDevice(deviceId: 'dev-phone', name: 'Phone'),
      storedOnHost: true,
    );
    await other.push();
    await first.pull();
    return other;
  }

  setUp(() => host = FakeVaultHost(crypto));

  test('create, reopen with the device slot, keep key metadata', () async {
    final store = MemoryLocalVaultStore();
    final v = KeyVault(store, crypto: crypto);
    await v.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'd1', name: 'Laptop'),
    );
    final id = await addKey(v, meta: {'fingerprint': 'F1'});
    await v.setPreferred('smime', 'sign', id);

    final reopened = KeyVault(store, crypto: crypto);
    expect(await reopened.open(), isTrue);
    expect(reopened.keyMeta(id), {'fingerprint': 'F1'});
    expect(reopened.preferredKey('smime', 'sign'), id);
    expect(reopened.devices.single.name, 'Laptop');
    expect(reopened.key(id)!.metadata, isEmpty);
  });

  test('importing a present key updates metadata and status only', () async {
    final v = await newVault();
    final pair = await crypto.ed25519Generate();
    Future<String> put(Map<String, dynamic> meta, [String? status]) =>
        v.importKey(
          family: 'smime',
          encoding: 'pkcs8',
          algorithm: 'Ed25519',
          purpose: const ['sign'],
          privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
          publicKey: buildSpkiEd25519(pair.publicKey),
          meta: meta,
          status: status,
        );
    final a = await put({'v': 1});
    final b = await put({'v': 2}, 'retired');
    expect(b, a);
    expect(v.keys, hasLength(1));
    expect(v.keyMeta(a), {'v': 2});
    expect(v.key(a)!.status, 'retired');
  });

  test('a local-only chain restarts at generation 1 on first push', () async {
    final v = KeyVault(MemoryLocalVaultStore(), crypto: crypto);
    await v.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'd1', name: 'Laptop'),
    );
    await addKey(v);
    await addKey(v);
    expect(v.generation, greaterThan(1));
    v.binding = bind();
    await v.push();
    expect(host.records.single['generation'], 1);
    expect(v.generation, 1);
    expect(v.keys, hasLength(2));
  });

  test('concurrent edits on two devices merge instead of overwriting',
      () async {
    final laptop = await newVault();
    await laptop.push();
    final phone = await secondDevice(laptop);
    expect(laptop.devices.map((d) => d.name), containsAll(['Laptop', 'Phone']));

    host.offline = true;
    final fromLaptop = await addKey(laptop, meta: {'by': 'laptop'});
    final fromPhone = await addKey(phone, meta: {'by': 'phone'});
    host.offline = false;

    await laptop.push();
    await phone.push();
    await laptop.pull();

    for (final v in [laptop, phone]) {
      expect(v.keys.map((k) => k.absoluteKeyId),
          containsAll([fromLaptop, fromPhone]));
      expect(v.keyMeta(fromLaptop), {'by': 'laptop'});
      expect(v.keyMeta(fromPhone), {'by': 'phone'});
    }
    expect(phone.generation, host.records.last['generation']);
    expect(laptop.vault.container.generationHash,
        host.records.last['generation_hash']);
  });

  test('a removed device learns it on the next pull', () async {
    final laptop = await newVault();
    await laptop.push();
    final phone = await secondDevice(laptop);
    final phoneSlot =
        laptop.devices.firstWhere((d) => d.name == 'Phone').slotId!;
    await laptop.removeDevice(phoneSlot);
    expect(laptop.devices.map((d) => d.name), ['Laptop']);
    await expectLater(
      phone.pull(),
      throwsA(isA<VaultClientException>()
          .having((e) => e.code, 'code', 'device_removed')),
    );
  });

  test('VEK rotation keeps only this device', () async {
    final laptop = await newVault();
    await laptop.push();
    final phone = await secondDevice(laptop);
    final before = laptop.vault.vek;
    await laptop.rotateVekToThisDevice();
    expect(laptop.vault.vek, isNot(before));
    expect(laptop.devices.map((d) => d.name), ['Laptop']);
    await expectLater(phone.pull(), throwsA(isA<VaultClientException>()));
  });

  test('a filtered export holds only the chosen keys under a fresh VEK',
      () async {
    final v = await newVault();
    final keep = await addKey(v, meta: {'n': 1});
    final drop = await addKey(v, meta: {'n': 2});
    final file = await v.exportWithPassword(
      'correct horse battery',
      keyIds: {keep},
      kdf: testArgon2id,
    );
    expect(inspectPublicMetadata(file)['unlock_methods'],
        [containsPair('method', 'password-argon2id')]);
    final opened = await v.openExport(file, 'correct horse battery');
    expect(opened.vek, isNot(v.vault.vek));
    expect(opened.payload.keys.map((k) => k.absoluteKeyId), [keep]);
    expect(opened.payload.extensions.toString(), isNot(contains(drop)));
  });

  test('export and import between devices of one vault', () async {
    final laptop = await newVault();
    await laptop.push();
    final phone = await secondDevice(laptop);
    host.offline = true;
    final id = await addKey(laptop, meta: {'n': 1});
    final file = await laptop.exportWithPassword('correct horse battery',
        kdf: testArgon2id);
    final opened = await phone.openExport(file, 'correct horse battery');
    final conflicts = await phone.importExport(opened);
    expect(conflicts, isEmpty);
    expect(phone.keyMeta(id), {'n': 1});
    expect(phone.devices.map((d) => d.name), containsAll(['Laptop', 'Phone']));
  });

  test('hostMutation signs with the vault MSK for the identity', () async {
    final v = await newVault();
    await v.authorizeDevice(
      deviceId: 'dev-1',
      deviceName: 'Laptop',
      devicePublicKey: List.filled(32, 7),
    );
    final env = host.mutations.single;
    expect(env['operation'], 'authorize_device');
    expect(env['principal'], identityId);
    expect((env['payload'] as Map)['device_id'], 'dev-1');
  });

  test('rotateSigningKey retires and keeps private material', () async {
    final v = await newVault();
    final oldId = await addKey(v);
    final pair = await crypto.ed25519Generate();
    final newId = await v.importKey(
      family: 'smime',
      encoding: 'pkcs8',
      algorithm: 'Ed25519',
      purpose: const ['sign'],
      privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
      publicKey: buildSpkiEd25519(pair.publicKey),
    );
    await v.rotateSigningKey(oldId, newPreferredId: newId, family: 'smime');
    expect(v.key(oldId)!.status, 'retired');
    expect(v.key(oldId)!.privateKey, isNotNull);
    expect(v.preferredKey('smime', 'sign'), newId);
    expect(v.vault.payload.tombstones, isEmpty);
  });

  test('importKey rejects pkcs8 when publicKey equals privateKey', () async {
    final v = await newVault();
    final secret = List<int>.filled(48, 7);
    await expectLater(
      v.importKey(
        family: 'smime',
        encoding: 'pkcs8',
        algorithm: 'unknown',
        purpose: const ['encrypt'],
        privateKey: secret,
        publicKey: secret,
      ),
      throwsA(isA<VaultClientException>()
          .having((e) => e.code, 'code', 'invalid_public_key')),
    );
  });

  test('revokeDevice drops the slot and pepper slots, keeps this device',
      () async {
    final fast = _FastKdfCrypto();
    final store = MemoryLocalVaultStore();
    final v = KeyVault(store, crypto: fast);
    await v.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'dev-laptop', name: 'Laptop'),
    );
    final mySlot = (await store.read(LocalVaultKeys.deviceSlotId))!;
    final other = await fast.x25519Generate();
    final otherSlotId = bytesToBase64url(fast.randomBytes(16));
    final pepper = _FakePepperHost({'k1': List.filled(32, 0x11)});
    final pepperKey = PepperKey(
      kid: 'k1',
      publicKey: Uint8List.fromList(List.filled(32, 0x42)),
    );

    await v.commit((current) async {
      final passwordSlot = await wrapPepperSlot(
        fast,
        vaultId: current.container.vaultId,
        vek: current.vek,
        method: passwordOprfMethod,
        secret: 'backup-password',
        pepper: pepper,
        key: pepperKey,
        kdf: pepperMinArgon2id,
      );
      final recoverySlot = await wrapPepperSlot(
        fast,
        vaultId: current.container.vaultId,
        vek: current.vek,
        method: recoveryCodeOprfMethod,
        secret: generateRecoveryCode(fast),
        pepper: pepper,
        key: pepperKey,
        kdf: pepperMinArgon2id,
      );
      final hpke = await wrapDeviceHpkeSlot(
        fast,
        vaultId: current.container.vaultId,
        vek: current.vek,
        recipientPublicKey: other.publicKey,
        slotId: otherSlotId,
      );
      final devices = _extensionData(current.payload, devicesExtensionId);
      devices[otherSlotId] = {
        'device_id': 'dev-phone',
        'name': 'Phone',
        'added_at': rfc3339(null),
        'public_key': bytesToBase64url(other.publicKey),
      };
      final withDevices = UnlockedVault(
        container: current.container,
        payload: _withExtensions(
          current.payload,
          _replaceExtension(
            current.payload.extensions,
            devicesExtensionId,
            devices,
          ),
        ),
        vek: current.vek,
      );
      return commitUnlockSlots(withDevices, fast, [
        ...current.container.unlockSlots,
        passwordSlot,
        recoverySlot,
        hpke,
      ]);
    }, push: false);

    expect(
      v.vault.container.unlockSlots.map((s) => s.method),
      containsAll([
        passwordOprfMethod,
        recoveryCodeOprfMethod,
        deviceHpkeMethod,
      ]),
    );
    final oldMsk = v.mskPublicKey;

    var replaceCalled = false;
    await v.revokeDevice(otherSlotId, replaceMsk: (pk) async {
      replaceCalled = true;
      expect(pk, hasLength(32));
      expect(pk, isNot(oldMsk));
    });

    expect(replaceCalled, isTrue);
    expect(v.vault.container.unlockSlots.map((s) => s.slotId), [mySlot]);
    expect(
      v.vault.container.unlockSlots.any((s) =>
          s.method == passwordOprfMethod ||
          s.method == recoveryCodeOprfMethod ||
          s.slotId == otherSlotId),
      isFalse,
    );
    expect(v.devices.map((d) => d.deviceId), ['dev-laptop']);
    expect(v.mskPublicKey, isNot(oldMsk));
  });
}

/// Real OpenSSL crypto with Argon2id forced to the test floor.
class _FastKdfCrypto extends OpensslCkvfCrypto {
  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) =>
      super.argon2id(
        password: password,
        salt: salt,
        m: testArgon2id.m,
        t: testArgon2id.t,
        p: testArgon2id.p,
        keyLength: keyLength,
      );
}

class _FakePepperHost implements PepperOprf {
  _FakePepperHost(this.serverKeys);
  final Map<String, List<int>> serverKeys;

  @override
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  }) async {
    final key = serverKeys[kid];
    if (key == null) throw StateError('unknown kid');
    return Uint8List.fromList(
      List<int>.generate(
        64,
        (i) => key[i % key.length] ^ secret[i % secret.length],
      ),
    );
  }
}

// Test-only mirrors of key_vault private helpers for building extension maps.
Map<String, dynamic> _extensionData(VaultPayload payload, String id) {
  for (final e in payload.extensions) {
    if (e.id == id && e.data is Map) {
      return Map<String, dynamic>.from(e.data as Map);
    }
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
