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

  test('rotateSigningKey retires and deletes sign-only private material',
      () async {
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
    expect(v.key(oldId)!.privateKey, isNull);
    expect(v.preferredKey('smime', 'sign'), newId);
    expect(v.vault.payload.tombstones, isNotEmpty);
  });
}
