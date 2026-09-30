import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

void main() {
  final ckvfCrypto = _SoftwareCrypto();

  test('empty folder accepts the first generation and rejects a stale head', () async {
    final root = Directory.systemTemp.createTempSync('ckvf-sync');
    final sync = FolderVaultSync(root);
    final store = MemoryLocalVaultStore();
    final vault = KeyVault(store, crypto: ckvfCrypto)..syncStore = sync;
    await vault.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'd1', name: 'Laptop'),
    );
    expect(await sync.getHead(vault.vaultId), isNull);
    await vault.push();
    final head = await sync.getHead(vault.vaultId);
    expect(head?.generation, 1);

    final pair = await ckvfCrypto.ed25519Generate();
    await vault.importKey(
      family: 'smime',
      encoding: 'pkcs8',
      algorithm: 'Ed25519',
      purpose: const ['sign'],
      privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
      publicKey: buildSpkiEd25519(pair.publicKey),
    );
    await vault.push();
    expect((await sync.getHead(vault.vaultId))?.generation, greaterThan(1));

    final gen1 = await sync.getGeneration(vault.vaultId, 1);
    expect(gen1, isNotNull);
    final parsed = jsonDecode(gen1!) as Map<String, dynamic>;
    final hash = parsed['generation_hash'] as String;
    expect(hash, isNot(vault.vault.container.generationHash));
    expect(parsed['generation'], 1);
    File('${root.path}/${vault.vaultId}/head.json').writeAsStringSync(jsonEncode({
      'format': 'CKVF-HEAD',
      'version': '1',
      'vault_id': vault.vaultId,
      'generation': 1,
      'generation_hash': hash,
    }));
    await expectLater(
      vault.pull(),
      throwsA(
        isA<VaultClientException>().having((e) => e.code, 'code', 'generation_rollback'),
      ),
    );
    root.deleteSync(recursive: true);
  });
}

class _SoftwareCrypto implements CkvfCrypto {
  final Ed25519 _ed25519 = Ed25519();
  final X25519 _x25519 = X25519();
  final AesGcm _aesGcm = AesGcm.with256bits();
  final Random _random = Random.secure();

  @override
  Uint8List randomBytes(int n) =>
      Uint8List.fromList(List<int>.generate(n, (_) => _random.nextInt(256)));

  @override
  Future<Uint8List> sha256(List<int> data) async =>
      Uint8List.fromList(crypto.sha256.convert(data).bytes);

  @override
  Future<({Uint8List ciphertext, Uint8List tag})> aes256gcmEncrypt(
    List<int> key,
    List<int> iv,
    List<int> plaintext,
    List<int> aad,
  ) async {
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: iv,
      aad: aad,
    );
    return (
      ciphertext: Uint8List.fromList(box.cipherText),
      tag: Uint8List.fromList(box.mac.bytes),
    );
  }

  @override
  Future<Uint8List> aes256gcmDecrypt(
    List<int> key,
    List<int> iv,
    List<int> ciphertext,
    List<int> tag,
    List<int> aad,
  ) async {
    try {
      final plain = await _aesGcm.decrypt(
        SecretBox(ciphertext, nonce: iv, mac: Mac(tag)),
        secretKey: SecretKey(key),
        aad: aad,
      );
      return Uint8List.fromList(plain);
    } catch (_) {
      throw StateError('ERR_AEAD_DECRYPT');
    }
  }

  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) async {
    final algorithm = Argon2id(
      parallelism: p,
      memory: m,
      iterations: t,
      hashLength: keyLength,
    );
    final key = await algorithm.deriveKey(secretKey: SecretKey(password), nonce: salt);
    return Uint8List.fromList(await key.extractBytes());
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519Generate() async {
    final pair = await _ed25519.newKeyPair();
    final privateKey = Uint8List.fromList(await pair.extractPrivateKeyBytes());
    final public = await pair.extractPublicKey();
    return (publicKey: Uint8List.fromList(public.bytes), privateKey: privateKey);
  }

  @override
  Future<Uint8List> ed25519PublicFromSeed(List<int> seed) async {
    final pair = await _ed25519.newKeyPairFromSeed(seed);
    return Uint8List.fromList((await pair.extractPublicKey()).bytes);
  }

  @override
  Future<Uint8List> ed25519Sign(List<int> seed, List<int> message) async {
    final pair = await _ed25519.newKeyPairFromSeed(seed);
    final signature = await _ed25519.sign(message, keyPair: pair);
    return Uint8List.fromList(signature.bytes);
  }

  @override
  Future<bool> ed25519Verify(List<int> publicKey, List<int> message, List<int> signature) {
    return _ed25519.verify(
      message,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      ),
    );
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> x25519Generate() async {
    final pair = await _x25519.newKeyPair();
    final privateKey = Uint8List.fromList(await pair.extractPrivateKeyBytes());
    final public = await pair.extractPublicKey();
    return (publicKey: Uint8List.fromList(public.bytes), privateKey: privateKey);
  }

  @override
  Future<Uint8List> x25519(List<int> privateKey, List<int> publicKey) async {
    final shared = await _x25519.sharedSecretKey(
      keyPair: await _x25519.newKeyPairFromSeed(privateKey),
      remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    );
    return Uint8List.fromList(await shared.extractBytes());
  }
}
