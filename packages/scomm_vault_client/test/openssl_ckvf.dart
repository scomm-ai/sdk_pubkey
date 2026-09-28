import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:scomm_openpgp/scomm_openpgp.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';

/// CKVF crypto and vault digests from libscomm_openpgp.
class OpensslCkvfCrypto implements CkvfCrypto {
  OpensslCkvfCrypto() {
    VaultDigest.install(
      sha256: nativeSha256,
      sha512: nativeSha512,
      hmacSha256: nativeHmacSha256,
    );
  }

  @override
  Uint8List randomBytes(int n) => nativeRandom(n);

  @override
  Future<Uint8List> sha256(List<int> data) async => nativeSha256(data);

  @override
  Future<({Uint8List ciphertext, Uint8List tag})> aes256gcmEncrypt(
    List<int> key,
    List<int> iv,
    List<int> plaintext,
    List<int> aad,
  ) async =>
      nativeAes256GcmEncrypt(
        key: key,
        nonce: iv,
        plaintext: plaintext,
        aad: aad,
      );

  @override
  Future<Uint8List> aes256gcmDecrypt(
    List<int> key,
    List<int> iv,
    List<int> ciphertext,
    List<int> tag,
    List<int> aad,
  ) async =>
      nativeAes256GcmDecrypt(
        key: key,
        nonce: iv,
        ciphertext: ciphertext,
        tag: tag,
        aad: aad,
      );

  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) =>
      Future.value(nativeArgon2id(
        password: password,
        salt: salt,
        iterations: t,
        lanes: p,
        memKib: m,
        outLen: keyLength,
      ));

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519Generate() async {
    final privateKey = nativeRandom(32);
    return (publicKey: nativeEd25519Public(privateKey), privateKey: privateKey);
  }

  @override
  Future<Uint8List> ed25519PublicFromSeed(List<int> seed) async =>
      nativeEd25519Public(seed);

  @override
  Future<Uint8List> ed25519Sign(List<int> seed, List<int> message) async =>
      nativeEd25519Sign(seed, message);

  @override
  Future<bool> ed25519Verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) async =>
      nativeEd25519Verify(publicKey, message, signature);
}
