import 'openssl_crypto.dart';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('hybrid MSK signs and verifies both halves', () async {
    final crypto = opensslCrypto();
    final key = await crypto.generateSigningKey(mskHybridAlgorithm);
    expect(key.publicKey, hasLength(1984));
    final message = Uint8List.fromList('SComm/Pubkey/1/arm_msk\n'.codeUnits);
    final signature = await crypto.sign(key, message);
    expect(signature, hasLength(3373));
    expect(
      await crypto.verify(key.publicKey!, message, signature, mskHybridAlgorithm),
      isTrue,
    );
    final stripped = Uint8List.fromList(signature);
    stripped[0] ^= 0x01;
    expect(
      await crypto.verify(key.publicKey!, message, stripped, mskHybridAlgorithm),
      isFalse,
    );
    final portable = await crypto.exportPrivateKey(key);
    expect(portable.encoding, 'seed-pair');
    expect(portable.bytes, hasLength(64));
    final imported = await crypto.importPrivateKey(portable);
    expect(imported.publicKey, key.publicKey);
  });
}
