import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

/// ML-DSA-65 || Ed25519 master signing key.
///
/// Seeds are 32-byte FIPS 204 `ξ` then the 32-byte RFC 8032 seed.
/// Public key and signature use that same order.
class HybridMsk {
  HybridMsk._();

  static const publicKeyBytes = 1952 + 32;
  static const signatureBytes = 3309 + 64;
  static final _params = DilithiumParams.mlDsa65;
  static final _ed25519 = Ed25519();

  static Future<({Uint8List seeds, Uint8List publicKey})> generate() async {
    final random = Random.secure();
    final xi = Uint8List.fromList(List<int>.generate(32, (_) => random.nextInt(256)));
    final edSeed = Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
    final publicKey = await publicFromSeeds(xi, edSeed);
    return (seeds: _concat(xi, edSeed), publicKey: publicKey);
  }

  static Future<Uint8List> publicFromSeeds(
    Uint8List mldsaSeed,
    Uint8List edSeed,
  ) async {
    final (pk, _) = MlDsa.generateKeyPairSeeded(_params, mldsaSeed);
    final ed = await _ed25519.newKeyPairFromSeed(edSeed);
    final edPub = await ed.extractPublicKey();
    return _concat(pk, Uint8List.fromList(edPub.bytes));
  }

  static Future<Uint8List> sign(Uint8List seeds, List<int> message) async {
    final mldsaSeed = Uint8List.sublistView(seeds, 0, 32);
    final edSeed = Uint8List.sublistView(seeds, 32, 64);
    final (_, sk) = MlDsa.generateKeyPairSeeded(_params, mldsaSeed);
    final mldsaSig = MlDsa.sign(
      sk,
      Uint8List.fromList(message),
      _params,
    );
    final ed = await _ed25519.newKeyPairFromSeed(edSeed);
    final edSig = await _ed25519.sign(message, keyPair: ed);
    return _concat(mldsaSig, Uint8List.fromList(edSig.bytes));
  }

  static Future<bool> verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) async {
    if (publicKey.length != publicKeyBytes ||
        signature.length != signatureBytes) {
      return false;
    }
    final pk = Uint8List.fromList(publicKey);
    final sig = Uint8List.fromList(signature);
    final mldsaOk = MlDsa.verify(
      Uint8List.sublistView(pk, 0, 1952),
      Uint8List.fromList(message),
      Uint8List.sublistView(sig, 0, 3309),
      _params,
    );
    if (!mldsaOk) return false;
    return _ed25519.verify(
      message,
      signature: Signature(
        Uint8List.sublistView(sig, 3309),
        publicKey: SimplePublicKey(
          Uint8List.sublistView(pk, 1952),
          type: KeyPairType.ed25519,
        ),
      ),
    );
  }

  static Uint8List _concat(List<int> a, List<int> b) {
    final out = Uint8List(a.length + b.length);
    out.setRange(0, a.length, a);
    out.setRange(a.length, out.length, b);
    return out;
  }
}
