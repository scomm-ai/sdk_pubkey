import 'dart:typed_data';

import '../constants.dart';
import '../errors.dart';

class CryptoCapabilities {
  const CryptoCapabilities({
    required this.id,
    required this.kind,
    required this.sign,
    required this.verify,
    required this.keyAgreement,
    required this.aead,
    required this.hash,
    required this.kem,
    required this.protections,
    required this.extractable,
    this.random = true,
    this.engines = const {},
  });

  final String id;
  final String kind;
  final List<String> sign;
  final List<String> verify;
  final List<String> keyAgreement;
  final List<String> aead;
  final List<String> hash;
  final List<String> kem;
  final List<String> protections;
  final List<bool> extractable;
  final bool random;
  final Map<String, bool> engines;
}

class KeyGenerateOptions {
  const KeyGenerateOptions({
    this.extractable = true,
    this.protection = KeyProtection.software,
    this.purpose,
  });

  final bool extractable;
  final String protection;
  final String? purpose;
}

class KeyRef {
  const KeyRef({
    required this.id,
    required this.algorithm,
    this.provider,
    this.purpose,
    this.publicKey,
    this.extractable = true,
    this.protection = KeyProtection.software,
  });

  final String id;
  final String algorithm;
  final String? provider;
  final String? purpose;
  final Uint8List? publicKey;
  final bool extractable;
  final String protection;
}

class PortablePrivateKey {
  const PortablePrivateKey({
    required this.algorithm,
    required this.encoding,
    required this.bytes,
    this.purpose,
    this.publicKey,
    this.extractable = true,
  });

  final String algorithm;
  final String encoding;
  final Uint8List bytes;
  final String? purpose;
  final Uint8List? publicKey;
  final bool extractable;
}

class VaultWrap {
  const VaultWrap({
    required this.salt,
    required this.iv,
    required this.iterations,
    required this.ciphertext,
  });

  final Uint8List salt;
  final Uint8List iv;
  final int iterations;
  final Uint8List ciphertext;
}

/// Cryptographic abstraction. Implementations must not know HTTP or OTP.
/// Algorithm names are protocol identifiers; [id] is an implementation choice.
abstract class CryptoProvider {
  String get id;
  String get kind;

  Future<CryptoCapabilities> capabilities();

  Future<bool> supports(
    String operation,
    String algorithm, {
    bool? extractable,
    String? protection,
    String? purpose,
  });

  Uint8List random(int length);

  Future<Uint8List> hash(String algorithm, List<int> data);

  Future<KeyRef> generateKey({
    required String algorithm,
    String? purpose,
    bool extractable = true,
    String protection = KeyProtection.software,
  });

  Future<KeyRef> generateSigningKey([
    String algorithm = mskAlgorithm,
    KeyGenerateOptions options = const KeyGenerateOptions(),
  ]) {
    return generateKey(
      algorithm: algorithm,
      purpose: options.purpose ?? Purposes.masterSigning,
      extractable: options.extractable,
      protection: options.protection,
    );
  }

  Future<KeyRef> generateEncryptionKey(
    String algorithm, [
    KeyGenerateOptions options = const KeyGenerateOptions(),
  ]) {
    return generateKey(
      algorithm: algorithm,
      purpose: options.purpose ?? Purposes.encryption,
      extractable: options.extractable,
      protection: options.protection,
    );
  }

  Future<Uint8List> sign(KeyRef key, List<int> payload);

  Future<bool> verify(
    List<int> publicKey,
    List<int> payload,
    List<int> signature, [
    String algorithm = mskAlgorithm,
  ]);

  Future<Uint8List> encrypt({
    KeyRef? key,
    List<int>? plaintext,
    String? algorithm,
  }) async {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'encrypt is not available on this provider',
    );
  }

  Future<Uint8List> decrypt({
    KeyRef? key,
    List<int>? ciphertext,
    String? algorithm,
  }) async {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'decrypt is not available on this provider',
    );
  }

  Future<Uint8List> deriveSecret(KeyRef privateKey, List<int> peerPublicKey) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'deriveSecret is not available on this provider',
    );
  }

  Future<KeyRef> importKey(
    PortablePrivateKey portable, {
    bool? extractable,
    String protection = KeyProtection.software,
  }) {
    return importPrivateKey(
      portable,
      extractable: extractable,
      protection: protection,
    );
  }

  Future<KeyRef> importPrivateKey(
    PortablePrivateKey portable, {
    bool? extractable,
    String protection = KeyProtection.software,
  });

  Future<PortablePrivateKey> exportKey(KeyRef key) => exportPrivateKey(key);

  Future<PortablePrivateKey> exportPrivateKey(KeyRef key);

  Future<Uint8List> deriveBits(String algorithm, Map<String, dynamic> params) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'deriveBits is not available on this provider',
    );
  }

  Future<VaultWrap> wrapVault(
    List<int> plaintext,
    String passphrase, {
    List<int>? salt,
    List<int>? iv,
    int? iterations,
  });

  Future<KeyRef> generateDeviceKey({
    bool extractable = false,
    String? protection,
  }) async {
    final preferred = protection ?? KeyProtection.osProtected;
    var chosen = preferred;
    if (protection == null &&
        !await supports(
          CryptoOperations.generateKey,
          'ed25519',
          extractable: extractable,
          protection: preferred,
          purpose: Purposes.authentication,
        )) {
      chosen = KeyProtection.software;
    }
    return generateSigningKey(
      'ed25519',
      KeyGenerateOptions(
        purpose: Purposes.authentication,
        extractable: extractable,
        protection: chosen,
      ),
    );
  }

  Future<KeyRef> generateMSK({
    bool extractable = true,
    String protection = KeyProtection.software,
  }) {
    return generateSigningKey(
      mskAlgorithm,
      KeyGenerateOptions(
        purpose: Purposes.masterSigning,
        extractable: extractable,
        protection: protection,
      ),
    );
  }

  Future<Uint8List> signWithMSK(KeyRef key, List<int> payload) =>
      sign(key, payload);

  Future<bool> verifyMSKSignature(
    List<int> publicKey,
    List<int> payload,
    List<int> signature,
  ) {
    return verify(publicKey, payload, signature, mskAlgorithm);
  }

  Future<Uint8List> hkdfSha256(
    List<int> ikm,
    List<int> info, {
    int length = 32,
    List<int>? salt,
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'hkdfSha256 is not available on this provider',
    );
  }

  /// Derives EEK (Export Encryption Key) — or REK,
  /// when needed — from a human-memorized passphrase/recovery code
  /// via Argon2id. Unlike [wrapVault]/[unwrapVault] (PBKDF2, used only by the
  /// unrelated single-key `Vault.exportKeyPackage` feature), this is the
  /// spec-mandated KDF for whole-vault offline export/import —
  /// backed by `package:cryptography`'s `Argon2id`, wired in
  /// `DartCryptoProvider` the same way `deriveSecret`/`hkdfSha256` were
  /// added for device pairing.
  Future<Uint8List> deriveArgon2id(
    List<int> passphrase,
    List<int> salt, {
    int parallelism = argon2idDefaultParallelism,
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int length = 32,
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'deriveArgon2id is not available on this provider',
    );
  }

  Future<({Uint8List iv, Uint8List ciphertext})> encryptAead(
    List<int> keyBytes,
    List<int> plaintext,
  ) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'encryptAead is not available on this provider',
    );
  }

  Future<Uint8List> decryptAead(
    List<int> keyBytes,
    List<int> iv,
    List<int> ciphertext,
  ) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'decryptAead is not available on this provider',
    );
  }

  /// CPace-Ristretto255-SHA512 initiator: returns [CPaceSession] whose
  /// [CPaceSession.publicElement] is Ya. Private scalar stays in this
  /// provider.
  Future<CPaceSession> cpaceStart({
    required List<int> password,
    required List<int> sid,
    List<int> ci = const [],
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'cpaceStart is not available on this provider',
    );
  }

  /// CPace responder: Yb plus 64-byte ISK.
  Future<({Uint8List publicElement, Uint8List isk})> cpaceRespond({
    required List<int> password,
    required List<int> sid,
    required List<int> peerPublicElement,
    List<int> ci = const [],
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'cpaceRespond is not available on this provider',
    );
  }

  /// Completes the initiator handshake with the peer's Yb.
  Future<Uint8List> cpaceFinish(
    CPaceSession session,
    List<int> peerPublicElement,
  ) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'cpaceFinish is not available on this provider',
    );
  }

  Future<Uint8List> unwrapVault(
    List<int> ciphertext,
    String passphrase,
    List<int> salt,
    List<int> iv,
    int iterations,
  );
}

/// Handle for an in-progress CPace initiator session.
class CPaceSession {
  const CPaceSession({required this.id, required this.publicElement});

  final String id;
  final Uint8List publicElement;
}
