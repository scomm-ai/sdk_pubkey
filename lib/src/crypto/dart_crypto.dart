import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

import '../constants.dart';
import '../errors.dart';
import '../identity.dart';
import 'cpace.dart';
import 'provider.dart';

class _KeySlot {
  _KeySlot({
    required this.algorithm,
    required this.extractable,
    required this.protection,
    this.purpose,
    this.ed25519,
    this.x25519,
    this.p256,
    this.rawPrivate,
    this.rawPublic,
  });

  final String algorithm;
  final bool extractable;
  final String protection;
  final String? purpose;
  final SimpleKeyPair? ed25519;
  final SimpleKeyPair? x25519;
  final EcKeyPair? p256;
  final Uint8List? rawPrivate;
  final Uint8List? rawPublic;
}

/// Software Dart provider (package:cryptography).
///
/// This is the **fallback** when a host has not registered a native adapter
/// (CryptoKit, Android Keystore, CNG). It is not hardware-backed.
class DartCryptoProvider extends CryptoProvider {
  final Map<String, _KeySlot> _keys = {};
  final Ed25519 _ed25519 = Ed25519();
  final X25519 _x25519 = X25519();
  final Ecdh _p256 = Ecdh.p256(length: 32);
  final AesGcm _aesGcm = AesGcm.with256bits();
  final Random _random = Random.secure();

  @override
  String get id => 'dart-software';

  @override
  String get kind => 'fallback';

  Uint8List _randomBytes(int length) {
    return Uint8List.fromList(
      List<int>.generate(length, (_) => _random.nextInt(256)),
    );
  }

  String _randomId() => bytesToHex(_randomBytes(16));

  Uint8List _ecUncompressed(EcPublicKey key) {
    return Uint8List.fromList([0x04, ...key.x, ...key.y]);
  }

  EcPublicKey _ecFromUncompressed(List<int> bytes) {
    if (bytes.length != 65 || bytes[0] != 0x04) {
      throw PubkeyException(
        ErrorCodes.invalidPublicKey,
        'P-256 public key must be an uncompressed point',
      );
    }
    return EcPublicKey(
      type: KeyPairType.p256,
      x: bytes.sublist(1, 33),
      y: bytes.sublist(33, 65),
    );
  }

  void _rejectHardware(String protection) {
    if (protection == KeyProtection.hardwareBacked ||
        protection == KeyProtection.osProtected) {
      throw PubkeyException(
        ErrorCodes.hardwareProtectionUnavailable,
        'DartCryptoProvider is software-only; register a NativeCryptoProvider for hardware-backed keys',
      );
    }
  }

  @override
  Future<CryptoCapabilities> capabilities() async {
    return const CryptoCapabilities(
      id: 'dart-software',
      kind: 'fallback',
      sign: [mskAlgorithm],
      verify: [mskAlgorithm],
      keyAgreement: ['x25519', 'p-256'],
      aead: ['aes-256-gcm'],
      hash: ['sha-256'],
      kem: [],
      protections: [KeyProtection.software, KeyProtection.portableVault],
      extractable: [true, false],
    );
  }

  @override
  Future<bool> supports(
    String operation,
    String algorithm, {
    bool? extractable,
    String? protection,
    String? purpose,
  }) async {
    if (protection == KeyProtection.hardwareBacked ||
        protection == KeyProtection.osProtected) {
      return false;
    }
    final algo = algorithm.toLowerCase();
    switch (operation) {
      case CryptoOperations.random:
      case CryptoOperations.hash:
        return algo == 'sha-256' || algo == 'sha256' || operation == CryptoOperations.random;
      case CryptoOperations.sign:
      case CryptoOperations.verify:
        return algo == mskAlgorithm || algo == 'ed25519';
      case CryptoOperations.generateKey:
      case CryptoOperations.importKey:
      case CryptoOperations.exportKey:
        return algo == mskAlgorithm ||
            algo == 'ed25519' ||
            algo == 'x25519' ||
            algo == 'p-256';
      case CryptoOperations.deriveSecret:
        return algo == 'x25519' || algo == 'p-256';
      case CryptoOperations.encrypt:
      case CryptoOperations.decrypt:
        return algo == 'aes-256-gcm';
      default:
        return false;
    }
  }

  @override
  Uint8List random(int length) => _randomBytes(length);

  @override
  Future<Uint8List> hash(String algorithm, List<int> data) async {
    final normalized = algorithm.toLowerCase().replaceAll('_', '-');
    if (normalized != 'sha-256' && normalized != 'sha256') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'DartCryptoProvider cannot hash $algorithm',
      );
    }
    return Uint8List.fromList(crypto.sha256.convert(data).bytes);
  }

  @override
  Future<KeyRef> generateKey({
    required String algorithm,
    String? purpose,
    bool extractable = true,
    String protection = KeyProtection.software,
  }) async {
    _rejectHardware(protection);
    if (algorithm == mskAlgorithm || algorithm == 'ed25519') {
      final keyPair = await _ed25519.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      final rawPrivate = Uint8List.fromList(await keyPair.extractPrivateKeyBytes());
      final rawPublic = Uint8List.fromList(publicKey.bytes);
      return _store(
        _KeySlot(
          algorithm: mskAlgorithm,
          extractable: extractable,
          protection: protection,
          purpose: purpose ?? Purposes.masterSigning,
          ed25519: keyPair,
          rawPrivate: extractable ? rawPrivate : null,
          rawPublic: rawPublic,
        ),
      );
    }
    if (algorithm == 'x25519') {
      final keyPair = await _x25519.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      return _store(
        _KeySlot(
          algorithm: 'x25519',
          extractable: extractable,
          protection: protection,
          purpose: purpose ?? Purposes.keyAgreement,
          x25519: keyPair,
          rawPublic: Uint8List.fromList(publicKey.bytes),
        ),
      );
    }
    if (algorithm == 'p-256' || algorithm == 'ecdh-p256') {
      final keyPair = await _p256.newKeyPair();
      final publicKey = await keyPair.extractPublicKey();
      return _store(
        _KeySlot(
          algorithm: 'p-256',
          extractable: extractable,
          protection: protection,
          purpose: purpose ?? Purposes.keyAgreement,
          p256: keyPair,
          rawPublic: _ecUncompressed(publicKey),
        ),
      );
    }
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'DartCryptoProvider cannot generate $algorithm',
    );
  }

  KeyRef _store(_KeySlot slot) {
    final id = _randomId();
    _keys[id] = slot;
    return KeyRef(
      id: id,
      provider: this.id,
      algorithm: slot.algorithm,
      purpose: slot.purpose,
      publicKey: slot.rawPublic,
      extractable: slot.extractable,
      protection: slot.protection,
    );
  }

  _KeySlot _slot(KeyRef key) {
    final slot = _keys[key.id];
    if (slot == null) {
      throw PubkeyException(ErrorCodes.keyNotFound, 'Unknown KeyHandle');
    }
    return slot;
  }

  @override
  Future<Uint8List> sign(KeyRef key, List<int> payload) async {
    final slot = _slot(key);
    if (slot.ed25519 == null) {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot sign with ${slot.algorithm}',
      );
    }
    final signature = await _ed25519.sign(payload, keyPair: slot.ed25519!);
    return Uint8List.fromList(signature.bytes);
  }

  @override
  Future<bool> verify(
    List<int> publicKey,
    List<int> payload,
    List<int> signature, [
    String algorithm = mskAlgorithm,
  ]) async {
    if (algorithm != mskAlgorithm && algorithm != 'ed25519') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot verify $algorithm with DartCryptoProvider',
      );
    }
    return _ed25519.verify(
      payload,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      ),
    );
  }

  @override
  Future<Uint8List> deriveSecret(
    KeyRef privateKey,
    List<int> peerPublicKey,
  ) async {
    final slot = _slot(privateKey);
    if (slot.x25519 != null) {
      final secret = await _x25519.sharedSecretKey(
        keyPair: slot.x25519!,
        remotePublicKey: SimplePublicKey(
          peerPublicKey,
          type: KeyPairType.x25519,
        ),
      );
      return Uint8List.fromList(await secret.extractBytes());
    }
    if (slot.p256 != null) {
      final secret = await _p256.sharedSecretKey(
        keyPair: slot.p256!,
        remotePublicKey: _ecFromUncompressed(peerPublicKey),
      );
      return Uint8List.fromList(await secret.extractBytes());
    }
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'Cannot deriveSecret with ${slot.algorithm}',
    );
  }

  @override
  Future<KeyRef> importPrivateKey(
    PortablePrivateKey portable, {
    bool? extractable,
    String protection = KeyProtection.software,
  }) async {
    _rejectHardware(protection);
    final canExtract = extractable ?? portable.extractable;
    if (portable.algorithm == 'x25519') {
      if (portable.bytes.length != 32) {
        throw PubkeyException(
          ErrorCodes.keyImportFailure,
          'X25519 seed must be 32 bytes',
        );
      }
      final keyPair = await _x25519.newKeyPairFromSeed(portable.bytes);
      final extracted = await keyPair.extractPublicKey();
      final rawPublic = portable.publicKey ?? Uint8List.fromList(extracted.bytes);
      return _store(
        _KeySlot(
          algorithm: 'x25519',
          extractable: canExtract,
          protection: protection,
          purpose: portable.purpose,
          x25519: keyPair,
          rawPrivate: canExtract ? Uint8List.fromList(portable.bytes) : null,
          rawPublic: rawPublic,
        ),
      );
    }
    if (portable.algorithm != mskAlgorithm && portable.algorithm != 'ed25519') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot import ${portable.algorithm}',
      );
    }
    if (portable.bytes.length != 32) {
      throw PubkeyException(
        ErrorCodes.keyImportFailure,
        'Ed25519 seed must be 32 bytes',
      );
    }
    final keyPair = await _ed25519.newKeyPairFromSeed(portable.bytes);
    final extracted = await keyPair.extractPublicKey();
    final rawPublic = portable.publicKey ?? Uint8List.fromList(extracted.bytes);
    return _store(
      _KeySlot(
        algorithm: mskAlgorithm,
        extractable: canExtract,
        protection: protection,
        purpose: portable.purpose,
        ed25519: keyPair,
        rawPrivate: canExtract ? Uint8List.fromList(portable.bytes) : null,
        rawPublic: rawPublic,
      ),
    );
  }

  @override
  Future<PortablePrivateKey> exportPrivateKey(KeyRef key) async {
    final slot = _slot(key);
    if (!slot.extractable || slot.rawPrivate == null) {
      throw PubkeyException(
        ErrorCodes.keyNotExportable,
        'Key is not extractable',
      );
    }
    return PortablePrivateKey(
      algorithm: slot.algorithm,
      encoding: 'raw-32',
      bytes: Uint8List.fromList(slot.rawPrivate!),
      publicKey: slot.rawPublic == null
          ? null
          : Uint8List.fromList(slot.rawPublic!),
      purpose: slot.purpose,
    );
  }

  @override
  Future<Uint8List> deriveBits(
    String algorithm,
    Map<String, dynamic> params,
  ) async {
    if (algorithm != vaultKdf && algorithm != 'pbkdf2-sha256') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot derive bits with $algorithm',
      );
    }
    final passphrase = params['passphrase'] as String? ?? '';
    final salt = params['salt'] as List<int>? ?? const <int>[];
    final iterations = params['iterations'] as int? ?? vaultPbkdf2Iterations;
    final bits = params['bits'] as int? ?? 256;
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: bits,
    );
    final key = await pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  Future<SecretKey> _vaultKey(
    String passphrase,
    List<int> salt,
    int iterations,
  ) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: 256,
    );
    return pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
  }

  @override
  Future<VaultWrap> wrapVault(
    List<int> plaintext,
    String passphrase, {
    List<int>? salt,
    List<int>? iv,
    int? iterations,
  }) async {
    final iter = iterations ?? vaultPbkdf2Iterations;
    final saltBytes = salt == null
        ? _randomBytes(vaultSaltBytes)
        : Uint8List.fromList(salt);
    final ivBytes = iv == null
        ? _randomBytes(vaultIvBytes)
        : Uint8List.fromList(iv);
    final key = await _vaultKey(passphrase, saltBytes, iter);
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: key,
      nonce: ivBytes,
    );
    final ciphertext = Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
    return VaultWrap(
      salt: saltBytes,
      iv: ivBytes,
      iterations: iter,
      ciphertext: ciphertext,
    );
  }

  @override
  Future<Uint8List> unwrapVault(
    List<int> ciphertext,
    String passphrase,
    List<int> salt,
    List<int> iv,
    int iterations,
  ) async {
    if (ciphertext.length < 16) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Vault ciphertext is truncated',
      );
    }
    final key = await _vaultKey(passphrase, salt, iterations);
    final cipherText = ciphertext.sublist(0, ciphertext.length - 16);
    final mac = Mac(ciphertext.sublist(ciphertext.length - 16));
    try {
      final plain = await _aesGcm.decrypt(
        SecretBox(cipherText, nonce: iv, mac: mac),
        secretKey: key,
      );
      return Uint8List.fromList(plain);
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.vaultAuthenticationFailure,
        'Vault authentication failed',
      );
    }
  }

  @override
  Future<Uint8List> hkdfSha256(
    List<int> ikm,
    List<int> info, {
    int length = 32,
    List<int>? salt,
  }) async {
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: length);
    final key = await hkdf.deriveKey(
      secretKey: SecretKey(ikm),
      nonce: salt ?? Uint8List(32),
      info: info,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  @override
  Future<Uint8List> deriveArgon2id(
    List<int> passphrase,
    List<int> salt, {
    int parallelism = argon2idDefaultParallelism,
    int memory = argon2idDefaultMemoryKib,
    int iterations = argon2idDefaultIterations,
    int length = 32,
  }) async {
    final algorithm = Argon2id(
      parallelism: parallelism,
      memory: memory,
      iterations: iterations,
      hashLength: length,
    );
    final key = await algorithm.deriveKey(
      secretKey: SecretKey(passphrase),
      nonce: salt,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  @override
  Future<({Uint8List iv, Uint8List ciphertext})> encryptAead(
    List<int> keyBytes,
    List<int> plaintext,
  ) async {
    final iv = _randomBytes(12);
    final box = await _aesGcm.encrypt(
      plaintext,
      secretKey: SecretKey(keyBytes),
      nonce: iv,
    );
    return (
      iv: iv,
      ciphertext: Uint8List.fromList([...box.cipherText, ...box.mac.bytes]),
    );
  }

  @override
  Future<Uint8List> decryptAead(
    List<int> keyBytes,
    List<int> iv,
    List<int> ciphertext,
  ) async {
    if (ciphertext.length < 16) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'AEAD ciphertext is truncated',
      );
    }
    final cipherText = ciphertext.sublist(0, ciphertext.length - 16);
    final mac = Mac(ciphertext.sublist(ciphertext.length - 16));
    final plain = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: iv, mac: mac),
      secretKey: SecretKey(keyBytes),
    );
    return Uint8List.fromList(plain);
  }

  final Map<String, CPaceInitiatorState> _cpace = {};

  @override
  Future<CPaceSession> cpaceStart({
    required List<int> password,
    required List<int> sid,
    List<int> ci = const [],
  }) async {
    final state = cpaceStartImpl(
      password: password,
      sid: sid,
      ci: ci,
      random64: _randomBytes(64),
    );
    final id = _randomId();
    _cpace[id] = state;
    return CPaceSession(id: id, publicElement: state.ya);
  }

  @override
  Future<({Uint8List publicElement, Uint8List isk})> cpaceRespond({
    required List<int> password,
    required List<int> sid,
    required List<int> peerPublicElement,
    List<int> ci = const [],
  }) async {
    final result = cpaceRespondImpl(
      password: password,
      sid: sid,
      ci: ci,
      peerYa: peerPublicElement,
      random64: _randomBytes(64),
    );
    return (publicElement: result.yb, isk: result.isk);
  }

  @override
  Future<Uint8List> cpaceFinish(
    CPaceSession session,
    List<int> peerPublicElement,
  ) async {
    final state = _cpace.remove(session.id);
    if (state == null) {
      throw PubkeyException(
        ErrorCodes.keyNotFound,
        'Unknown CPace session',
      );
    }
    return cpaceFinishImpl(state: state, peerYb: peerPublicElement);
  }
}
