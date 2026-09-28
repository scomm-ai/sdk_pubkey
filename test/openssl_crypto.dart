import 'dart:typed_data';

import 'package:scomm_openpgp/scomm_openpgp.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/crypto/cpace.dart';

/// OpenSSL [CryptoProvider] for SDK tests. The app supplies its own.
class OpensslCryptoProvider extends CryptoProvider {
  final Map<String, _Slot> _keys = {};
  final Map<String, CPaceInitiatorState> _cpace = {};

  static void installDigests() {
    ProtocolDigest.install(
      sha256: nativeSha256,
      sha512: nativeSha512,
    );
  }

  @override
  String get id => 'openssl';

  @override
  String get kind => 'software';

  @override
  Future<CryptoCapabilities> capabilities() async => const CryptoCapabilities(
        id: 'openssl',
        kind: 'software',
        sign: ['ed25519'],
        verify: ['ed25519'],
        keyAgreement: ['x25519'],
        aead: ['aes-256-gcm'],
        hash: ['sha-256'],
        kem: [],
        protections: [KeyProtection.software],
        extractable: [true, false],
      );

  @override
  Future<bool> supports(
    String operation,
    String algorithm, {
    bool? extractable,
    String? protection,
    String? purpose,
  }) async {
    if (protection != null && protection != KeyProtection.software) {
      return false;
    }
    final algo = algorithm.toLowerCase();
    switch (operation) {
      case CryptoOperations.sign:
      case CryptoOperations.verify:
      case CryptoOperations.generateKey:
        return algo == 'ed25519' || algo == mskAlgorithm;
      case CryptoOperations.deriveSecret:
        return algo == 'x25519';
      case CryptoOperations.hash:
        return algo == 'sha-256' || algo == 'sha256';
      default:
        return false;
    }
  }

  @override
  Uint8List random(int length) => nativeRandom(length);

  @override
  Future<Uint8List> hash(String algorithm, List<int> data) async {
    final normalized = algorithm.toLowerCase().replaceAll('_', '-');
    if (normalized != 'sha-256' && normalized != 'sha256') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'OpensslCryptoProvider cannot hash $algorithm',
      );
    }
    return nativeSha256(data);
  }

  void _rejectHardware(String protection) {
    if (protection == KeyProtection.hardwareBacked) {
      throw PubkeyException(
        ErrorCodes.hardwareProtectionUnavailable,
        'OpensslCryptoProvider is software-only',
      );
    }
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
      final seed = nativeRandom(32);
      return _store(
        _Slot(
          algorithm: mskAlgorithm,
          extractable: extractable,
          protection: protection,
          purpose: purpose ?? Purposes.masterSigning,
          seed: extractable ? seed : seed,
          rawPrivate: extractable ? seed : null,
          rawPublic: nativeEd25519Public(seed),
        ),
      );
    }
    if (algorithm == 'x25519') {
      final seed = nativeRandom(32);
      return _store(
        _Slot(
          algorithm: 'x25519',
          extractable: extractable,
          protection: protection,
          purpose: purpose ?? Purposes.keyAgreement,
          seed: seed,
          rawPrivate: extractable ? seed : null,
          rawPublic: nativeX25519Public(seed),
        ),
      );
    }
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'OpensslCryptoProvider cannot generate $algorithm',
    );
  }

  KeyRef _store(_Slot slot) {
    final id = bytesToHex(nativeRandom(8));
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

  _Slot _slot(KeyRef key) {
    final slot = _keys[key.id];
    if (slot == null) {
      throw PubkeyException(ErrorCodes.keyNotFound, 'Unknown KeyHandle');
    }
    return slot;
  }

  @override
  Future<Uint8List> sign(KeyRef key, List<int> payload) async {
    final slot = _slot(key);
    final seed = slot.seed;
    if (seed == null || slot.algorithm != mskAlgorithm) {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot sign with ${slot.algorithm}',
      );
    }
    return nativeEd25519Sign(seed, payload);
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
        'Cannot verify $algorithm',
      );
    }
    return nativeEd25519Verify(publicKey, payload, signature);
  }

  @override
  Future<Uint8List> deriveSecret(
    KeyRef privateKey,
    List<int> peerPublicKey,
  ) async {
    final slot = _slot(privateKey);
    final seed = slot.seed;
    if (seed == null || slot.algorithm != 'x25519') {
      throw PubkeyException(
        ErrorCodes.unsupportedAlgorithm,
        'Cannot deriveSecret with ${slot.algorithm}',
      );
    }
    return nativeX25519Dh(seed, peerPublicKey);
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
      return _store(
        _Slot(
          algorithm: 'x25519',
          extractable: canExtract,
          protection: protection,
          purpose: portable.purpose,
          seed: Uint8List.fromList(portable.bytes),
          rawPrivate: canExtract ? Uint8List.fromList(portable.bytes) : null,
          rawPublic: portable.publicKey ?? nativeX25519Public(portable.bytes),
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
    return _store(
      _Slot(
        algorithm: mskAlgorithm,
        extractable: canExtract,
        protection: protection,
        purpose: portable.purpose,
        seed: Uint8List.fromList(portable.bytes),
        rawPrivate: canExtract ? Uint8List.fromList(portable.bytes) : null,
        rawPublic:
            portable.publicKey ?? nativeEd25519Public(portable.bytes),
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
      publicKey: slot.rawPublic,
      purpose: slot.purpose,
    );
  }

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
      random64: nativeRandom(64),
    );
    final id = bytesToHex(nativeRandom(8));
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
      random64: nativeRandom(64),
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
      throw PubkeyException(ErrorCodes.keyNotFound, 'Unknown CPace session');
    }
    return cpaceFinishImpl(state: state, peerYb: peerPublicElement);
  }
}

class _Slot {
  _Slot({
    required this.algorithm,
    required this.extractable,
    required this.protection,
    required this.rawPublic,
    this.purpose,
    this.seed,
    this.rawPrivate,
  });

  final String algorithm;
  final bool extractable;
  final String protection;
  final String? purpose;
  final Uint8List? seed;
  final Uint8List? rawPrivate;
  final Uint8List rawPublic;
}

OpensslCryptoProvider opensslCrypto() {
  OpensslCryptoProvider.installDigests();
  return OpensslCryptoProvider();
}

final bool protocolDigestsInstalled = () {
  OpensslCryptoProvider.installDigests();
  return true;
}();
