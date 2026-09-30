import 'dart:convert';
import 'dart:typed_data';

import 'package:scomm_openpgp/scomm_openpgp.dart';
import 'package:scomm_smime/scomm_smime.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';
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
    VaultDigest.install(
      sha256: nativeSha256,
      sha512: nativeSha512,
      hmacSha256: nativeHmacSha256,
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

/// AES-256-GCM decrypt for the local debug CLI. Ciphertext and tag are separate.
Uint8List opensslAes256GcmDecrypt({
  required List<int> key,
  required List<int> nonce,
  required List<int> ciphertext,
  required List<int> tag,
}) {
  return nativeAes256GcmDecrypt(
    key: key,
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tag,
  );
}

final bool protocolDigestsInstalled = () {
  OpensslCryptoProvider.installDigests();
  return true;
}();

/// OpenPGP RFC 9980 signing key for the debug CLI. The secret stays in memory.
class OpenPgpPqcSigningKey {
  OpenPgpPqcSigningKey({required this.publicKey, required this.sign});

  final Uint8List publicKey;
  final Uint8List Function(Uint8List popBytes) sign;
}

/// OpenPGP v4 ECDH subkey packet for a raw 32-byte X25519 public key.
Uint8List openPgpCv25519Packet(Uint8List raw32) {
  if (raw32.length != 32) {
    throw ArgumentError('X25519 public key must be 32 bytes');
  }
  final point = Uint8List(33)..[0] = 0x40;
  point.setRange(1, 33, raw32);
  final mpi = _mpi(point);
  final oid = Uint8List.fromList([
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
  ]);
  final created = Uint8List(4);
  final seconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  created[0] = (seconds >> 24) & 0xff;
  created[1] = (seconds >> 16) & 0xff;
  created[2] = (seconds >> 8) & 0xff;
  created[3] = seconds & 0xff;
  final body = BytesBuilder(copy: false)
    ..addByte(4)
    ..add(created)
    ..addByte(18)
    ..addByte(oid.length)
    ..add(oid)
    ..add(mpi)
    ..add(const [3, 1, 8, 7]);
  final encoded = body.toBytes();
  return Uint8List.fromList([0xce, encoded.length, ...encoded]);
}

Uint8List _mpi(Uint8List bytes) {
  var start = 0;
  while (start < bytes.length - 1 && bytes[start] == 0) {
    start += 1;
  }
  final body = bytes.sublist(start);
  var highest = 0;
  for (var i = 31; i >= 0; i--) {
    if ((body[0] & (1 << i)) != 0) {
      highest = i + 1;
      break;
    }
  }
  final bitLength = (body.length - 1) * 8 + highest;
  return Uint8List(2 + body.length)
    ..[0] = (bitLength >> 8) & 0xff
    ..[1] = bitLength & 0xff
    ..setRange(2, 2 + body.length, body);
}

/// OpenPGP v4 EdDSA primary-key packet for a raw 32-byte Ed25519 public key.
Uint8List openPgpEd25519Packet(Uint8List raw32) {
  if (raw32.length != 32) {
    throw ArgumentError('Ed25519 public key must be 32 bytes');
  }
  final point = Uint8List(33)..[0] = 0x40;
  point.setRange(1, 33, raw32);
  final mpi = _mpi(point);
  final oid = Uint8List.fromList([
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
  ]);
  final created = Uint8List(4);
  final seconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  created[0] = (seconds >> 24) & 0xff;
  created[1] = (seconds >> 16) & 0xff;
  created[2] = (seconds >> 8) & 0xff;
  created[3] = seconds & 0xff;
  final body = BytesBuilder(copy: false)
    ..addByte(4)
    ..add(created)
    ..addByte(22)
    ..addByte(oid.length)
    ..add(oid)
    ..add(mpi);
  final encoded = body.toBytes();
  return Uint8List.fromList([0xc6, encoded.length, ...encoded]);
}

/// RFC 9980 certificate whose encryption subkey is ML-KEM-768+X25519.
class OpenPgpPqcEncryptionKey {
  OpenPgpPqcEncryptionKey({required this.publicKey, required this.secret});

  final Uint8List publicKey;
  final Uint8List secret;
}

OpenPgpPqcEncryptionKey generateOpenPgpPqcEncryptionKey(String userid) {
  final generated = ScommOpenPgp.instance.generateKey(
    userid: userid,
    profile: OpenPgpKeyProfile.rfc9980MlDsa65,
  );
  return OpenPgpPqcEncryptionKey(
    publicKey: Uint8List.fromList(generated.public),
    secret: Uint8List.fromList(generated.secret),
  );
}

/// Literal nonce from an `openpgp_message` challenge.
Uint8List openPgpChallengePlaintext({
  required Uint8List secret,
  required Uint8List message,
  String passphrase = '',
}) {
  return ScommOpenPgp.instance.decrypt(
    ciphertext: message,
    privateKey: secret,
    passphrase: passphrase,
  );
}

/// Raw ML-DSA-65 verifying key from an RFC 9980 certificate, plus a signer
/// that returns only the ML-DSA half. Directory family for this key is `pq`.
class SmimeMlDsaKey {
  SmimeMlDsaKey({required this.publicKey, required this.sign});

  final Uint8List publicKey;
  final ({Uint8List mldsa, Uint8List ed25519}) Function(Uint8List popBytes) sign;
}

SmimeMlDsaKey generateSmimeMlDsaKey(String userid) {
  final generated = ScommSmime.instance.generateKey(
    userid: userid,
    profile: SmimeKeyProfile.pqcCms,
  );
  final secret = Uint8List.fromList(generated.secret);
  final decoded = jsonDecode(utf8.decode(generated.public));
  final entries = (decoded as Map)['entries'] as List;
  final signing = entries.cast<Map>().firstWhere(
    (entry) => entry['alg'] == 'pqc-mldsa65',
  );
  return SmimeMlDsaKey(
    publicKey: Uint8List.fromList(base64Decode(signing['spki_b64'] as String)),
    sign: (popBytes) {
      final sig = ScommSmime.instance.popSignMldsa(
        data: popBytes,
        privateKey: secret,
      );
      return (mldsa: sig, ed25519: Uint8List(0));
    },
  );
}

OpenPgpPqcSigningKey generateOpenPgpPqcSigningKey(String userid) {
  final generated = ScommOpenPgp.instance.generateKey(
    userid: userid,
    profile: OpenPgpKeyProfile.rfc9980MlDsa65,
  );
  final secret = Uint8List.fromList(generated.secret);
  return OpenPgpPqcSigningKey(
    publicKey: Uint8List.fromList(generated.public),
    sign: (popBytes) => ScommOpenPgp.instance.signPop(
      data: popBytes,
      privateKey: secret,
    ),
  );
}
