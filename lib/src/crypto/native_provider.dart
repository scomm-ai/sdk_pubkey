import 'dart:typed_data';

import '../constants.dart';
import '../errors.dart';
import 'provider.dart';

/// Contract for Apple CryptoKit/Keychain, Android Keystore/JCA, Windows CNG,
/// and a Linux provider. This package has no Flutter or FFI dependency, so a
/// host application must supply the concrete adapter.
///
/// These adapters are **not implemented** here. Do not treat this type as a
/// working hardware-backed provider.
abstract class NativeCryptoProvider extends CryptoProvider {
  String get platform;

  @override
  String get kind => 'platform';
}

/// Honest stand-in used until a host registers a real native adapter.
class UnimplementedNativeCryptoProvider extends NativeCryptoProvider {
  UnimplementedNativeCryptoProvider(this.platform);

  @override
  final String platform;

  @override
  String get id => 'native-$platform';

  @override
  Future<CryptoCapabilities> capabilities() async {
    return CryptoCapabilities(
      id: id,
      kind: kind,
      sign: const [],
      verify: const [],
      keyAgreement: const [],
      aead: const [],
      hash: const [],
      kem: const [],
      protections: const [
        KeyProtection.osProtected,
        KeyProtection.hardwareBacked,
      ],
      extractable: const [false],
      random: false,
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
    return false;
  }

  Never _unavailable() {
    throw PubkeyException(
      ErrorCodes.providerUnavailable,
      'Native $platform crypto is not wired in this Dart package. '
      'A Flutter/FFI host must supply CryptoKit, Android Keystore, CNG, '
      'or a Linux provider. The software DartCryptoProvider is the fallback.',
    );
  }

  @override
  Uint8List random(int length) => _unavailable();

  @override
  Future<Uint8List> hash(String algorithm, List<int> data) async =>
      _unavailable();

  @override
  Future<KeyRef> generateKey({
    required String algorithm,
    String? purpose,
    bool extractable = true,
    String protection = KeyProtection.software,
  }) async {
    if (protection == KeyProtection.hardwareBacked ||
        protection == KeyProtection.osProtected) {
      throw PubkeyException(
        ErrorCodes.hardwareProtectionUnavailable,
        'Native $platform hardware-backed keys are not implemented',
      );
    }
    _unavailable();
  }

  @override
  Future<Uint8List> sign(KeyRef key, List<int> payload) async => _unavailable();

  @override
  Future<bool> verify(
    List<int> publicKey,
    List<int> payload,
    List<int> signature, [
    String algorithm = mskAlgorithm,
  ]) async =>
      _unavailable();

  @override
  Future<KeyRef> importPrivateKey(
    PortablePrivateKey portable, {
    bool? extractable,
    String protection = KeyProtection.software,
  }) async =>
      _unavailable();

  @override
  Future<PortablePrivateKey> exportPrivateKey(KeyRef key) async =>
      _unavailable();

  @override
  Future<VaultWrap> wrapVault(
    List<int> plaintext,
    String passphrase, {
    List<int>? salt,
    List<int>? iv,
    int? iterations,
  }) async =>
      _unavailable();

  @override
  Future<Uint8List> unwrapVault(
    List<int> ciphertext,
    String passphrase,
    List<int> salt,
    List<int> iv,
    int iterations,
  ) async =>
      _unavailable();
}
