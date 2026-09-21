import '../errors.dart';

/// S/MIME CMS/X.509 engine. CMS I/O only — primitives stay on CryptoProvider.
///
/// Hosts typically wrap `secmail_crypto_sdk` via [DelegatingSmimeEngine].
/// This package does not depend on Flutter or the crypto SDK.
abstract class SmimeEngine {
  bool get available;
  List<String> get advertisedAlgorithms;

  Future<List<int>> encrypt({
    required List<int> plaintext,
    required List<int> recipientPublicKey,
    String? algorithm,
  });

  Future<List<int>> decrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String? algorithm,
  });
}

class UnsupportedSmimeEngine implements SmimeEngine {
  const UnsupportedSmimeEngine();

  @override
  bool get available => false;

  @override
  List<String> get advertisedAlgorithms => const [];

  @override
  Future<List<int>> encrypt({
    required List<int> plaintext,
    required List<int> recipientPublicKey,
    String? algorithm,
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'S/MIME CMS engine is not implemented; X.509/CMS I/O is deferred',
    );
  }

  @override
  Future<List<int>> decrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String? algorithm,
  }) {
    throw PubkeyException(
      ErrorCodes.unsupportedAlgorithm,
      'S/MIME CMS engine is not implemented; X.509/CMS I/O is deferred',
    );
  }
}

/// Host-supplied CMS engine. Typical impl wraps secmail_crypto_sdk.
class DelegatingSmimeEngine implements SmimeEngine {
  DelegatingSmimeEngine({
    required this.advertisedAlgorithms,
    required Future<List<int>> Function({
      required List<int> plaintext,
      required List<int> recipientPublicKey,
      String? algorithm,
    })
    encrypt,
    required Future<List<int>> Function({
      required List<int> ciphertext,
      required List<int> privateKey,
      String? algorithm,
    })
    decrypt,
  }) : _encrypt = encrypt,
       _decrypt = decrypt;

  @override
  bool get available => advertisedAlgorithms.isNotEmpty;

  @override
  final List<String> advertisedAlgorithms;

  final Future<List<int>> Function({
    required List<int> plaintext,
    required List<int> recipientPublicKey,
    String? algorithm,
  })
  _encrypt;

  final Future<List<int>> Function({
    required List<int> ciphertext,
    required List<int> privateKey,
    String? algorithm,
  })
  _decrypt;

  @override
  Future<List<int>> encrypt({
    required List<int> plaintext,
    required List<int> recipientPublicKey,
    String? algorithm,
  }) {
    return _encrypt(
      plaintext: plaintext,
      recipientPublicKey: recipientPublicKey,
      algorithm: algorithm,
    );
  }

  @override
  Future<List<int>> decrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String? algorithm,
  }) {
    return _decrypt(
      ciphertext: ciphertext,
      privateKey: privateKey,
      algorithm: algorithm,
    );
  }
}
