import '../errors.dart';

/// OpenPGP packet engine. Packet I/O only — primitives stay on CryptoProvider.
///
/// Hosts typically wrap `secmail_crypto_sdk` via [DelegatingPgpEngine].
/// This package does not depend on Flutter or the crypto SDK.
abstract class PgpEngine {
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

class UnsupportedPgpEngine implements PgpEngine {
  const UnsupportedPgpEngine();

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
      'OpenPGP engine is not implemented; packet I/O is deferred',
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
      'OpenPGP engine is not implemented; packet I/O is deferred',
    );
  }
}

/// Host-supplied packet engine. Typical impl wraps secmail_crypto_sdk.
class DelegatingPgpEngine implements PgpEngine {
  DelegatingPgpEngine({
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
