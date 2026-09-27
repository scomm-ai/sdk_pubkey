import 'dart:typed_data';

import 'package:dio/dio.dart';

import '../client/mailer_client.dart';
import '../client/pubkey_client.dart';
import '../config/pubkey_config.dart';
import '../constants.dart';
import '../crypto/dart_crypto.dart';
import '../crypto/provider.dart';
import '../engines/pgp.dart';
import '../engines/smime.dart';
import '../errors.dart';

/// Per-account discovery / mailer / MSK runtime.
///
/// Vault create/open/sync/pairing/recovery live in
/// `package:scomm_vault_client` ([KeyVault]). Host apps bind an opened
/// vault's MSK through [attachMsk] / [mskLoader] so directory mutations can
/// still be signed without embedding the legacy vault stack here.
class PubkeyRuntime {
  PubkeyRuntime._({
    required this.accountEmail,
    required this.crypto,
    required this.client,
    required this.mailer,
  });

  final String accountEmail;
  final DartCryptoProvider crypto;
  final PubkeyClient client;
  final MailerClient mailer;

  /// Armed MSK for this account, when known in-process.
  KeyRef? mskKey;

  /// MSK generated during OTP enroll, before arm completes.
  KeyRef? pendingMsk;

  /// Optional loader used by [requireMsk] when [mskKey] is unset (typically
  /// reading [KeyVault.mskSeed] from an opened vault).
  Future<KeyRef?> Function()? mskLoader;

  static final Map<String, PubkeyRuntime> _instances = {};

  static String _normalize(String email) => email.trim().toLowerCase();

  /// Builds the runtime for an email not yet cached by [instance]. Host
  /// apps override this once at startup to supply their Dio / base URLs.
  static PubkeyRuntime Function(String email, {Dio? dio}) factory =
      createPubkeyRuntime;

  /// Gets (or lazily creates, via [factory]) the runtime scoped to [email].
  static PubkeyRuntime instance({required String email, Dio? dio}) {
    final normalized = _normalize(email);
    return _instances[normalized] ??= factory(normalized, dio: dio);
  }

  /// Drops the cached runtime for [email].
  static void clearAccount(String email) {
    _instances.remove(_normalize(email));
  }

  /// Clears every cached runtime (tests only).
  static void resetForTest() {
    _instances.clear();
    factory = createPubkeyRuntime;
  }

  /// Caches [key] as the in-process MSK after a successful directory arm.
  ///
  /// The CKVF vault that durable-stores this seed is owned by
  /// `scomm_vault_client.KeyVault` — call [KeyVault.create] with
  /// `mskSeed` (or open an existing vault) separately.
  Future<void> persistMsk(KeyRef key, {required String email}) async {
    mskKey = key;
    pendingMsk = null;
  }

  /// Sets [mskKey] from raw 32-byte seed bytes (e.g. [KeyVault.mskSeed]).
  Future<KeyRef> attachMsk(Uint8List seed) async {
    final key = await crypto.importPrivateKey(
      PortablePrivateKey(
        algorithm: mskAlgorithm,
        encoding: 'raw-32',
        bytes: seed,
        purpose: Purposes.masterSigning,
      ),
    );
    mskKey = key;
    pendingMsk = null;
    return key;
  }

  /// Returns the armed MSK, loading via [mskLoader] when needed.
  Future<KeyRef> requireMsk() async {
    if (mskKey != null) return mskKey!;
    final loaded = await mskLoader?.call();
    if (loaded != null) {
      mskKey = loaded;
      return loaded;
    }
    throw PubkeyException(
      ErrorCodes.masterKeyNotArmed,
      'Master Identity Key is not armed. Create one on this first device, '
      'or open the local KeyVault that holds it.',
    );
  }
}

/// Builds a discovery/MSK [PubkeyRuntime] for [email].
PubkeyRuntime createPubkeyRuntime(
  String email, {
  Dio? dio,
  String? readBaseUrl,
  String? writeBaseUrl,
  String? mailerBaseUrl,
  // Ignored: vault host is `scomm_vault_client.VaultHostClient`.
  String? vaultBaseUrl,
  // Ignored: legacy DeviceKeyStore removed with the vault split.
  Object? store,
  bool rfc9980Ready = true,
}) {
  final crypto = DartCryptoProvider();
  final pgp = DelegatingPgpEngine(
    advertisedAlgorithms: OpenPgpAlgorithms.advertised(
      rfc9980Ready: rfc9980Ready,
    ),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final smime = DelegatingSmimeEngine(
    advertisedAlgorithms: SmimeAlgorithms.advertised(pqcReady: rfc9980Ready),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final client = PubkeyClient(
    crypto: crypto,
    pgpEngine: pgp,
    smimeEngine: smime,
    readBaseUrl: readBaseUrl,
    writeBaseUrl: writeBaseUrl,
    dio: dio,
  );
  return PubkeyRuntime._(
    accountEmail: email,
    crypto: crypto,
    client: client,
    mailer: MailerClient(
      baseUrl: mailerBaseUrl ?? PubkeyConfig.mailerBaseUrl,
      dio: dio,
    ),
  );
}

Never _engineUnused() {
  throw PubkeyException(
    ErrorCodes.unsupportedAlgorithm,
    'Mail encrypt/decrypt uses a dedicated OpenPGP engine, not the Pubkey engine facade',
  );
}

Future<List<int>> _unsupportedEncrypt({
  required List<int> plaintext,
  required List<int> recipientPublicKey,
  String? algorithm,
}) async =>
    _engineUnused();

Future<List<int>> _unsupportedDecrypt({
  required List<int> ciphertext,
  required List<int> privateKey,
  String? algorithm,
}) async =>
    _engineUnused();

/// Builds a [PubkeyClient] wired to [email]'s cached [PubkeyRuntime].
PubkeyClient createPubkeyClient(String email) =>
    PubkeyRuntime.instance(email: email).client;

/// Builds an account-agnostic [PubkeyClient] for read-only directory lookups.
PubkeyClient createDiscoveryPubkeyClient({
  String? readBaseUrl,
  String? writeBaseUrl,
  String? vaultBaseUrl,
  Dio? dio,
  bool rfc9980Ready = true,
}) {
  final crypto = DartCryptoProvider();
  final pgp = DelegatingPgpEngine(
    advertisedAlgorithms: OpenPgpAlgorithms.advertised(
      rfc9980Ready: rfc9980Ready,
    ),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final smime = DelegatingSmimeEngine(
    advertisedAlgorithms: SmimeAlgorithms.advertised(pqcReady: rfc9980Ready),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  return PubkeyClient(
    crypto: crypto,
    pgpEngine: pgp,
    smimeEngine: smime,
    readBaseUrl: readBaseUrl,
    writeBaseUrl: writeBaseUrl,
    dio: dio,
  );
}
