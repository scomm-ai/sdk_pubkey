import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart' hide parseGrantV1;
import 'package:scomm_vault_client/scomm_vault_client.dart' hide protocolVersion;

import '../test/openssl_crypto.dart';

const _usage = '''
vault_dev — debug client for a local vault host.
A release build does not include this client.

dart run bin/vault_dev.dart --url http://127.0.0.1:3001 <command> [flags]

Commands:
  identity       mailbox SHA-256 identity_id
  pepper-keys    GET /v1/pw-oprf/keys
  fetch-msk      GET Discovery /v1/msk for the mailbox hash
  request-otp    Mailbox OTP challenge (vault_open, replace_msk, vault_backup, recovery_envelope, recovery_generation)
  open           POST /v1/vault/open
  rebind         POST /v1/vault/{vault_id}/msk
  current        GET /v1/vault/{vault_id}/current
  generation     GET /v1/vault/{vault_id}/generation/{n}
  pending        GET /v1/vault/{vault_id}/pending-mutations
  pairing-create POST /v1/pairing/{session_id}

Flags:
  --url          Loopback vault URL (required)
  --discovery    Loopback discovery URL (default http://127.0.0.1:3000)
  --email        Mailbox address
  --otp          Mailbox OTP (open, rebind). Not printed.
  --challenge    Challenge id from request-otp
  --purpose      OTP purpose (request-otp). Default vault_open
  --msk          Raw 32-byte MSK seed (open, rebind)
  --vault-id     64 hex vault id (open optional; required for reads and rebind)
  --grant        Single-use vault grant for current, generation, pending. Not printed.
  --generation   Generation number
  --identity     mailbox SHA-256 for pairing-create
  --session      Pairing session id
  --device-name  Pairing device name
''';

class DevUsage implements Exception {
  DevUsage(this.message);
  final String message;
}

class DevArgs {
  DevArgs({
    required this.url,
    required this.discovery,
    required this.command,
    this.email,
    this.otp,
    this.challengeId,
    this.purpose,
    this.mskIn,
    this.vaultId,
    this.grant,
    this.generation,
    this.identityId,
    this.sessionId,
    this.deviceName,
  });

  final String url;
  final String discovery;
  final String command;
  final String? email;
  final String? otp;
  final String? challengeId;
  final String? purpose;
  final String? mskIn;
  final String? vaultId;
  final String? grant;
  final int? generation;
  final String? identityId;
  final String? sessionId;
  final String? deviceName;
}

DevArgs parseVaultDevArgs(List<String> args) {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    throw DevUsage(_usage);
  }
  String? url;
  var discovery = 'http://127.0.0.1:3000';
  String? email;
  String? otp;
  String? challengeId;
  String? purpose;
  String? mskIn;
  String? vaultId;
  String? grant;
  int? generation;
  String? identityId;
  String? sessionId;
  String? deviceName;
  String? command;
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    String take(String name) {
      if (i + 1 >= args.length) throw DevUsage('$name needs a value');
      i += 1;
      return args[i];
    }

    switch (arg) {
      case '--url':
        url = take(arg);
      case '--discovery':
        discovery = take(arg);
      case '--email':
        email = take(arg);
      case '--otp':
        otp = take(arg);
      case '--challenge':
        challengeId = take(arg);
      case '--purpose':
        purpose = take(arg);
      case '--msk':
        mskIn = take(arg);
      case '--vault-id':
        vaultId = take(arg);
      case '--grant':
        grant = take(arg);
      case '--generation':
        generation = int.tryParse(take(arg));
        if (generation == null) throw DevUsage('--generation must be an integer');
      case '--identity':
        identityId = take(arg);
      case '--session':
        sessionId = take(arg);
      case '--device-name':
        deviceName = take(arg);
      default:
        if (arg.startsWith('-')) throw DevUsage('Unknown flag $arg');
        if (command != null) throw DevUsage('Unexpected argument $arg');
        command = arg;
    }
  }
  if (url == null || url.isEmpty) throw DevUsage('--url is required\n\n$_usage');
  if (command == null) throw DevUsage('command is required\n\n$_usage');
  return DevArgs(
    url: url,
    discovery: discovery,
    command: command,
    email: email,
    otp: otp,
    challengeId: challengeId,
    purpose: purpose,
    mskIn: mskIn,
    vaultId: vaultId,
    grant: grant,
    generation: generation,
    identityId: identityId,
    sessionId: sessionId,
    deviceName: deviceName,
  );
}

void _preloadOpenPgp() {
  final fromEnv = Platform.environment['SCOMM_OPENPGP_LIB'];
  if (fromEnv != null && fromEnv.isNotEmpty && File(fromEnv).existsSync()) {
    DynamicLibrary.open(fromEnv);
    return;
  }
  final fileName = Platform.isWindows
      ? 'scomm_openpgp.dll'
      : Platform.isMacOS
          ? 'libscomm_openpgp.dylib'
          : 'libscomm_openpgp.so';
  final triple = _hostTriple();
  if (triple.isEmpty) {
    throw DevUsage('vault_dev has no OpenPGP library for this platform');
  }
  final roots = <Directory>[
    Directory.current,
    File(Platform.script.toFilePath()).parent,
  ];
  final seen = <String>{};
  for (final start in roots) {
    var dir = start;
    for (var depth = 0; depth < 6; depth++) {
      final candidates = [
        Directory(
          '${dir.path}${Platform.pathSeparator}prebuilt${Platform.pathSeparator}$triple',
        ),
        Directory(
          '${dir.path}${Platform.pathSeparator}scomm-openpgp${Platform.pathSeparator}prebuilt${Platform.pathSeparator}$triple',
        ),
      ];
      for (final folder in candidates) {
        final path = '${folder.path}${Platform.pathSeparator}$fileName';
        if (!seen.add(path)) continue;
        if (File(path).existsSync()) {
          DynamicLibrary.open(path);
          return;
        }
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
  }
  throw DevUsage(
    'Could not find $fileName. Set SCOMM_OPENPGP_LIB to the prebuilt library.',
  );
}

String _hostTriple() {
  if (Platform.isWindows) {
    if (Abi.current() == Abi.windowsX64) return 'x86_64-pc-windows-msvc';
    if (Abi.current() == Abi.windowsArm64) return 'aarch64-pc-windows-msvc';
    if (Abi.current() == Abi.windowsIA32) return 'i686-pc-windows-msvc';
  }
  if (Platform.isLinux) {
    if (Abi.current() == Abi.linuxX64) return 'x86_64-unknown-linux-gnu';
    if (Abi.current() == Abi.linuxArm64) return 'aarch64-unknown-linux-gnu';
  }
  if (Platform.isMacOS) {
    if (Abi.current() == Abi.macosX64) return 'x86_64-apple-darwin';
    if (Abi.current() == Abi.macosArm64) return 'aarch64-apple-darwin';
  }
  return '';
}

void _requireLoopback(String url, String label) {
  final uri = Uri.tryParse(url);
  final host = uri?.host.toLowerCase();
  final loopback = host == 'localhost' || host == '127.0.0.1' || host == '::1';
  final schemeOk = uri != null && (uri.scheme == 'http' || uri.scheme == 'https');
  if (!schemeOk || !loopback) {
    throw DevUsage('$label only talks to loopback (localhost or 127.0.0.1)');
  }
}

String _email(DevArgs args) {
  final email = args.email?.trim();
  if (email == null || email.isEmpty) throw DevUsage('--email is required');
  return email;
}

Future<void> vaultDevMain(List<String> args) async {
  try {
    final parsed = parseVaultDevArgs(args);
    _requireLoopback(parsed.url, 'vault_dev');
    _requireLoopback(parsed.discovery, '--discovery');
    _preloadOpenPgp();
    OpensslCryptoProvider.installDigests();
    final email = parsed.email;
    stderr.writeln(
      'vault=${parsed.url} discovery=${parsed.discovery} '
      'mailbox=${email == null || email.isEmpty ? '-' : emailSha256Hex(email)} '
      'command=${parsed.command}',
    );
    final result = await _run(parsed);
    stdout.writeln(jsonEncode(result));
  } on DevUsage catch (error) {
    stderr.writeln(error.message);
    final help = args.isEmpty || args.contains('--help') || args.contains('-h');
    exit(help ? 0 : 64);
  } on PubkeyException catch (error) {
    stderr.writeln('${error.code}: ${error.message}');
    exit(1);
  } on VaultClientException catch (error) {
    stderr.writeln('${error.code}: ${error.message}');
    exit(1);
  }
}

Future<Map<String, Object?>> _run(DevArgs args) async {
  final crypto = opensslCrypto();
  final vault = VaultHostClient(args.url);
  final mailer = MailerClient(baseUrl: args.discovery);
  switch (args.command) {
    case 'identity':
      return {'identity_id': vault.identityId(_email(args))};
    case 'pepper-keys':
      final keys = await vault.pepperKeys();
      return {
        'current_kid': keys.currentKid,
        'kids': [for (final key in keys.keys) key.kid],
      };
    case 'fetch-msk':
      return _fetchMsk(args);
    case 'request-otp':
      return _requestOtp(crypto, mailer, args);
    case 'open':
      return _open(crypto, vault, mailer, args);
    case 'rebind':
      return _rebind(crypto, vault, mailer, args);
    case 'current':
      return _read(vault, args, (id, auth) => vault.current(id, auth));
    case 'generation':
      final n = args.generation;
      if (n == null) throw DevUsage('--generation is required');
      return _read(vault, args, (id, auth) => vault.generation(id, n, auth));
    case 'pending':
      return _read(vault, args, (id, auth) async {
        final list = await vault.pendingMutations(id, auth);
        return {'mutations': list.length};
      });
    case 'pairing-create':
      final session = args.sessionId;
      final identity = args.identityId;
      final name = args.deviceName;
      if (session == null || identity == null || name == null) {
        throw DevUsage('--session, --identity, and --device-name are required');
      }
      final body = await vault.createPairing(session, {
        'identity_id': identity,
        'device_name': name,
      });
      return _public(body);
    default:
      throw DevUsage('Unknown command ${args.command}\n\n$_usage');
  }
}

Future<Map<String, Object?>> _fetchMsk(DevArgs args) async {
  final sha = emailSha256Hex(_email(args));
  final dio = MailerClient(baseUrl: args.discovery).dio;
  final response = await dio.get<Object?>(
    '${args.discovery}/v1/msk',
    queryParameters: {'sha256': sha},
  );
  final body = response.data;
  if (body is! Map) return {'ok': false};
  return {
    'identity_id': body['identity_id'],
    'algorithm': body['algorithm'],
    'public_key_bytes': body['public_key'] is String
        ? decodeBase64Url(body['public_key'] as String).length
        : null,
    'archived': body['archived_public_keys'] is List
        ? (body['archived_public_keys'] as List).length
        : 0,
  };
}

Future<Map<String, Object?>> _requestOtp(
  CryptoProvider crypto,
  MailerClient mailer,
  DevArgs args,
) async {
  final purpose = args.purpose ?? MailerOtpPurpose.vaultOpen;
  List<int>? publicKey;
  if (purpose == MailerOtpPurpose.replaceMsk ||
      purpose == MailerOtpPurpose.enroll) {
    publicKey = (await _mskKey(crypto, args)).publicKey;
  }
  final id = await mailer.requestOtp(
    email: _email(args),
    purpose: purpose,
    mskPublicKey: publicKey,
  );
  return {'challenge_id': id, 'purpose': purpose};
}

Future<Map<String, Object?>> _open(
  CryptoProvider crypto,
  VaultHostClient vault,
  MailerClient mailer,
  DevArgs args,
) async {
  final email = _email(args);
  final grant = await _redeem(mailer, args, MailerOtpPurpose.vaultOpen);
  final vaultId = args.vaultId ?? _randomVaultId();
  final proof = await _proof(
    crypto,
    args,
    operation: 'vault_open',
    principal: grant.requireIdentityId,
    payload: {'vault_id': vaultId, 'grant_jti': _jti(grant.otpGrant)},
  );
  final result = await vault.openVault(
    identityId: grant.requireIdentityId,
    vaultId: vaultId,
    mailboxSha256: emailSha256Hex(email),
    otpGrant: grant.otpGrant,
    msk: proof.msk,
    mskProof: proof.envelope,
  );
  return {..._public(result), 'vault_id': vaultId};
}

Future<Map<String, Object?>> _rebind(
  CryptoProvider crypto,
  VaultHostClient vault,
  MailerClient mailer,
  DevArgs args,
) async {
  final email = _email(args);
  final vaultId = args.vaultId;
  if (vaultId == null || vaultId.isEmpty) throw DevUsage('--vault-id is required');
  final grant = await _redeem(mailer, args, MailerOtpPurpose.replaceMsk);
  final vaultGrant = grant.vaultGrant;
  if (vaultGrant == null || vaultGrant.isEmpty) {
    throw DevUsage('replace_msk did not return a vault grant');
  }
  final claims = parseGrantV1(vaultGrant);
  if (claims == null) throw DevUsage('vault grant could not be read');
  final proof = await _proof(
    crypto,
    args,
    operation: 'arm_replacement_msk',
    principal: claims.identityId,
    payload: {'vault_id': vaultId, 'grant_jti': claims.jti},
  );
  final result = await vault.rebindMsk(
    identityId: claims.identityId,
    vaultId: vaultId,
    mailboxSha256: emailSha256Hex(email),
    otpGrant: vaultGrant,
    msk: proof.msk,
    mskProof: proof.envelope,
  );
  return _public(result);
}

Future<MailerOtpGrant> _redeem(
  MailerClient mailer,
  DevArgs args,
  String purpose,
) async {
  final otp = args.otp;
  final challenge = args.challengeId;
  if (otp == null || challenge == null) {
    throw DevUsage('--otp and --challenge are required');
  }
  mailer.rememberOtpChallenge(
    email: _email(args),
    purpose: purpose,
    challengeId: challenge,
  );
  return mailer.verifyOtp(email: _email(args), otp: otp, purpose: purpose);
}

Future<Map<String, Object?>> _read(
  VaultHostClient vault,
  DevArgs args,
  Future<Map<String, dynamic>> Function(String, VaultAuthorization) call,
) async {
  final vaultId = args.vaultId;
  final grant = args.grant;
  if (vaultId == null || grant == null) {
    throw DevUsage('--vault-id and --grant are required');
  }
  return _public(await call(vaultId, VaultAuthorization.otpGrant(grant)));
}

Future<KeyRef> _mskKey(CryptoProvider crypto, DevArgs args) async {
  final path = args.mskIn;
  if (path == null) throw DevUsage('--msk is required');
  final seed = await File(path).readAsBytes();
  if (seed.length != 32) throw DevUsage('$path must be a 32-byte MSK seed');
  return crypto.importPrivateKey(
    PortablePrivateKey(algorithm: mskAlgorithm, encoding: 'raw-32', bytes: seed),
  );
}

class _Proof {
  _Proof(this.msk, this.envelope);
  final Map<String, dynamic> msk;
  final Map<String, dynamic> envelope;
}

Future<_Proof> _proof(
  CryptoProvider crypto,
  DevArgs args, {
  required String operation,
  required String principal,
  required Map<String, Object?> payload,
}) async {
  final key = await _mskKey(crypto, args);
  final publicKey = key.publicKey;
  if (publicKey == null || publicKey.length != 32) {
    throw DevUsage('MSK public key is missing');
  }
  final timestamp = DateTime.now().millisecondsSinceEpoch;
  final nonce = base64Url.encode(Random.secure().nextBytes(16)).replaceAll('=', '');
  final bytes = canonicalSignedBytes(
    protocolVersion: protocolVersion,
    operation: operation,
    principal: principal,
    timestamp: timestamp,
    nonce: nonce,
    payload: payload,
  );
  final signature = await crypto.sign(key, bytes);
  return _Proof(
    {'algorithm': mskAlgorithm, 'public_key': encodeBase64Url(publicKey)},
    {
      'protocol_version': protocolVersion,
      'principal': principal,
      'operation': operation,
      'timestamp': timestamp,
      'nonce': nonce,
      'payload': payload,
      'signature': {
        'algorithm': mskAlgorithm,
        'value': encodeBase64Url(signature),
      },
    },
  );
}

String _jti(String grant) {
  final claims = parseGrantV1(grant);
  if (claims == null) throw DevUsage('Grant could not be read');
  return claims.jti;
}

String _randomVaultId() {
  final bytes = Random.secure().nextBytes(32);
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Map<String, Object?> _public(Map<String, dynamic> body) {
  const drop = {
    'otp_grant',
    'vault_grant',
    'oprf_token',
    'pairing_read_token',
    'ciphertext',
    'msk_signature',
  };
  return {
    for (final entry in body.entries)
      if (!drop.contains(entry.key)) entry.key: entry.value,
  };
}

extension on Random {
  Uint8List nextBytes(int length) {
    final out = Uint8List(length);
    for (var i = 0; i < length; i++) {
      out[i] = nextInt(256);
    }
    return out;
  }
}
