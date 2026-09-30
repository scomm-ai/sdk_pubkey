import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';

import '../test/openssl_crypto.dart';

const _usage = '''
pubkey_dev — debug client for a local pubkey directory.
A release build does not include this client.

dart run bin/pubkey_dev.dart --url http://127.0.0.1:3000 <command> [flags]

Commands:
  request-otp  Send the mailbox OTP challenge for a new MSK
  arm       Redeem that challenge and arm the MSK
  enroll    Arm a new MSK with a mailbox OTP
  replace   Replace the armed MSK with a mailbox OTP
  sign      Publish an Ed25519 S/MIME verification key
  sign-smime-pqc  Publish an ML-DSA-65 S/MIME verification key
  sign-pgp  Publish an OpenPGP Ed25519 verification key
  sign-pqc  Publish an OpenPGP ML-DSA-65+Ed25519 verification key
  encrypt   Publish an S/MIME X25519 key-agreement key
  encrypt-pgp  Publish an OpenPGP Curve25519 encryption key
  encrypt-pgp-pqc  Publish an OpenPGP ML-KEM-768+X25519 encryption key
  retire    Retire a key by its scomm key_id (16 hex digits)
  fetch     Fetch a verification key by its 16-hex key-id
  fetch-pgp-pqc  Fetch the active OpenPGP ML-KEM-768+X25519 encryption key

Flags:
  --url       Loopback directory URL (required)
  --email     Mailbox address
  --otp       Mailbox OTP for arm, enroll, and replace
  --challenge Challenge id from request-otp (arm)
  --msk       Raw 32-byte MSK seed (arm, sign, sign-smime-pqc, sign-pgp, sign-pqc, encrypt, encrypt-pgp, encrypt-pgp-pqc, retire)
  --msk-out   File for the new MSK seed (request-otp, enroll, replace)
  --key-id    16-hex scomm key_id for retire or fetch
''';

final _ed25519SpkiPrefix = Uint8List.fromList([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

final _x25519SpkiPrefix = Uint8List.fromList([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

class DevUsage implements Exception {
  DevUsage(this.message);

  final String message;
}

class DevArgs {
  DevArgs({
    required this.url,
    required this.command,
    required this.email,
    this.otp,
    this.mskIn,
    this.mskOut,
    this.keyId,
    this.challengeId,
  });

  final String url;
  final String command;
  final String email;
  final String? otp;
  final String? mskIn;
  final String? mskOut;
  final String? keyId;
  final String? challengeId;
}

DevArgs parseDevArgs(List<String> args) {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    throw DevUsage(_usage);
  }
  String? url;
  String? email;
  String? otp;
  String? mskIn;
  String? mskOut;
  String? keyId;
  String? challengeId;
  String? command;
  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    String take(String name) {
      if (i + 1 >= args.length) {
        throw DevUsage('$name needs a value');
      }
      i += 1;
      return args[i];
    }

    switch (arg) {
      case '--url':
        url = take(arg);
      case '--email':
        email = take(arg);
      case '--otp':
        otp = take(arg);
      case '--msk':
        mskIn = take(arg);
      case '--msk-out':
        mskOut = take(arg);
      case '--key-id':
        keyId = take(arg);
      case '--challenge':
        challengeId = take(arg);
      default:
        if (arg.startsWith('-')) {
          throw DevUsage('Unknown flag $arg');
        }
        if (command != null) {
          throw DevUsage('Unexpected argument $arg');
        }
        command = arg;
    }
  }
  if (url == null || url.isEmpty) {
    throw DevUsage('--url is required\n\n$_usage');
  }
  _requireLoopback(url);
  if (command == null) {
    throw DevUsage('A command is required\n\n$_usage');
  }
  if (email == null || email.trim().isEmpty) {
    throw DevUsage('--email is required');
  }
  const known = {
    'request-otp',
    'arm',
    'enroll',
    'replace',
    'sign',
    'sign-smime-pqc',
    'sign-pgp',
    'sign-pqc',
    'encrypt',
    'encrypt-pgp',
    'encrypt-pgp-pqc',
    'retire',
    'fetch',
    'fetch-pgp-pqc',
  };
  if (!known.contains(command)) {
    throw DevUsage('Unknown command $command');
  }
  if ((command == 'arm' || command == 'enroll' || command == 'replace') &&
      (otp == null || otp.isEmpty)) {
    throw DevUsage('--otp is required for $command');
  }
  if (command == 'arm' && (challengeId == null || challengeId.isEmpty)) {
    throw DevUsage('--challenge is required for arm');
  }
  if ((command == 'request-otp' ||
          command == 'enroll' ||
          command == 'replace') &&
      (mskOut == null || mskOut.isEmpty)) {
    throw DevUsage('--msk-out is required for $command');
  }
  if ((command == 'arm' ||
          command == 'sign' ||
          command == 'sign-smime-pqc' ||
          command == 'sign-pgp' ||
          command == 'sign-pqc' ||
          command == 'encrypt' ||
          command == 'encrypt-pgp' ||
          command == 'encrypt-pgp-pqc' ||
          command == 'retire') &&
      (mskIn == null || mskIn.isEmpty)) {
    throw DevUsage('--msk is required for $command');
  }
  if (command == 'retire' || command == 'fetch') {
    if (keyId == null || keyId.isEmpty) {
      throw DevUsage('--key-id is required for $command');
    }
  }
  if (command == 'retire' && int.tryParse(keyId!) == null) {
    throw DevUsage('--key-id for retire must be the numeric key id');
  }
  return DevArgs(
    url: url,
    command: command,
    email: email.trim(),
    otp: otp,
    mskIn: mskIn,
    mskOut: mskOut,
    keyId: keyId,
    challengeId: challengeId,
  );
}

/// `dart run` does not copy the Flutter FFI plugin next to the process.
/// Load the prebuilt library by full path so the later basename open succeeds.
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
    throw DevUsage('pubkey_dev has no OpenPGP library for this platform');
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
        Directory('${dir.path}${Platform.pathSeparator}prebuilt${Platform.pathSeparator}$triple'),
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

void _requireLoopback(String url) {
  final uri = Uri.tryParse(url);
  final host = uri?.host.toLowerCase();
  final loopback = host == 'localhost' || host == '127.0.0.1' || host == '::1';
  final schemeOk = uri != null && (uri.scheme == 'http' || uri.scheme == 'https');
  if (!schemeOk || !loopback) {
    throw DevUsage(
      'pubkey_dev only talks to a loopback directory (localhost or 127.0.0.1)',
    );
  }
}

Future<void> pubkeyDevMain(List<String> args) async {
  try {
    final parsed = parseDevArgs(args);
    _preloadOpenPgp();
    OpensslCryptoProvider.installDigests();
    stderr.writeln(
      'host=${parsed.url} mailbox=${emailSha256Hex(parsed.email)} command=${parsed.command}',
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
  }
}

Future<Map<String, Object?>> _run(DevArgs args) async {
  final crypto = opensslCrypto();
  final client = PubkeyClient(
    crypto: crypto,
    readBaseUrl: args.url,
    writeBaseUrl: args.url,
  );
  switch (args.command) {
    case 'request-otp':
      return _requestOtp(crypto, args, MailerOtpPurpose.enroll);
    case 'arm':
      return _armExisting(crypto, client, args);
    case 'enroll':
      return _armMsk(crypto, client, args, MailerOtpPurpose.enroll);
    case 'replace':
      return _armMsk(crypto, client, args, MailerOtpPurpose.replaceMsk);
    case 'sign':
      return _sign(crypto, client, args);
    case 'sign-smime-pqc':
      return _signSmimePqc(crypto, client, args);
    case 'sign-pgp':
      return _signPgp(crypto, client, args);
    case 'sign-pqc':
      return _signPqc(crypto, client, args);
    case 'encrypt':
      return _encrypt(crypto, client, args);
    case 'encrypt-pgp':
      return _encryptPgp(crypto, client, args);
    case 'encrypt-pgp-pqc':
      return _encryptPgpPqc(crypto, client, args);
    case 'retire':
      final retired = await client.retireKey(
        email: args.email,
        keyId: args.keyId!,
        mskKey: await _loadMsk(crypto, args.mskIn!),
      );
      return _publicResult(retired);
    case 'fetch':
      final fetched = await client.getVerificationKey(
        email: args.email,
        keyId: args.keyId!,
      );
      return _publicResult(fetched);
    case 'fetch-pgp-pqc':
      final fetched = await client.getBestKey(
        email: args.email,
        purpose: Purposes.encryption,
        capabilities: {
          'families': {
            Families.pgp: [OpenPgpAlgorithms.mlkem768X25519],
          },
        },
      );
      return _publicResult(fetched);
    default:
      throw DevUsage('Unknown command ${args.command}');
  }
}

Future<Map<String, Object?>> _requestOtp(
  CryptoProvider crypto,
  DevArgs args,
  String purpose,
) async {
  final msk = await crypto.generateSigningKey(mskAlgorithm);
  final mailer = MailerClient(baseUrl: args.url);
  final challengeId = await mailer.requestOtp(
    email: args.email,
    purpose: purpose,
    mskPublicKey: msk.publicKey,
  );
  final exported = await crypto.exportPrivateKey(msk);
  await File(args.mskOut!).writeAsBytes(exported.bytes, flush: true);
  stderr.writeln(
    'wrote MSK seed (${exported.bytes.length} bytes) to ${args.mskOut}',
  );
  return {'status': 'pending', 'id': challengeId};
}

Future<Map<String, Object?>> _armExisting(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final redeemed = await client.respondToChallenge(
    mailbox: args.email,
    challengeId: args.challengeId!,
    response: {'code': args.otp!},
  );
  final grant = redeemed.raw['otp_grant'];
  if (grant is! String || grant.isEmpty) {
    throw PubkeyException(
      ErrorCodes.otpGrantInvalid,
      'Challenge response did not include an otp_grant',
    );
  }
  final armed = await client.verifyEnrollForIdentity(
    email: args.email,
    otpGrant: grant,
    mskKey: await _loadMsk(crypto, args.mskIn!),
  );
  return _publicResult(armed);
}

Future<Map<String, Object?>> _armMsk(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
  String purpose,
) async {
  final msk = await crypto.generateSigningKey(mskAlgorithm);
  final mailer = MailerClient(baseUrl: args.url);
  await mailer.requestOtp(
    email: args.email,
    purpose: purpose,
    mskPublicKey: msk.publicKey,
  );
  final grant = await mailer.verifyOtp(
    email: args.email,
    otp: args.otp!,
    purpose: purpose,
  );
  final dynamic armed;
  if (purpose == MailerOtpPurpose.replaceMsk) {
    armed = await client.verifyReplaceForIdentity(
      identityId: emailSha256Hex(args.email),
      otpGrant: grant.otpGrant,
      mskKey: msk,
    );
  } else {
    armed = await client.verifyEnrollForIdentity(
      email: args.email,
      otpGrant: grant.otpGrant,
      mskKey: msk,
    );
  }
  final exported = await crypto.exportPrivateKey(msk);
  await File(args.mskOut!).writeAsBytes(exported.bytes, flush: true);
  stderr.writeln('wrote MSK seed (${exported.bytes.length} bytes) to ${args.mskOut}');
  return _publicResult(armed);
}

Future<Map<String, Object?>> _sign(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final signing = await crypto.generateSigningKey(mskAlgorithm);
  final spki = _spki(_ed25519SpkiPrefix, signing.publicKey!);
  final armed = await client.setSigningKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    contentSigningKey: signing,
    artifact: {
      'family': Families.smime,
      'purpose': Purposes.verify,
      'algorithm': 'smime-ed25519',
      'public_material': encodeBase64Url(spki),
    },
  );
  return {
    ..._publicResult(armed),
    'scomm_key_id': ScommKeyId.derive(spki),
  };
}

Future<Map<String, Object?>> _signSmimePqc(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final signing = generateSmimeMlDsaKey(args.email);
  final armed = await client.setSigningKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    compositePopSigner: signing.sign,
    artifact: {
      'family': Families.pq,
      'purpose': Purposes.verify,
      'algorithm': SmimeAlgorithms.mldsa65,
      'public_material': encodeBase64Url(signing.publicKey),
    },
  );
  return {
    ..._publicResult(armed),
    'scomm_key_id': ScommKeyId.derive(signing.publicKey),
    'algorithm': SmimeAlgorithms.mldsa65,
  };
}

Future<Map<String, Object?>> _signPgp(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final signing = await crypto.generateSigningKey(mskAlgorithm);
  final packet = openPgpEd25519Packet(signing.publicKey!);
  final armed = await client.setSigningKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    contentSigningKey: signing,
    artifact: {
      'family': Families.pgp,
      'purpose': Purposes.verify,
      'algorithm': OpenPgpAlgorithms.ed25519,
      'public_material': encodeBase64Url(packet),
    },
  );
  return {
    ..._publicResult(armed),
    'scomm_key_id': ScommKeyId.derive(
      packet,
      purpose: Purposes.verify,
      algorithm: OpenPgpAlgorithms.ed25519,
    ),
    'algorithm': OpenPgpAlgorithms.ed25519,
  };
}

Future<Map<String, Object?>> _signPqc(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final signing = generateOpenPgpPqcSigningKey(args.email);
  final armed = await client.setSigningKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    compositePopSigner: signing.sign,
    artifact: {
      'family': Families.pgp,
      'purpose': Purposes.verify,
      'algorithm': OpenPgpAlgorithms.mldsa65Ed25519,
      'public_material': encodeBase64Url(signing.publicKey),
    },
  );
  return {
    ..._publicResult(armed),
    'scomm_key_id': ScommKeyId.derive(signing.publicKey),
    'algorithm': OpenPgpAlgorithms.mldsa65Ed25519,
  };
}

Future<Map<String, Object?>> _encrypt(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final agreement = await crypto.generateKey(
    algorithm: 'x25519',
    purpose: Purposes.keyAgreement,
  );
  final spki = _spki(_x25519SpkiPrefix, agreement.publicKey!);
  final issued = await client.requestEncryptionKeyChallenge(
    email: args.email,
    family: Families.smime,
    algorithm: 'smime-x25519',
    publicMaterial: encodeBase64Url(spki),
    mskKey: await _loadMsk(crypto, args.mskIn!),
  );
  final plaintext = await _recoverChallengeNonce(crypto, agreement, issued);
  final armed = await client.setEncryptionKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    artifact: {
      'family': Families.smime,
      'purpose': 'key_agreement',
      'algorithm': 'smime-x25519',
      'public_material': encodeBase64Url(spki),
    },
    decryptProof: {
      'challenge_id': issued['challenge_id'],
      'plaintext': encodeBase64Url(plaintext),
    },
  );
  return _publicResult(armed);
}

Future<Map<String, Object?>> _encryptPgp(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final agreement = await crypto.generateKey(
    algorithm: 'x25519',
    purpose: Purposes.keyAgreement,
  );
  final publicMaterial = encodeBase64Url(
    openPgpCv25519Packet(agreement.publicKey!),
  );
  final issued = await client.requestEncryptionKeyChallenge(
    email: args.email,
    family: Families.pgp,
    algorithm: OpenPgpAlgorithms.cv25519,
    publicMaterial: publicMaterial,
    mskKey: await _loadMsk(crypto, args.mskIn!),
  );
  final plaintext = await _recoverChallengeNonce(crypto, agreement, issued);
  final armed = await client.setEncryptionKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    artifact: {
      'family': Families.pgp,
      'purpose': Purposes.encryption,
      'algorithm': OpenPgpAlgorithms.cv25519,
      'public_material': publicMaterial,
    },
    decryptProof: {
      'challenge_id': issued['challenge_id'],
      'plaintext': encodeBase64Url(plaintext),
    },
  );
  return {
    ..._publicResult(armed),
    'algorithm': OpenPgpAlgorithms.cv25519,
  };
}

Future<Map<String, Object?>> _encryptPgpPqc(
  CryptoProvider crypto,
  PubkeyClient client,
  DevArgs args,
) async {
  final generated = generateOpenPgpPqcEncryptionKey(args.email);
  final publicMaterial = encodeBase64Url(generated.publicKey);
  final issued = await client.requestEncryptionKeyChallenge(
    email: args.email,
    family: Families.pgp,
    algorithm: OpenPgpAlgorithms.mlkem768X25519,
    publicMaterial: publicMaterial,
    mskKey: await _loadMsk(crypto, args.mskIn!),
  );
  final kem = issued['kem_ciphertext'] as String?;
  final ephemeral = issued['ephemeral_public'] as String?;
  if (kem == null || ephemeral == null) {
    throw DevUsage('Hybrid encryption challenge is missing KEM material');
  }
  final shared = openPgpHybridShared(
    secret: generated.secret,
    kemCiphertext: decodeBase64Url(kem),
    ephemeralX25519: decodeBase64Url(ephemeral),
  );
  final key = await crypto.hash('sha-256', shared);
  final wrapped = decodeBase64Url(issued['ciphertext'] as String);
  if (wrapped.length < 28) {
    throw DevUsage('Encryption challenge ciphertext is too short');
  }
  final plaintext = opensslAes256GcmDecrypt(
    key: key,
    nonce: wrapped.sublist(0, 12),
    tag: wrapped.sublist(12, 28),
    ciphertext: wrapped.sublist(28),
  );
  final armed = await client.setEncryptionKeyWithProof(
    email: args.email,
    mskKey: await _loadMsk(crypto, args.mskIn!),
    artifact: {
      'family': Families.pgp,
      'purpose': Purposes.encryption,
      'algorithm': OpenPgpAlgorithms.mlkem768X25519,
      'public_material': publicMaterial,
    },
    decryptProof: {
      'challenge_id': issued['challenge_id'],
      'plaintext': encodeBase64Url(plaintext),
    },
  );
  return {
    ..._publicResult(armed),
    'algorithm': OpenPgpAlgorithms.mlkem768X25519,
  };
}

Future<Uint8List> _recoverChallengeNonce(
  CryptoProvider crypto,
  KeyRef agreement,
  Map<String, dynamic> issued,
) async {
  final ephemeral = decodeBase64Url(issued['ephemeral_public'] as String);
  if (ephemeral.length < 32) {
    throw DevUsage('Encryption challenge did not include an ephemeral key');
  }
  final shared = await crypto.deriveSecret(
    agreement,
    ephemeral.sublist(ephemeral.length - 32),
  );
  final key = await crypto.hash('sha-256', shared);
  final wrapped = decodeBase64Url(issued['ciphertext'] as String);
  if (wrapped.length < 28) {
    throw DevUsage('Encryption challenge ciphertext is too short');
  }
  return opensslAes256GcmDecrypt(
    key: key,
    nonce: wrapped.sublist(0, 12),
    tag: wrapped.sublist(12, 28),
    ciphertext: wrapped.sublist(28),
  );
}

Future<KeyRef> _loadMsk(CryptoProvider crypto, String path) async {
  final bytes = await File(path).readAsBytes();
  if (bytes.length != 32) {
    throw DevUsage('$path must be a 32-byte MSK seed');
  }
  return crypto.importPrivateKey(
    PortablePrivateKey(
      algorithm: mskAlgorithm,
      encoding: 'raw-32',
      bytes: bytes,
    ),
  );
}

Uint8List _spki(Uint8List prefix, Uint8List raw) {
  if (raw.length != 32) {
    throw DevUsage('Expected a 32-byte raw public key');
  }
  return Uint8List.fromList([...prefix, ...raw]);
}

Map<String, Object?> _publicResult(dynamic result) {
  if (result is! Map) return {'ok': true};
  const keep = {
    'status',
    'identity_id',
    'principal',
    'scomm_key_id',
    'family',
    'suite',
    'algorithm',
    'purpose',
    'created_at',
    'retired_at',
  };
  return {
    for (final entry in result.entries)
      if (keep.contains(entry.key)) entry.key.toString(): entry.value,
  };
}
