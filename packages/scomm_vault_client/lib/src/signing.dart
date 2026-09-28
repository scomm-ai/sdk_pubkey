import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'authorization.dart';

const int protocolVersion = 1;

/// Operation names the vault host checks in signed envelopes.
abstract final class VaultOperations {
  static const vaultRecordsPut = 'vault_records_put';
  static const vaultGetCurrent = 'vault_get_current';
  static const vaultGetGeneration = 'vault_get_generation';
  static const vaultGetPendingMutations = 'vault_get_pending_mutations';
  static const pwOprfEvaluate = 'pw_oprf_evaluate';
  static const authorizeDevice = 'authorize_device';
  static const revokeDevice = 'revoke_device';
  static const listDevices = 'list_devices';
  static const getMe = 'get_me';
  static const reportVaultCoverage = 'report_vault_coverage';
  static const cancelHighRiskMutation = 'cancel_high_risk_mutation';
  static const vaultOpen = 'vault_open';
  static const armReplacementMsk = 'arm_replacement_msk';
}

String domainSeparator(String operation) =>
    'SComm/Pubkey/$protocolVersion/$operation';

String payloadSha256Hex(Object? payload) =>
    hash.sha256.convert(utf8.encode(jcs(payload ?? const {}))).toString();

String _nonce(CkvfCrypto crypto) => bytesToBase64url(crypto.randomBytes(16));

/// `SComm/Pubkey/1/vault_records_put` text the MSK signs for
/// `POST /v1/vault/{vault_id}/records` (ckvf `profiles/vault-host.md` §2.4).
String vaultRecordsSigningText({
  required String identityId,
  required String vaultId,
  required int generation,
  required String generationHash,
}) =>
    '${domainSeparator(VaultOperations.vaultRecordsPut)}\n'
    'principal=$identityId\n'
    'vault_id=$vaultId\n'
    'generation=$generation\n'
    'generation_hash=$generationHash\n';

/// Signs with an Ed25519 MSK seed (the CKVF payload's `msk.current`).
class MskSigner {
  MskSigner(List<int> seed, {required CkvfCrypto crypto})
      : _seed = Uint8List.fromList(seed),
        _crypto = crypto {
    if (seed.length != 32 && seed.length != 64) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'must be 32 bytes (ed25519) or 64 bytes (mldsa65-ed25519)',
      );
    }
  }

  /// The current MSK of an unlocked CKVF vault.
  factory MskSigner.fromVault(
    UnlockedVault vault, {
    required CkvfCrypto crypto,
  }) {
    final current = vault.payload.msk.current;
    final privateKey = current.privateKey;
    if (privateKey is Map) {
      final mldsa = base64urlToBytes(privateKey['mldsa65_seed'] as String, 32);
      final ed = base64urlToBytes(privateKey['ed25519_seed'] as String, 32);
      return MskSigner([...mldsa, ...ed], crypto: crypto);
    }
    final raw = base64urlToBytes(privateKey as String);
    return MskSigner(raw, crypto: crypto);
  }

  final Uint8List _seed;
  final CkvfCrypto _crypto;

  bool get isHybrid => _seed.length == 64;

  String get algorithm => isHybrid ? 'mldsa65-ed25519' : 'ed25519';

  Future<Uint8List> publicKey() async {
    if (!isHybrid) return _crypto.ed25519PublicFromSeed(_seed);
    final params = DilithiumParams.mlDsa65;
    final (pk, _) = MlDsa.generateKeyPairSeeded(
      params,
      Uint8List.sublistView(_seed, 0, 32),
    );
    final ed = await _crypto.ed25519PublicFromSeed(
      Uint8List.sublistView(_seed, 32, 64),
    );
    return Uint8List.fromList([...pk, ...ed]);
  }

  Future<Uint8List> sign(List<int> message) async {
    if (!isHybrid) return _crypto.ed25519Sign(_seed, message);
    final params = DilithiumParams.mlDsa65;
    final (_, sk) = MlDsa.generateKeyPairSeeded(
      params,
      Uint8List.sublistView(_seed, 0, 32),
    );
    final mldsa = MlDsa.sign(sk, Uint8List.fromList(message), params);
    final ed = await Ed25519().sign(
      message,
      keyPair: await Ed25519().newKeyPairFromSeed(
        Uint8List.sublistView(_seed, 32, 64),
      ),
    );
    return Uint8List.fromList([...mldsa, ...ed.bytes]);
  }

  /// `{protocol_version, principal, operation, timestamp, nonce, payload,
  /// signature}` for `/v1/mutate` and MSK proofs.
  Future<Map<String, dynamic>> envelope({
    required String principal,
    required String operation,
    Map<String, dynamic> payload = const {},
    DateTime? now,
  }) async {
    final timestamp = (now ?? DateTime.now()).millisecondsSinceEpoch;
    final nonce = _nonce(_crypto);
    final text = '${domainSeparator(operation)}\n'
        'principal=$principal\n'
        'timestamp=$timestamp\n'
        'nonce=$nonce\n'
        'payload_sha256=${payloadSha256Hex(payload)}\n';
    return {
      'protocol_version': protocolVersion,
      'principal': principal,
      'operation': operation,
      'timestamp': timestamp,
      'nonce': nonce,
      'payload': payload,
      'signature': {
        'algorithm': algorithm,
        'value': bytesToBase64url(await sign(utf8.encode(text))),
      },
    };
  }

  /// `msk_signature` for a records upload.
  Future<Map<String, String>> recordSignature({
    required String identityId,
    required VaultContainer container,
  }) async {
    final text = vaultRecordsSigningText(
      identityId: identityId,
      vaultId: container.vaultId,
      generation: container.generation,
      generationHash: container.generationHash,
    );
    return {
      'algorithm': algorithm,
      'value': bytesToBase64url(await sign(utf8.encode(text))),
    };
  }
}

/// Verifies an Ed25519 or `mldsa65-ed25519` signature. A wrong length fails.
Future<bool> verifyArmedMsk({
  required List<int> publicKey,
  required List<int> message,
  required List<int> signature,
}) async {
  if (publicKey.length == 32 && signature.length == 64) {
    return Ed25519().verify(
      message,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      ),
    );
  }
  if (publicKey.length != 1984 || signature.length != 3373) return false;
  final pk = Uint8List.fromList(publicKey);
  final sig = Uint8List.fromList(signature);
  final params = DilithiumParams.mlDsa65;
  final mldsaOk = MlDsa.verify(
    Uint8List.sublistView(pk, 0, 1952),
    Uint8List.fromList(message),
    Uint8List.sublistView(sig, 0, 3309),
    params,
  );
  if (!mldsaOk) return false;
  return Ed25519().verify(
    message,
    signature: Signature(
      Uint8List.sublistView(sig, 3309),
      publicKey: SimplePublicKey(
        Uint8List.sublistView(pk, 1952),
        type: KeyPairType.ed25519,
      ),
    ),
  );
}

/// `Authorization: Device …` for vault reads, signed by an enrolled device
/// key (registered with `authorize_device` or `first_device`).
Future<VaultAuthorization> deviceReadAuthorization({
  required List<int> deviceSeed,
  required String identityId,
  required String vaultId,
  required String operation,
  Map<String, dynamic> payload = const {},
  required CkvfCrypto crypto,
  DateTime? now,
}) async {
  final c = crypto;
  final timestamp = (now ?? DateTime.now()).millisecondsSinceEpoch;
  final nonce = _nonce(c);
  final payloadHash = payloadSha256Hex(payload);
  final text = '${domainSeparator(operation)}\n'
      'principal=$identityId\n'
      'vault_id=$vaultId\n'
      'timestamp=$timestamp\n'
      'nonce=$nonce\n'
      'payload_sha256=$payloadHash\n';
  final signature = await c.ed25519Sign(deviceSeed, utf8.encode(text));
  final envelope = {
    'protocol_version': protocolVersion,
    'principal': identityId,
    'vault_id': vaultId,
    'operation': operation,
    'timestamp': timestamp,
    'nonce': nonce,
    'payload_sha256': payloadHash,
    'signature': bytesToBase64url(signature),
  };
  return VaultAuthorization.device(
    bytesToBase64url(utf8.encode(jsonEncode(envelope))),
  );
}
