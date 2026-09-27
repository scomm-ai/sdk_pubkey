import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:crypto/crypto.dart' as hash;

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
  MskSigner(List<int> seed, {CkvfCrypto? crypto})
      : _seed = Uint8List.fromList(seed),
        _crypto = crypto ?? defaultCkvfCrypto {
    if (seed.length != 32) {
      throw ArgumentError.value(seed.length, 'seed', 'must be 32 bytes');
    }
  }

  /// The current MSK of an unlocked CKVF vault.
  factory MskSigner.fromVault(UnlockedVault vault, {CkvfCrypto? crypto}) =>
      MskSigner(
        base64urlToBytes(vault.payload.msk.current.privateKey, 32),
        crypto: crypto,
      );

  final Uint8List _seed;
  final CkvfCrypto _crypto;

  Future<Uint8List> publicKey() => _crypto.ed25519PublicFromSeed(_seed);

  Future<Uint8List> sign(List<int> message) =>
      _crypto.ed25519Sign(_seed, message);

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
        'algorithm': 'ed25519',
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
      'algorithm': 'ed25519',
      'value': bytesToBase64url(await sign(utf8.encode(text))),
    };
  }
}

/// `Authorization: Device …` for vault reads, signed by an enrolled device
/// key (registered with `authorize_device` or `first_device`).
Future<VaultAuthorization> deviceReadAuthorization({
  required List<int> deviceSeed,
  required String identityId,
  required String vaultId,
  required String operation,
  Map<String, dynamic> payload = const {},
  CkvfCrypto? crypto,
  DateTime? now,
}) async {
  final c = crypto ?? defaultCkvfCrypto;
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
