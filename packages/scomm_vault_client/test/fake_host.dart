import 'dart:convert';

import 'package:ckvf/ckvf.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';

/// In-memory vault host with the records rules of ckvf
/// `profiles/vault-host.md` §2.4 and the pairing mailbox.
class FakeVaultHost extends VaultHostClient {
  FakeVaultHost(this.crypto) : super('http://fake.invalid');

  final CkvfCrypto crypto;

  final records = <Map<String, dynamic>>[];
  final pairings = <String, Map<String, dynamic>>{};
  final mutations = <Map<String, dynamic>>[];
  final readTokens = <String>{};
  bool offline = false;

  void _online() {
    if (offline) throw VaultClientException('network_error', 'offline');
  }

  @override
  Future<VaultRead> currentRecord(
    String vaultId,
    VaultAuthorization authorization,
  ) async {
    _online();
    if (authorization.header.startsWith('PairingRead ')) {
      final token = authorization.header.substring('PairingRead '.length);
      if (!readTokens.remove(token)) {
        throw VaultClientException('pairing_read_token_invalid', null, 401);
      }
    }
    if (records.isEmpty) return const VaultRead();
    return VaultRead.fromJson({'record': records.last});
  }

  @override
  Future<Map<String, dynamic>> putRecord({
    required String identityId,
    required VaultContainer container,
    required MskSigner signer,
    String? licenseDeviceId,
  }) async {
    _online();
    await Ckvf.validate(container, crypto: crypto);
    final sig = await signer.recordSignature(
      identityId: identityId,
      container: container,
    );
    final ok = await crypto.ed25519Verify(
      await signer.publicKey(),
      utf8.encode(vaultRecordsSigningText(
        identityId: identityId,
        vaultId: container.vaultId,
        generation: container.generation,
        generationHash: container.generationHash,
      )),
      base64urlToBytes(sig['value']!, 64),
    );
    if (!ok) throw VaultClientException('invalid_signature', null, 401);
    final head = records.isEmpty ? null : records.last;
    final headGeneration = head?['generation'] as int? ?? 0;
    final headHash = head?['generation_hash'] as String?;
    final g = container.generation;
    if (g <= headGeneration) {
      final stored = records[g - 1];
      if (stored['generation_hash'] == container.generationHash) {
        return {'generation': g, 'duplicate': true};
      }
    }
    if (g != headGeneration + 1 ||
        container.previousGenerationHash != headHash) {
      throw VaultClientException(
        'generation_conflict',
        'does not extend the head',
        409,
        {
          'generation': g,
          'head_generation': headGeneration,
          'head_generation_hash': headHash,
        },
      );
    }
    records.add({
      'container': jsonDecode(serializeContainer(container)),
      'generation': g,
      'generation_hash': container.generationHash,
      'msk_signature': sig,
    });
    return {'generation': g};
  }

  @override
  Future<Map<String, dynamic>> mutate(Map<String, dynamic> envelope) async {
    _online();
    mutations.add(envelope);
    return {'ok': true};
  }

  @override
  Future<Map<String, dynamic>> createPairing(
    String sessionId,
    Map<String, dynamic> body,
  ) async {
    pairings[sessionId] = {...body, 'state': 'PENDING'};
    return {'session_id': sessionId, 'state': 'PENDING'};
  }

  @override
  Future<Map<String, dynamic>> getPairing(
    String sessionId, {
    String? retrieverDeviceId,
  }) async {
    final row = pairings[sessionId]!;
    final state = row['state'];
    if (state == 'PENDING') {
      return {
        'session_id': sessionId,
        'state': 'PENDING',
        'device_name': row['device_name'],
        'device_id': row['device_id'],
        'b_pake_element': row['b_pake_element'],
      };
    }
    if (state == 'RESPONDED' && retrieverDeviceId == row['device_id']) {
      row['state'] = 'COMPLETED';
      final token = 'token-$sessionId';
      readTokens.add(token);
      final vaultId = records.isEmpty
          ? null
          : (records.last['container'] as Map)['vault_id'];
      return {
        'session_id': sessionId,
        'state': 'RESPONDED',
        for (final k in [
          'a_pake_element',
          'vek_envelope',
          'confirmation_tag',
          'msk_signature',
        ])
          k: row[k],
        'vault_id': vaultId,
        'pairing_read_token': token,
      };
    }
    return {'session_id': sessionId, 'state': state};
  }

  @override
  Future<Map<String, dynamic>> respondPairing(
    String sessionId,
    Map<String, dynamic> body,
  ) async {
    final row = pairings[sessionId]!;
    if (row['state'] != 'PENDING') {
      throw VaultClientException(
          'pairing_session_already_responded', null, 409);
    }
    row.addAll(body);
    row['state'] = 'RESPONDED';
    return {'session_id': sessionId, 'state': 'RESPONDED'};
  }
}
