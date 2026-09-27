import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';

import '../authorization.dart';
import '../errors.dart';
import '../key_vault.dart';
import '../vault_host_client.dart';
import 'cpace.dart';
import 'pairing_protocol.dart';

/// The new device's open pairing request.
class PairingOffer {
  PairingOffer({
    required this.sessionId,
    required this.password,
    required this.expiresAt,
    required this.completed,
    this.typedPassword,
  });

  final String sessionId;
  final Uint8List password;

  /// Set when the password is typed rather than scanned.
  final String? typedPassword;
  final DateTime expiresAt;

  /// The vault opened with the transferred VEK. Adopt it with
  /// [KeyVault.adopt] (`storedOnHost: true`), then push and
  /// [KeyVault.authorizeDevice].
  final Future<UnlockedVault> completed;

  String get uri =>
      PairingUri(sessionId: sessionId, password: password).toUriString();
}

/// A request the approving device fetched with [fetchPairingRequest].
class PendingPairing {
  const PendingPairing({
    required this.sessionId,
    required this.deviceName,
    required this.deviceId,
    required this.ya,
  });

  final String sessionId;
  final String deviceName;
  final String deviceId;
  final Uint8List ya;
}

Map<String, dynamic>? _map(Object? v) =>
    v is Map ? Map<String, dynamic>.from(v) : null;

void _refuseV1(Map<String, dynamic> body) {
  if (body.containsKey('b_ephemeral_public_key') ||
      body.containsKey('a_ephemeral_public_key')) {
    throw VaultClientException(
      'pairing_protocol_unsupported',
      'the pairing mailbox spoke v1 ECDH; CPace v2 is required',
    );
  }
}

/// New device: opens a pairing mailbox and polls until the other device
/// answers. [identityId] is the identity OPRF output for this mailbox.
Future<PairingOffer> startPairing({
  required VaultHostClient host,
  required String identityId,
  required String deviceName,
  required String deviceId,
  bool typedPassword = false,
  Duration pollInterval = const Duration(seconds: 4),
  int expiresInSeconds = 300,
  CkvfCrypto? crypto,
}) async {
  final c = crypto ?? defaultCkvfCrypto;
  final sessionId = PairingProtocol.generateSessionId(c);
  final typed = typedPassword ? PairingProtocol.generateTypedPassword(c) : null;
  final password = typed != null
      ? PairingProtocol.typedPasswordBytes(typed)
      : PairingProtocol.generateHighEntropyPassword(c);
  final state = cpaceStart(
    password: password,
    sid: PairingProtocol.sid(sessionId, identityId),
    ci: PairingProtocol.ci(identityId),
    random64: c.randomBytes(64),
  );
  final created = await host.createPairing(sessionId, {
    'identity_id': identityId,
    'device_name': deviceName,
    'requested_tier': pairingTier,
    'b_pake_element': bytesToBase64url(state.ya),
    'device_id': deviceId,
    'expires_in': expiresInSeconds,
  });
  final raw = created['expires_at'];
  final expiresAt = raw is String
      ? DateTime.parse(raw).toUtc()
      : DateTime.now().toUtc().add(Duration(seconds: expiresInSeconds));
  return PairingOffer(
    sessionId: sessionId,
    password: password,
    typedPassword: typed,
    expiresAt: expiresAt,
    completed: _awaitResponse(
      host: host,
      crypto: c,
      identityId: identityId,
      sessionId: sessionId,
      deviceId: deviceId,
      state: state,
      expiresAt: expiresAt,
      pollInterval: pollInterval,
    ),
  );
}

Future<UnlockedVault> _awaitResponse({
  required VaultHostClient host,
  required CkvfCrypto crypto,
  required String identityId,
  required String sessionId,
  required String deviceId,
  required CPaceInitiator state,
  required DateTime expiresAt,
  required Duration pollInterval,
}) async {
  Map<String, dynamic> body;
  while (true) {
    body = await host.getPairing(sessionId, retrieverDeviceId: deviceId);
    _refuseV1(body);
    final s = body['state'];
    if (s == 'RESPONDED' && body['a_pake_element'] is String) break;
    if (s == 'COMPLETED' || s == 'RESPONDED') {
      throw VaultClientException(
        'pairing_session_already_responded',
        'the pairing response was already retrieved',
      );
    }
    if (DateTime.now().toUtc().isAfter(expiresAt)) {
      throw VaultClientException(
        'pairing_session_expired',
        'the other device did not approve in time',
      );
    }
    await Future<void>.delayed(pollInterval);
  }

  final yb = base64urlToBytes(body['a_pake_element'] as String, 32);
  final tag = _map(body['confirmation_tag']);
  final vekBox = _map(body['vek_envelope']);
  final sig = body['msk_signature'];
  final vaultId = body['vault_id'];
  final token = body['pairing_read_token'];
  if (tag == null || vekBox == null || sig is! String) {
    throw VaultClientException(
      'pairing_protocol_unsupported',
      'the pairing response is missing CPace v2 fields',
    );
  }
  if (vaultId is! String || token is! String) {
    throw VaultClientException(
      'pairing_read_token_invalid',
      'the pairing response has no vault_id and pairing_read_token',
    );
  }

  final confirmation = PairingBox.fromJson(tag);
  final tek = PairingProtocol.tek(
    cpaceFinish(state, yb),
    sessionId: sessionId,
    ya: state.ya,
    yb: yb,
    identityId: identityId,
  );
  final Uint8List vek;
  try {
    await PairingProtocol.open(crypto, tek, confirmation);
    vek = await PairingProtocol.open(crypto, tek, PairingBox.fromJson(vekBox));
  } on VaultClientException {
    rethrow;
  } catch (_) {
    throw VaultClientException(
      'pairing_password_mismatch',
      'the confirmation failed: wrong password or tampering',
    );
  }

  final read = await host.currentRecord(
    vaultId,
    VaultAuthorization.pairingRead(token),
  );
  final record = read.record;
  if (record == null) {
    throw VaultClientException(
      'vault_not_synced',
      'the other device has not stored its vault on the host yet',
    );
  }
  final opened = await openVaultWith(
    record.container,
    crypto: crypto,
    unwrap: (_) async => vek,
  );
  await verifyRecordSignature(record, opened, identityId, crypto);
  final transcript = PairingProtocol.transcript(
    sessionId: sessionId,
    identityId: identityId,
    ya: state.ya,
    yb: yb,
    confirmationTag: confirmation,
  );
  final signed = await crypto.ed25519Verify(
    base64urlToBytes(opened.payload.msk.current.publicKey, 32),
    transcript,
    base64urlToBytes(sig, 64),
  );
  if (!signed) {
    throw VaultClientException(
      'pairing_signature_invalid',
      'the pairing transcript is not signed by the vault MSK',
    );
  }
  return opened;
}

/// Approving device: reads a pending request by session id (from the QR
/// code or typed).
Future<PendingPairing> fetchPairingRequest(
  VaultHostClient host,
  String sessionId,
) async {
  final body = await host.getPairing(sessionId);
  _refuseV1(body);
  if (body['state'] != 'PENDING') {
    throw VaultClientException(
      'pairing_session_already_responded',
      'the pairing session is not awaiting approval (${body['state']})',
    );
  }
  final ya = body['b_pake_element'];
  if (ya is! String) {
    throw VaultClientException(
      'pairing_protocol_unsupported',
      'the pending pairing session has no CPace element',
    );
  }
  return PendingPairing(
    sessionId: sessionId,
    deviceName: '${body['device_name'] ?? ''}',
    deviceId: '${body['device_id'] ?? ''}',
    ya: base64urlToBytes(ya, 32),
  );
}

/// Approving device: pushes the vault so the host holds it, answers the
/// request with the VEK under the CPace TEK, and waits for the new device
/// to collect it.
Future<void> approvePairing({
  required KeyVault vault,
  required PendingPairing request,
  required List<int> password,
  Duration pollInterval = const Duration(seconds: 2),
  Duration timeout = const Duration(minutes: 5),
}) async {
  final b = vault.binding ??
      (throw VaultClientException('not_bound', 'no vault host binding'));
  await vault.push();
  final crypto = vault.crypto;
  final identityId = b.identityId;
  final responded = cpaceRespond(
    password: password,
    sid: PairingProtocol.sid(request.sessionId, identityId),
    ci: PairingProtocol.ci(identityId),
    peerYa: request.ya,
    random64: crypto.randomBytes(64),
  );
  final tek = PairingProtocol.tek(
    responded.isk,
    sessionId: request.sessionId,
    ya: request.ya,
    yb: responded.yb,
    identityId: identityId,
  );
  final tag = await PairingProtocol.seal(
    crypto,
    tek,
    utf8.encode(pairingConfirmPlaintext),
  );
  final vekBox = await PairingProtocol.seal(crypto, tek, vault.vault.vek);
  final transcript = PairingProtocol.transcript(
    sessionId: request.sessionId,
    identityId: identityId,
    ya: request.ya,
    yb: responded.yb,
    confirmationTag: tag,
  );
  await b.host.respondPairing(request.sessionId, {
    'identity_id': identityId,
    'a_pake_element': bytesToBase64url(responded.yb),
    'vek_envelope': vekBox.toJson(),
    'confirmation_tag': tag.toJson(),
    'msk_signature': bytesToBase64url(await vault.signer.sign(transcript)),
  });

  final deadline = DateTime.now().toUtc().add(timeout);
  while (true) {
    final body = await b.host.getPairing(request.sessionId);
    if (body['state'] == 'COMPLETED') return;
    if (DateTime.now().toUtc().isAfter(deadline)) {
      throw VaultClientException(
        'pairing_session_expired',
        'the new device did not collect the pairing response',
      );
    }
    await Future<void>.delayed(pollInterval);
  }
}
