import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';

import '../errors.dart';
import '../key_vault.dart';
import '../signing.dart';
import 'cpace.dart';
import 'pairing_flow.dart';
import 'pairing_protocol.dart';

/// A pairing request waiting in a shared folder.
class FolderPairingRequest {
  const FolderPairingRequest({
    required this.sessionId,
    required this.deviceName,
    required this.deviceId,
    required this.requestedTier,
    required this.identityId,
    required this.ya,
  });

  final String sessionId;
  final String deviceName;
  final String deviceId;
  final String requestedTier;
  final String identityId;
  final Uint8List ya;
}

/// `{root}/pair/{sessionId}.json`. Both devices must see this directory.
/// The QR code names the session. It does not upload the vault.
class FolderPairingChannel {
  FolderPairingChannel(this.root);

  final Directory root;

  Directory get _pair => Directory('${root.path}/pair');

  File _file(String sessionId) {
    if (!RegExp(r'^[0-9a-fA-F]{16,64}$').hasMatch(sessionId)) {
      throw VaultClientException('pairing_session', 'session id');
    }
    return File('${_pair.path}/$sessionId.json');
  }

  Map<String, dynamic>? _read(String sessionId) {
    final file = _file(sessionId);
    if (!file.existsSync()) return null;
    final json = jsonDecode(file.readAsStringSync());
    if (json is! Map) {
      throw VaultClientException('pairing_session', 'session file');
    }
    return Map<String, dynamic>.from(json);
  }

  void _write(String sessionId, Map<String, dynamic> body) {
    _pair.createSync(recursive: true);
    final file = _file(sessionId);
    final tmp = File('${file.path}.tmp');
    tmp.writeAsStringSync(jsonEncode(body), flush: true);
    tmp.renameSync(file.path);
  }
}

/// New device: writes a CPace request and waits for the CKVF container.
Future<PairingOffer> startFolderPairing({
  required FolderPairingChannel channel,
  required String identityId,
  required String deviceName,
  required String deviceId,
  required String requestedTier,
  required CkvfCrypto crypto,
  bool typedPassword = false,
  Duration pollInterval = const Duration(seconds: 2),
  int expiresInSeconds = 300,
}) async {
  final sessionId = PairingProtocol.generateSessionId(crypto);
  final typed = typedPassword ? PairingProtocol.generateTypedPassword(crypto) : null;
  final password = typed != null
      ? PairingProtocol.typedPasswordBytes(typed)
      : PairingProtocol.generateHighEntropyPassword(crypto);
  final state = cpaceStart(
    password: password,
    sid: PairingProtocol.sid(sessionId, identityId),
    ci: PairingProtocol.ci(identityId),
    random64: crypto.randomBytes(64),
  );
  final expiresAt =
      DateTime.now().toUtc().add(Duration(seconds: expiresInSeconds));
  channel._write(sessionId, {
    'state': 'PENDING',
    'identity_id': identityId,
    'device_name': deviceName,
    'device_id': deviceId,
    'requested_tier': requestedTier,
    'b_pake_element': bytesToBase64url(state.ya),
    'expires_at': expiresAt.toIso8601String(),
  });
  return PairingOffer(
    sessionId: sessionId,
    password: password,
    typedPassword: typed,
    expiresAt: expiresAt,
    completed: _awaitFolderResponse(
      channel: channel,
      crypto: crypto,
      identityId: identityId,
      sessionId: sessionId,
      state: state,
      expiresAt: expiresAt,
      pollInterval: pollInterval,
    ),
  );
}

Future<UnlockedVault> _awaitFolderResponse({
  required FolderPairingChannel channel,
  required CkvfCrypto crypto,
  required String identityId,
  required String sessionId,
  required CPaceInitiator state,
  required DateTime expiresAt,
  required Duration pollInterval,
}) async {
  Map<String, dynamic> body;
  while (true) {
    final read = channel._read(sessionId);
    if (read != null && read['state'] == 'RESPONDED') {
      body = read;
      break;
    }
    if (read != null && read['state'] == 'COMPLETED') {
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

  final ybRaw = body['a_pake_element'];
  final tag = body['confirmation_tag'];
  final vekBox = body['vek_envelope'];
  final sig = body['msk_signature'];
  final container = body['container'];
  if (ybRaw is! String ||
      tag is! Map ||
      vekBox is! Map ||
      sig is! String ||
      container is! String) {
    throw VaultClientException(
      'pairing_protocol_unsupported',
      'the pairing response is missing CPace fields or the container',
    );
  }
  final yb = base64urlToBytes(ybRaw, 32);
  final confirmation = PairingBox.fromJson(Map<String, dynamic>.from(tag));
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
    vek = await PairingProtocol.open(
      crypto,
      tek,
      PairingBox.fromJson(Map<String, dynamic>.from(vekBox)),
    );
  } on VaultClientException {
    rethrow;
  } catch (_) {
    throw VaultClientException(
      'pairing_password_mismatch',
      'the confirmation failed: wrong password or tampering',
    );
  }

  final opened = await openVaultWith(
    container,
    crypto: crypto,
    unwrap: (_) async => vek,
  );
  if (opened.payload.identity.identityId != identityId) {
    throw VaultClientException(
      'identity_mismatch',
      'the paired vault is for another identity',
    );
  }
  final transcript = PairingProtocol.transcript(
    sessionId: sessionId,
    identityId: identityId,
    ya: state.ya,
    yb: yb,
    confirmationTag: confirmation,
  );
  final signed = await verifyArmedMsk(
    publicKey: base64urlToBytes(opened.payload.msk.current.publicKey),
    message: transcript,
    signature: base64urlToBytes(sig),
  );
  if (!signed) {
    throw VaultClientException(
      'pairing_signature_invalid',
      'the pairing transcript is not signed by the vault MSK',
    );
  }
  channel._write(sessionId, {'state': 'COMPLETED'});
  return opened;
}

/// Approving device: reads a pending request from the shared folder.
FolderPairingRequest fetchFolderPairing(
  FolderPairingChannel channel,
  String sessionId,
) {
  final body = channel._read(sessionId);
  if (body == null) {
    throw VaultClientException(
      'pairing_session_not_found',
      'no pairing request in the sync folder',
    );
  }
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
  return FolderPairingRequest(
    sessionId: sessionId,
    deviceName: '${body['device_name'] ?? ''}',
    deviceId: '${body['device_id'] ?? ''}',
    requestedTier: '${body['requested_tier'] ?? pairingTier}',
    identityId: '${body['identity_id'] ?? ''}',
    ya: base64urlToBytes(ya, 32),
  );
}

/// Approving device: seals the Vault Encryption Key and the container into
/// the shared folder. A copied VEK cannot be erased later.
Future<void> approveFolderPairing({
  required FolderPairingChannel channel,
  required KeyVault vault,
  required FolderPairingRequest request,
  required List<int> password,
  Duration pollInterval = const Duration(milliseconds: 200),
  Duration timeout = const Duration(minutes: 5),
}) async {
  if (!vault.isOpen) {
    throw VaultClientException('vault_locked', 'vault locked');
  }
  final identityId = vault.vault.payload.identity.identityId;
  if (request.identityId != identityId) {
    throw VaultClientException(
      'identity_mismatch',
      'the pairing request is for another identity',
    );
  }
  final crypto = vault.crypto;
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
  channel._write(request.sessionId, {
    'state': 'RESPONDED',
    'identity_id': identityId,
    'a_pake_element': bytesToBase64url(responded.yb),
    'vek_envelope': vekBox.toJson(),
    'confirmation_tag': tag.toJson(),
    'msk_signature': bytesToBase64url(await vault.signer.sign(transcript)),
    'container': serializeContainer(vault.vault.container),
  });

  final deadline = DateTime.now().toUtc().add(timeout);
  while (true) {
    final body = channel._read(request.sessionId);
    if (body != null && body['state'] == 'COMPLETED') return;
    if (DateTime.now().toUtc().isAfter(deadline)) {
      throw VaultClientException(
        'pairing_session_expired',
        'the new device did not collect the pairing response',
      );
    }
    await Future<void>.delayed(pollInterval);
  }
}
