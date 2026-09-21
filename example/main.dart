// Standalone demo of the crypto stack: no Flutter, no HTTP, no secMail10.
//
// Run with: dart run example/main.dart
//
// Shows the pieces that matter to a host app that just wants the crypto
// primitives — Vault creation, key storage, offline export/import, and a
// device-pairing handshake — without needing a live pubkey server or the
// full Scomm.AI application.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';

Future<void> main() async {
  final crypto = DartCryptoProvider();

  // --- 1. Create a vault and arm an identity (MSK/AEK/VEK), offline. ---
  final vault = Vault(crypto: crypto, store: MemoryVaultStore());
  await vault.createVault('demo-principal');

  final msk = await crypto.generateMSK();
  final mskPortable = await crypto.exportPrivateKey(msk);
  final aek = KeyHierarchy.generateAek(crypto);
  final vek = KeyHierarchy.generateVek(crypto);
  await vault.setMsk(aek: aek, msk: mskPortable);
  stdout.writeln('Created vault for "${vault.principal}", MSK ${msk.publicKey != null ? "armed" : "missing"}.');

  // --- 2. Add a content key. ---
  vault.addKey({
    'kind': 'content',
    'key_id': 1,
    'family': Families.pgp,
    'purpose': Purposes.encryption,
    'algorithm': 'openpgp-cv25519',
    'fingerprint': 'demo-fingerprint-1',
    'status': 'active',
    'private_material': encodeBase64Url(Uint8List.fromList(List.generate(32, (i) => i))),
  });
  stdout.writeln('Added key ${vault.getCurrentKey(Purposes.encryption)?.fingerprint}.');

  // --- 3. Offline export/import round trip, password-protected. ---
  final salt = crypto.random(eekSaltBytes);
  const passphrase = 'correct horse battery staple';
  final eek = await VaultExport.deriveEek(crypto, passphrase, salt);
  final vekEnvelope = await VaultExport.wrapWithEek(crypto, eek, vek, salt: salt);

  final exported = await vault.exportVault(vek);
  final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
  final iv = decodeBase64Url((exported['encryption'] as Map)['iv'] as String);
  final exportFile = VaultExport.buildExportFile(
    identity: 'demo-principal',
    tier: 'limited',
    createdAt: DateTime.now().millisecondsSinceEpoch,
    vekEnvelope: vekEnvelope,
    generation: vault.generation,
    ciphertext: ciphertext,
    nonce: iv,
    ciphertextHash: sha256Bytes(ciphertext),
  );
  stdout.writeln('Exported vault backup file: ${jsonEncode(exportFile).length} bytes.');

  final restoredVek = await VaultExport.unwrapWithEek(
    crypto,
    passphrase,
    VaultExport.parseExportFile(exportFile).vekEnvelope!,
  );
  final restoredVault = Vault(crypto: crypto, store: MemoryVaultStore());
  await restoredVault.importVault(exported, restoredVek);
  stdout.writeln('Restored vault sees key: ${restoredVault.getKey(1)?.fingerprint}.');

  // --- 4. CPace device pairing handshake between two in-memory devices. ---
  const sessionId = 'demo-session';
  const locator = 'demo-identity-locator';
  final password = DevicePairing.generateHighEntropyPassword(crypto);
  final sid = DevicePairing.pairingSid(
    sessionId: sessionId,
    identityLocator: locator,
    requestedTier: 'full',
  );
  final ci = DevicePairing.pairingCi(locator);
  final started = await crypto.cpaceStart(password: password, sid: sid, ci: ci);
  final responded = await crypto.cpaceRespond(
    password: password,
    sid: sid,
    peerPublicElement: started.publicElement,
    ci: ci,
  );
  final isk = await crypto.cpaceFinish(started, responded.publicElement);
  final tek = await DevicePairing.deriveTekV2(
    crypto,
    isk,
    sessionId: sessionId,
    ya: started.publicElement,
    yb: responded.publicElement,
    identityLocator: locator,
    requestedTier: 'full',
  );

  final envelopes = await DevicePairing.wrapForTransfer(crypto, tek, vek, aek);
  final transfer = await DevicePairing.unwrapTransfer(
    crypto,
    tek,
    envelopes.vekEnvelope,
    envelopes.aekEnvelope,
  );
  stdout.writeln(
    'Device B recovered VEK/AEK via CPace pairing: '
    'vek matches = ${_bytesEqual(transfer.vek, vek)}, '
    'aek matches = ${_bytesEqual(transfer.aek!, aek)}.',
  );
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
