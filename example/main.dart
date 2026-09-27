// Standalone demo of discovery / MSK runtime pieces (no Flutter, no vault host).
//
// Run with: dart run example/main.dart
//
// Vault create/open/sync lives in package:scomm_vault_client. Legacy SDK vault
// ciphertext can be migrated once via LegacyVaultMigrator.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/runtime/pubkey_runtime.dart';

Future<void> main() async {
  final crypto = DartCryptoProvider();
  final msk = await crypto.generateMSK();
  final portable = await crypto.exportPrivateKey(msk);
  stdout.writeln(
    'Generated MSK (${portable.bytes.length} bytes seed, '
    'algorithm ${portable.algorithm}).',
  );

  final runtime = createPubkeyRuntime('demo@example.com');
  await runtime.attachMsk(portable.bytes);
  stdout.writeln(
    'PubkeyRuntime armed for ${runtime.accountEmail}; '
    'requireMsk() returns a live KeyRef.',
  );
  final armed = await runtime.requireMsk();
  stdout.writeln('MSK key id: ${armed.id}');

  // CPace still lives on CryptoProvider for hosts that need it; full pairing
  // flows are in scomm_vault_client.
  final sid = Uint8List.fromList(List<int>.generate(16, (i) => i));
  final password = utf8.encode('demo-pairing-password');
  final start = await crypto.cpaceStart(password: password, sid: sid);
  final responded = await crypto.cpaceRespond(
    password: password,
    sid: sid,
    peerPublicElement: start.publicElement,
  );
  final isk = await crypto.cpaceFinish(start, responded.publicElement);
  stdout.writeln('CPace ISK length: ${isk.length}');
}
