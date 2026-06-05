import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';

/// Smoke-check read/write pubkey hosts (compile-time URLs).
Future<void> main(List<String> args) async {
  final email = args.isNotEmpty ? args.first : 'health-check@example.com';
  final read = PubkeyReadClient();
  final write = PubkeyWriteClient();

  final readHealth = await read.health();
  final writeHealth = await write.health();
  print('read health: $readHealth');
  print('write health: $writeHealth');

  final check = await read.checkAccount(email);
  print('account $email known=${check.known} hasKeys=${check.hasKeys}');
}
