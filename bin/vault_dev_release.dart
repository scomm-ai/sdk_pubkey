import 'dart:io';

const vaultDevReleaseMessage =
    'vault_dev is omitted from release builds. Run it with dart run.';

Future<void> vaultDevMain(List<String> args) async {
  stderr.writeln(vaultDevReleaseMessage);
  exit(64);
}
