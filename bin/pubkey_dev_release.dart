import 'dart:io';

/// Shown when this tool is compiled in Dart product (release) mode.
const pubkeyDevReleaseMessage =
    'pubkey_dev is omitted from release builds. Run it with dart run.';

Future<void> pubkeyDevMain(List<String> args) async {
  stderr.writeln(pubkeyDevReleaseMessage);
  exit(64);
}
