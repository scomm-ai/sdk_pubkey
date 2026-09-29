import 'pubkey_dev_debug.dart'
    if (dart.vm.product) 'pubkey_dev_release.dart';

/// Local directory client. `dart run` uses the debug implementation.
/// `dart compile exe` (product mode) links [pubkey_dev_release.dart] only,
/// so the debug client is not in a release binary.
Future<void> main(List<String> args) => pubkeyDevMain(args);
