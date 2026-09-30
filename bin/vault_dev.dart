import 'vault_dev_debug.dart'
    if (dart.vm.product) 'vault_dev_release.dart';

/// Local vault client. `dart run` uses the debug implementation.
Future<void> main(List<String> args) => vaultDevMain(args);
