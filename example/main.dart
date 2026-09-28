// The host app constructs a CryptoProvider backed by libscomm_openpgp and
// passes it to createPubkeyRuntime. This package does not ship a provider.
import 'dart:io';

void main() {
  stdout.writeln(
    'Pass a CryptoProvider into createPubkeyRuntime. '
    'Key generation, CPace, and MSK proofs use that provider.',
  );
}
