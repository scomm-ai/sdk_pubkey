/// Scomm.AI vault client: a local-first CKVF [KeyVault], device pairing,
/// identity OPRF, pepper POPRF, and vault-host routes. Container format and
/// slots live in `package:ckvf`.
library;

export 'package:ckvf/ckvf.dart' show PepperKey, PepperOprf;

export 'src/authorization.dart';
export 'src/digest.dart';
export 'src/errors.dart';
export 'src/host_pepper_oprf.dart';
export 'src/key_vault.dart';
export 'src/local_vault_store.dart';
export 'src/mailbox_identity.dart';
export 'src/oprf/poprf.dart';
export 'src/pairing/pairing_flow.dart';
export 'src/pairing/pairing_protocol.dart'
    show PairingBox, PairingProtocol, PairingUri, pairingTypedPasswordLength;
export 'src/signing.dart';
export 'src/vault_host_client.dart';
