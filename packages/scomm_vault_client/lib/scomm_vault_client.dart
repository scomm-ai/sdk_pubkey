/// Scomm.AI vault client: a local-first CKVF [KeyVault], device pairing,
/// and optional generation sync to storage the user controls. Container
/// format and slots live in `package:ckvf`. A vault host is not required
/// to unlock a container that has an offline slot.
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
export 'src/pairing/folder_pairing.dart';
export 'src/pairing/pairing_flow.dart';
export 'src/pairing/pairing_protocol.dart'
    show PairingBox, PairingProtocol, PairingUri, pairingTypedPasswordLength;
export 'src/signing.dart';
export 'src/software_ckvf_crypto.dart';
export 'src/vault_host_client.dart';
export 'src/vault_sync.dart';
