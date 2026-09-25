/// SComm pubkey protocol adapter. Canonical JSON and base64url go through
/// the CKVF Rust library (`scomm_vault`).
library;

export 'src/canonical.dart';
export 'src/client/identity_wire.dart';
export 'src/client/mailer_client.dart';
export 'src/client/pubkey_client.dart';
export 'src/config/pubkey_config.dart';
export 'src/constants.dart';
export 'src/oprf/identity_oprf.dart';
export 'src/device.dart';
export 'src/discovery/document.dart';
export 'src/discovery/scomm_key_id.dart';
export 'src/discovery/types.dart';
export 'src/crypto/capabilities.dart';
export 'src/crypto/dart_crypto.dart';
export 'src/crypto/native_provider.dart';
export 'src/crypto/provider.dart';
export 'src/crypto/registry.dart';
export 'src/engines/openpgp_rfc9980.dart';
export 'src/engines/pgp.dart';
export 'src/engines/smime.dart';
export 'src/errors.dart';
export 'src/identity.dart';
export 'src/jcs.dart';
export 'src/native_vault.dart' show ensureScommVault;
export 'src/locator.dart';
export 'src/registry.dart';
// `createPubkeyRuntime`/`createPubkeyClient`/`createDiscoveryPubkeyClient`
// are intentionally hidden here: host apps (e.g. secMail10) define their own
// same-named wrappers supplying app-specific storage/URLs, and a file that
// imports both this barrel and such a wrapper would otherwise get an
// ambiguous-import error. Standalone consumers (tests, a demo app) that want
// the package's own defaults should import
// 'package:secmail_pubkey_sdk/src/runtime/pubkey_runtime.dart' directly.
export 'src/runtime/pubkey_runtime.dart'
    hide createPubkeyRuntime, createPubkeyClient, createDiscoveryPubkeyClient;
export 'src/vault/device_pairing.dart';
export 'src/vault/key_hierarchy.dart';
export 'src/vault/recovery_code.dart';
export 'src/vault/store.dart';
export 'src/vault/vault.dart';
export 'src/vault/vault_backup_store.dart';
export 'src/vault/vault_export.dart';
