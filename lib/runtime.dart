/// [PubkeyRuntime]'s package-default factory functions
/// (`createPubkeyRuntime`/`createPubkeyClient`/`createDiscoveryPubkeyClient`),
/// for a host app building its own same-named wrapper around its own
/// storage/URLs (see `secmail_pubkey_sdk.dart`'s doc comment on why these
/// are hidden from the main barrel). Standalone consumers that don't need a
/// host-specific wrapper can just use `secmail_pubkey_sdk.dart` directly —
/// [PubkeyRuntime.instance] already falls back to these defaults.
library;

export 'src/runtime/pubkey_runtime.dart';
