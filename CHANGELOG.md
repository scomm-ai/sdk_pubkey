# Changelog

## 2.0.0

- **BREAKING:** `secmail_pubkey_sdk` is discovery, mailer, keys, and MSK only.
  Writable legacy vault code under `lib/src/vault/*` is removed. Vault
  create/open/sync/pairing/recovery live in `packages/scomm_vault_client`
  (`KeyVault`). `PubkeyRuntime` no longer holds a `Vault` / `DeviceKeyStore`.
- Read-only `LegacyVaultMigrator` opens legacy SDK vault ciphertext and builds
  a CKVF generation-1 container (device + optional password/recovery pepper
  slots) via `scomm_vault_client`.
- Path dependency on `scomm_vault_client` (0.2.0) for the migrator.
- Dropped PBKDF2 `wrapVault` / `unwrapVault` / `exportKeyPackage` /
  `importKeyPackage`.
- `PubkeyClient` vault-host routes remain removed (use `VaultHostClient`).
- Conformance fixture `mailer-otp.json` verify body uses `sha256` (not email).
- `scomm_vault_client` 0.2.0: `KeyVault.rotateSigningKey` (D8 retire +
  `deletePrivate` for sign-only keys).
- Prior `1.3.x` Unreleased items (single-call MSK arm, grant parsing, mailer
  ID-token, LateInitializationError fix) ship with this cutover.

## 1.3.0

- Mailer client can prove a Gmail or Microsoft mailbox with an OIDC ID token
  (`fetchIdTokenConfig`, `createIdTokenChallenge`, `verifyIdToken`) and receive
  the same `otp_grant` the OTP verify call returns.
- `recoverWithGrant` and `DiscoveryBackupStore.getWithGrant` accept that grant
  directly. `recoverWithCode` and `get` still verify an OTP, then call them.
- Error codes for the ID-token path: `idtoken_not_supported`,
  `idtoken_challenge_invalid`, `idtoken_invalid`, `idtoken_replayed`,
  `idtoken_email_unverified`, `idtoken_email_mismatch`,
  `idtoken_subject_mismatch`.
