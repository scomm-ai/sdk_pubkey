# secmail_pubkey_sdk

SComm Dart pubkey protocol adapter (HTTP, enrollment, OTP, MSK) over
[`ckvf`](https://github.com/scomm-public/ckvf/tree/main/packages/dart)
canonicalization. Vault create/open/sync lives in
`packages/scomm_vault_client` (`KeyVault`).

Implements Discovery Protocol **`0.2-draft`** HTTP API client surface
(`discoverMailbox`, resources, operations, challenges) plus convenience
methods (`enrollMsk` / single-call arm, `getBestKey`).

This package is not published on pub.dev. Consume it from Git:

```yaml
secmail_pubkey_sdk:
  git:
    url: https://github.com/scomm-ai/sdk_pubkey.git
    ref: <full-sha>
```

Three-repo development with `discovery-protocol` and `pubkey`: see
`pubkey/docs/PROTOCOL_DEVELOPMENT.md`.

## Hosts

Missing dart-defines resolve to empty strings. Callers must supply
`PUBKEY_READ_BASE_URL` and `PUBKEY_WRITE_BASE_URL` (or pass URLs into
`createPubkeyRuntime` / `createDiscoveryPubkeyClient`). There is no silent
fallback to a production host.

Scripted tests pass explicit URLs. Host apps should pass the same arguments
into `createPubkeyRuntime` / `createDiscoveryPubkeyClient`.

```bash
dart test
```

## Layout

- `PubkeyClient` — directory HTTP, Discovery Document GET, enrollment, MSK arm
- `DiscoveryDocument` / `DiscoveryResource` / challenge types — generic protocol models
- `PubkeyRuntime` — per-account discovery/MSK runtime (vault via `KeyVault`)
- `LegacyVaultMigrator` — read-only upgrade from the pre-CKVF SDK vault format
- `packages/scomm_vault_client` — CKVF `KeyVault`, pairing, pepper, vault host
- OpenPGP and S/MIME engines — protocol adapters used by the host app
