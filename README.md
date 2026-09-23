# secmail_pubkey_sdk

SComm Dart pubkey protocol adapter (HTTP, enrollment, OTP, Vault wrap) over
[`ckvf`](https://github.com/scomm-public/ckvf/tree/main/packages/dart).

Implements Discovery Protocol **`0.2-draft`** HTTP API client surface
(`discoverMailbox`, resources, operations, challenges) while preserving legacy
convenience methods (`enrollMsk`, `getBestKey`, vault APIs).

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

- `PubkeyClient` — directory HTTP, Discovery Document GET, enrollment, Vault sync
- `DiscoveryDocument` / `DiscoveryResource` / challenge types — generic protocol models
- `PubkeyRuntime` — per-account runtime over a `VaultStore`
- `Vault` / device pairing / recovery code — local key hierarchy
- OpenPGP and S/MIME engines — protocol adapters used by the host app
