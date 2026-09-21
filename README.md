# secmail_pubkey_sdk / @scomm/discovery

SComm Discovery Protocol + Pubkey client SDKs over
[`ckvf`](https://github.com/Cryptographic-Key-Vault-Format/ckvf)
for portable Vault **containers**.

| Package | Path | Track | Language |
| --- | --- | --- | --- |
| `secmail_pubkey_sdk` | repo root | A + B | Dart |
| `@scomm/discovery` | `packages/js` | A (read + select) | TypeScript |

Layering (SComm vault is master; `package:ckvf` follows for encodings): [`docs/LAYERING.md`](docs/LAYERING.md), [`docs/scomm-vault-hierarchy.md`](docs/scomm-vault-hierarchy.md).

Implements Discovery Protocol **`0.2-draft`** HTTP client surface
(`discoverMailbox`, resources, operations, challenges) while preserving legacy
convenience methods (`enrollMsk`, `getBestKey`, vault APIs) on the Dart package.

This package is not published on pub.dev / npm yet. Consume from Git:

```yaml
# Dart
secmail_pubkey_sdk:
  git:
    url: https://github.com/scomm-ai/sdk_pubkey.git
    ref: <full-sha>
```

```json
// JS (Track A)
{
  "dependencies": {
    "@scomm/discovery": "git+https://github.com/scomm-ai/sdk_pubkey.git#semver:packages/js"
  }
}
```

Until npm publish, depend via path or git subdirectory tooling used by your repo.

Three-repo development with `discovery-protocol`, `pubkey`, and `ckvf`: see
`pubkey/docs/PROTOCOL_DEVELOPMENT.md`.

## Conformance (anti-drift)

Shared fixtures live in `conformance/fixtures/discovery/` and must stay aligned
with `discovery-protocol/examples/v1/api/`. Pin:
`DISCOVERY_PROTOCOL_VERSION.json`.

```bash
# Dart
dart test

# JS Track A
cd packages/js && npm ci && npm test
```

CI runs both. Signing vectors and mailbox-discovery fixtures are required gates.

## Hosts

Missing dart-defines resolve to empty strings. Callers must supply
`PUBKEY_READ_BASE_URL` and `PUBKEY_WRITE_BASE_URL` (or pass URLs into
`createPubkeyRuntime` / `createDiscoveryPubkeyClient` / JS `createDiscoveryClient`).
There is no silent fallback to a production host.

## Layout

### Dart (`secmail_pubkey_sdk`)

- `PubkeyClient` — directory HTTP, Discovery Document GET, enrollment, Vault sync
- `DiscoveryDocument` / `DiscoveryResource` / challenge types — generic protocol models
- `PubkeyRuntime` — per-account runtime over a `VaultStore`
- `Vault` / device pairing / recovery code — local key hierarchy (CKVF-shaped;
  container I/O via `package:ckvf`)
- OpenPGP and S/MIME engines — protocol adapters used by the host app

### JS (`@scomm/discovery`) — Track A

- `discoverMailbox(mailbox)` — `GET /v1/mailboxes/{mailbox}`
- `DiscoveryDocument.selectBestEncryptionKey(capabilities)` — local select
- No MSK, Vault, or hosted sync (Track B is Dart today; JS Track B later)

## Vault ownership

| Task | Where |
| --- | --- |
| CKVF create/open/export/import | [`ckvf`](https://github.com/Cryptographic-Key-Vault-Format/ckvf) |
| Hosted vault record sync / MSK | This repo (Dart Track B) |
| Public Discovery read | This repo (Dart + JS Track A) |
