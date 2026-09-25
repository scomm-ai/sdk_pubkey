# Client SDK layering

Protocol, Vault format, and crypto providers are separate layers. Keep them that way.

```text
Applications (Flutter, browser, Outlook, webview mail)
        │
        ├─ Track A (any client) ── discoverMailbox + local key select
        │
        └─ Track B (SComm-class) ── MSK / challenges / ops + Vault orchestration
                │
                ▼
     Discovery / Pubkey client SDKs (this repo)
     Rust: crates/discovery (WASM from the same crate)
     Dart: secmail_pubkey_sdk (Flutter binding of the same wire rules)
                │
                │  depends on (format only)
                ▼
     ckvf  (@ckvf/* / package:ckvf)
     JS ↔ Dart sync for portable vault containers
                │
                ▼
     discovery-protocol  (schemas, examples, signing-vectors)
     Sole normative wire contract
```

## Ownership

| Layer | Owns | Must not own |
| --- | --- | --- |
| `discovery-protocol` | Document + HTTP API schemas, examples, signing vectors | Client SDKs, hosted service |
| `discovery.scomm.ai` (`pubkey`) | Compatible host implementing `/v1/` | Client providers, Vault plaintext |
| This repo (Discovery/Pubkey clients) | HTTP client, MSK signing, challenges/ops, **SComm** hosted vault sync (VEK/AEK/DKEK), password backup stores | CKVF container dialect |
| [`scomm-public/ckvf`](https://github.com/scomm-public/ckvf) | SComm.AI-maintained vault format: encodings, JCS/base64url, shared test-vectors; VEK/AEK/DKEK + password backup as a layer above VEK | Hosted Discovery HTTP, live SComm runtime |

## Sync policy

- **Must match across languages:** Discovery wire (`/v1/`), error codes, MSK canonical bytes, CKVF container bytes.
- **May diverge:** CryptoProvider (WebCrypto vs native), PGP/CMS engines, OS keystores, Track B feature depth, release timing.
- **Do not** merge Discovery HTTP into `ckvf`. CKVF is the SComm.AI-maintained container layer, not a Discovery client.
- **Do not** require identical JS and Dart public APIs—require shared conformance fixtures.

## Tracks

- **Track A:** `GET /v1/mailboxes/{mailbox}`, parse Discovery Document, select mutually supported encryption keys. Enough for third-party web/webview clients.
- **Track B:** Track A plus challenges, operations, resources, MSK, hosted vault sync. SComm product clients (secMail0, Outlook).

## Version pins

- Protocol pin: [`DISCOVERY_PROTOCOL_VERSION.json`](../DISCOVERY_PROTOCOL_VERSION.json) (align with `pubkey/vendor/discovery-protocol/`).
- CKVF pin: `pubspec.yaml` / JS dependency on `ckvf` at a full SHA or tag—not `main`.
- Conformance fixtures under `conformance/fixtures/discovery/` must stay byte-compatible with `discovery-protocol/examples/v1/api/`.
