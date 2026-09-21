# @scomm/discovery

Discovery Protocol **Track A** client for browsers, webviews, and Node.

- `discoverMailbox(mailbox)` → `GET /v1/mailboxes/{mailbox}`
- `DiscoveryDocument.selectBestEncryptionKey(capabilities)` → local select

No MSK, Vault, OTP, or hosted sync. Those are Track B (`secmail_pubkey_sdk` Dart today).

Layering: [`../../docs/LAYERING.md`](../../docs/LAYERING.md).

## Install

Path (monorepo / workspace):

```bash
cd packages/js && npm ci && npm test
```

## Usage

```ts
import { createDiscoveryClient } from "@scomm/discovery";

const client = createDiscoveryClient({
  readBaseUrl: "https://discovery.scomm.ai",
});

const doc = await client.discoverMailbox("alice@example.com");
const key = doc.selectBestEncryptionKey({
  families: { pgp: ["openpgp-cv25519"] },
});
```

Callers must supply `readBaseUrl`. There is no silent production host default.

## Conformance

Tests load `../../conformance/fixtures/discovery/` (same pack as Dart).
