# Discovery conformance fixtures

These files are the **anti-drift pack** for Discovery Protocol clients.

| Fixture | Source of truth |
| --- | --- |
| `mailbox-discovery.json` | `discovery-protocol/examples/v1/api/mailbox-discovery.json` |
| `signing-vectors.json` | `discovery-protocol/examples/v1/api/signing-vectors.json` |

Pin: [`../../DISCOVERY_PROTOCOL_VERSION.json`](../../DISCOVERY_PROTOCOL_VERSION.json).

## Rules

1. Do not invent alternate canonical bytes or document shapes in language SDKs.
2. After a protocol change, refresh the vendored copy in `pubkey/vendor/discovery-protocol/`,
   then copy the API examples here and bump `specCommit`.
3. Dart (`dart test`) and JS (`packages/js` `npm test`) MUST load these paths
   (or identical bytes). Server tests load the vendored protocol tree.

Vault **container** vectors belong in `ckvf`, not here.
