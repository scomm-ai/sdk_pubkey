# Sync Discovery fixtures into sdk_pubkey

Run from the `sdk_pubkey` repo root when `discovery-protocol` examples change.

```powershell
$proto = "..\..\scomm-public\discovery-protocol"  # adjust if needed
Copy-Item "$proto\examples\v1\api\mailbox-discovery.json" `
  "conformance\fixtures\discovery\mailbox-discovery.json" -Force
Copy-Item "$proto\examples\v1\api\signing-vectors.json" `
  "conformance\fixtures\discovery\signing-vectors.json" -Force
# Then bump DISCOVERY_PROTOCOL_VERSION.json specCommit to match
# pubkey/vendor/discovery-protocol/DISCOVERY_PROTOCOL_VERSION.json
```

After sync: `dart test test/discovery_api_test.dart` and
`cd packages/js; npm test`.
