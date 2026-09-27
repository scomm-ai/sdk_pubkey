# scomm_vault_client

Reference Dart client for the ckvf
[vault-host profile](https://github.com/scomm-public/ckvf/blob/main/specification/profiles/vault-host.md).
Container create, open, merge, and unlock slots stay in `package:ckvf`; this
package does the network half.

- `VaultHostClient`: `GET /v1/id/oprf/key`, `POST /v1/id/oprf/evaluate`,
  `GET /v1/pw-oprf/keys`, `POST /v1/pw-oprf/evaluate`, vault reads, open,
  and MSK rebind.
- `identityId`: RFC 9497 identity OPRF with the host's DLEQ proof verified
  against a pinned or fetched public key.
- `HostPepperOprf`: the `PepperOprf` that `addPepperSlot`,
  `openVaultWithPepper`, and `rewrapPepperSlot` call. It blinds, calls the
  host, checks the `kid`, and verifies the POPRF proof. A bad proof raises
  `VaultClientException('invalid_evaluation')`.
- `VaultAuthorization`: `OtpGrant`, `PairingRead`, `OprfToken`, `Device`.
- `parseGrantV1`: reads `Scomm/grant/v1` claims for routing and expiry.

```dart
final host = VaultHostClient('https://vault.scomm.ai');
final keys = await host.pepperKeys();
final pepper = HostPepperOprf(host, VaultAuthorization.oprfToken(token));
final opened = await openVaultWithPepper(container,
    secret: password, pepper: pepper, crypto: DartCkvfCrypto());
final slot = opened.container.unlockSlots
    .firstWhere((s) => s.method == passwordOprfMethod);
if (keys.needsRewrap(slot.oprf!.kid)) {
  await rewrapPepperSlot(opened, DartCkvfCrypto(),
      slotId: slot.slotId, secret: password, pepper: pepper, key: keys.current);
}
```

Test fixtures: `test/fixtures/pepper-poprf.json` is ckvf
`test-vectors/pepper-oprf/poprf.json`; `identity-voprf.json` was produced
with `@noble/curves` the way the vault host evaluates.
