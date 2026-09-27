# scomm_vault_client

Reference Dart client for the ckvf
[vault-host profile](https://github.com/scomm-public/ckvf/blob/main/specification/profiles/vault-host.md).
Container format, merge, and unlock slots stay in `package:ckvf`.

- `KeyVault`: a local-first CKVF vault opened with this device's
  `device-wrap-a256gcm` slot. Keys, preferred keys, tombstones, device and
  key metadata (`priv:scomm.*` extensions), recovery-code and backup
  password slots, VEK rotation, and password-protected export. `push` and
  `pull` store generations with `POST /v1/vault/{vault_id}/records` and
  resolve `generation_conflict` with `mergeOnto`.
- `startPairing` / `fetchPairingRequest` / `approvePairing`: CPace v2
  pairing through the host mailbox. The approving device sends the VEK; the
  new device opens the stored container and `adopt`s it with its own slot.
- `openHostVaultWithSecret`: recovery with a grant, `oprf_token`, and a
  recovery code or backup password.
- `MskSigner`: `/v1/mutate` envelopes and records signatures from the
  payload MSK; `deviceReadAuthorization` for `Device` reads.
- `VaultHostClient`: `GET /v1/id/oprf/key`, `POST /v1/id/oprf/evaluate`,
  `GET /v1/pw-oprf/keys`, `POST /v1/pw-oprf/evaluate`, records, vault reads,
  open, MSK rebind, mutate, and the pairing mailbox.
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
