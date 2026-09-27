# Changelog

## 0.2.0

- `KeyVault.rotateSigningKey`: D8 signing retention — retire a sign-only key
  and `deletePrivate` (tombstone), optionally setting the new preferred signer.
  Decryption keys are not wiped.
- Barrel re-exports `PepperKey` / `PepperOprf` from `package:ckvf`.

## 0.1.0

- Initial local-first CKVF `KeyVault`, vault-host HTTP, identity VOPRF,
  pepper POPRF, and CPace pairing.
