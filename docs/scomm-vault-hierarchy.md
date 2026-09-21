# SComm vault hierarchy (master)

SComm is the live vault implementation. Community CKVF (`package:ckvf` /
[ckvf-sdks](https://github.com/Cryptographic-Key-Vault-Format/ckvf-sdks))
should describe this hierarchy — not the reverse. Wire format for hosted
generations stays SComm opaque ciphertext + MSK signature. `package:ckvf` is
used for JCS/base64url helpers until it exports equivalent hierarchy APIs.

## Standing device unlock (not password)

1. **DKEK** — device-only wrap key (software today). Never leaves the device.
2. **VEK** — AES-256-GCM vault seal. Wrapped by DKEK on the device.
3. **AEK** — wraps MSK inside the vault. Full-tier devices only. Wrapped by DKEK.
4. **Vault plaintext** — content keys (signing/encryption privates), device
   list, pointers. Sealed with VEK.
5. **Hosted generations** — opaque ciphertext + hash chain + MSK signature.
   The write host MUST NOT unwrap records or take a vault password as the
   sync root.

Limited-tier devices receive VEK (and can pull hosted generations after VEK
is installed). They cannot unwrap MSK or upload.

## Password backup layer (after VEK seal)

Password is **not** standing unlock and **not** password-as-VEK.

`exportVaultOffline` produces `kind: scomm-vault-export` with Argon2id **EEK**
wrapping VEK (and AEK for full tier). Stores:

- Local file / USB (user already holds the blob; password-only unwrap)
- Optional hosted slot on discovery.scomm.ai (MSK-signed put; mailbox OTP
  gates download; OTP MUST NOT decrypt; client unwraps EEK locally)

Never upload an export with `hasSecrets == false` to the hosted store.

## Recovery (honest bounds)

| Loss | Recovery |
|------|----------|
| One device | Pairing or password backup import |
| All devices, password backup exists | File or hosted backup + OTP + password |
| All devices, recovery code exists | REK path |
| OTP only | New empty vault; old generations stay undecryptable |

## Container VERSION pins

Do not silently rewrite a container version on open. Match test-vector
VERSION pins. No live-format migration is implied by documenting this
hierarchy in community SDKs.
