# Upstream note for ckvf-sdks

SComm remains the master runtime (`sdk_pubkey`). Community Dart/JS SDKs
should document:

- VEK / AEK / DKEK device envelopes
- Opaque hosted generations (server never unwraps; password is not the sync root)
- Password **backup** as a layer above VEK (`scomm-vault-export` / Argon2id EEK), not password-as-VEK
- VERSION pins: do not rewrite container version on open

Copy the hierarchy from `docs/scomm-vault-hierarchy.md` in this repo.
