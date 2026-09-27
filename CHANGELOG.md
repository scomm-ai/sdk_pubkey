# Changelog

## Unreleased

- New package `packages/scomm_vault_client` (0.1.0): vault-host client
  with identity OPRF proof verification, pepper POPRF (`HostPepperOprf` for
  the `ckvf` slot APIs), key listing, read authorization, and grant parsing.
  Pure Dart; checked against the ckvf `pepper-oprf` vectors.
- `parseGrantV1` reads a `Scomm/grant/v1` vault grant (purpose, audience,
  expiry, MSK fingerprint) without verifying it. Directory grants are opaque
  and return null. Shared vectors live in
  `conformance/fixtures/grant-vectors.json`.
- MSK arming is one call. `verifyEnrollForIdentity` posts to `/v1/msk/arm` and
  `verifyReplaceForIdentity` to `/v1/msk/replace/arm`, each with the grant,
  the MSK public key, and the MSK proof. `enrollMskForIdentity` and
  `replaceMskForIdentity` are deprecated and no longer call the server.
- `MailerClient.requestOtp` and `createIdTokenChallenge` require
  `mskPublicKey` for `enroll` and `replace_msk` (sent as `msk_jkt`).
- `MailerOtpGrant.vaultGrant` carries the signed vault grant returned with
  `replace_msk`.
- A directory without the single-call routes fails with
  `directory_upgrade_required`.
- Fix: the first native base64/JCS call in a process no longer throws
  `LateInitializationError`.

## 1.3.0

- Mailer client can prove a Gmail or Microsoft mailbox with an OIDC ID token
  (`fetchIdTokenConfig`, `createIdTokenChallenge`, `verifyIdToken`) and receive
  the same `otp_grant` the OTP verify call returns.
- `recoverWithGrant` and `DiscoveryBackupStore.getWithGrant` accept that grant
  directly. `recoverWithCode` and `get` still verify an OTP, then call them.
- Error codes for the ID-token path: `idtoken_not_supported`,
  `idtoken_challenge_invalid`, `idtoken_invalid`, `idtoken_replayed`,
  `idtoken_email_unverified`, `idtoken_email_mismatch`,
  `idtoken_subject_mismatch`.
