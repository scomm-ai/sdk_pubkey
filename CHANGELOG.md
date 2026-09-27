# Changelog

## Unreleased

- `parseGrantV1` reads a `Scomm/grant/v1` vault grant (purpose, audience,
  expiry, MSK fingerprint) without verifying it. Directory grants are opaque
  and return null. Shared vectors live in
  `conformance/fixtures/grant-vectors.json`.

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
