# Custom Auth Protocol v1

Custom protocol glue over audited primitives only. No OAuth, no email reset, no social login.

## Registration `POST /auth/register`

Client sends: `email`, `authVerifier` (base64, 32B, HKDF-derived — never the password),
`kdfSalt`, `kdfParams {memoryKib, iterations, parallelism}`,
`wrappedVaultKey` (by KEK), `recoveryWrappedVaultKey`, `recoveryAuthProofB64` (see CRYPTO.md),
`identityPublicKey`, `wrappedIdentityPrivateKey`.
Server: validates, stores PBKDF2(authVerifier), creates default vault. First device in the
registration request (`device {id, name, platform}`) is auto-approved (bootstrap).

## Login

1. `POST /auth/prelogin {email}` → `{kdfSalt, kdfParams}`. Unknown emails get deterministic
   fake params (SHA-256 of email → salt) to prevent account enumeration.
2. Client derives AuthVerifier locally.
3. `POST /auth/login {email, authVerifier, device}`:
   - Unknown/unapproved device → creates `pending_devices` row, returns
     `403 {code:"DEVICE_APPROVAL_REQUIRED", deviceId}`.
   - Approved device → `200 {accessToken, refreshToken, wrappedVaultKey, recoveryWrappedVaultKey, vaultId}`.
4. Existing device approves: `GET /devices/pending`, `POST /devices/:deviceId/approve` (Bearer).
   New device then retries login (poll `GET /auth/device-status?deviceId=` → `pending|approved|unknown`).

## Tokens

- Access: opaque 256-bit random, 15 min TTL, stored SHA-256-hashed in `sessions`.
- Refresh: opaque 256-bit random, 30 day TTL, rotating. Presenting an already-rotated
  refresh token revokes **all** sessions for that device (theft detection).
- Native clients and web use `Authorization: Bearer`. No cookies → no CSRF surface.
- Password change (`POST /auth/change-password`, requires current verifier): re-derives,
  replaces verifier hash + wrapped keys, revokes all other sessions.

## Password change & recovery (implemented)

- `POST /auth/change-password` (Bearer): requires the current derived verifier; replaces
  verifier + KDF salt/params + KEK-wrapped vault key (new random salt). All other sessions revoked.
  The recovery-wrapped copy is untouched — the vault key does not change.
- Recovery (forgotten password), two calls, both gated by the recovery proof
  (server stores PBKDF2 of `HKDF(recoveryKey, "openpass/recovery-auth/v1")` from registration):
  1. `POST /auth/recovery-info {email, recoveryAuthProofB64}` → recovery-wrapped vault key.
  2. Client unwraps the vault key with the recovery key locally, derives a new master
     password, then `POST /auth/recover` replaces verifier/wrapped keys. All sessions revoked.
  The recovery key itself does not rotate in this flow, so the same key keeps working.

## Hardening (in scope)

PBKDF2 verifier hashing, constant-time verifier comparison, per-IP + per-account rate
limiting (middleware; Durable Object upgrade path), Turnstile hook on register (optional
env), audit log of auth events (metadata only), registration kill-switch env.

## Explicitly rejected

- Email password reset (breaks zero-knowledge). Recovery = Recovery Key only.
- Sending the master password to the server in any form other than the HKDF verifier.
- JWTs (opaque tokens give instant revocation, needed for device management).
