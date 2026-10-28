# Custom Auth Protocol v1

Custom protocol glue over audited primitives only. No OAuth, no email reset, no social login.

## Registration `POST /auth/register`

Client sends: `email`, `authVerifier` (base64, 32B, HKDF-derived — never the password),
`kdfSalt`, `kdfParams {memoryKib, iterations, parallelism}`,
`wrappedVaultKey` (by KEK), `recoveryWrappedVaultKey`, `identityPublicKey`, `wrappedIdentityPrivateKey`.
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

## Hardening (in scope)

PBKDF2 verifier hashing, constant-time verifier comparison, per-IP + per-account rate
limiting (middleware; Durable Object upgrade path), Turnstile hook on register (optional
env), audit log of auth events (metadata only), registration kill-switch env.

## Explicitly rejected

- Email password reset (breaks zero-knowledge). Recovery = Recovery Key only.
- Sending the master password to the server in any form other than the HKDF verifier.
- JWTs (opaque tokens give instant revocation, needed for device management).
