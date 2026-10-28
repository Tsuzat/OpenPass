# Cryptography Spec v1

Implemented in `crates/openpass-core`. This document is normative; code must match it or the spec is amended first.

## Algorithms

| Use | Primitive |
|---|---|
| Master KDF | Argon2id, m=64 MiB, t=3, p=4, 16-byte random salt, 32-byte output |
| Key separation | HKDF-SHA-256, salt = Argon2id salt, info strings below |
| Symmetric encryption | XChaCha20-Poly1305, 24-byte random nonce per operation |
| Wrapping | Same AEAD; wrapped blob = `version(1) ‖ nonce(24) ‖ ciphertext` |
| Recovery key | 256-bit random, encoded as grouped Base32 (XXXX-XXXX-…) |
| Recovery proof | `HKDF-SHA256(recoveryKey, info="openpass/recovery-auth/v1")` — server stores PBKDF2 of this; proves recovery-key possession without revealing the key that also wraps the vault key |
| TOTP | RFC 6238, HMAC-SHA-1 (compat) / SHA-256, 30 s period, 6 digits default |
| Server verifier storage | PBKDF2-HMAC-SHA-256, 100k iterations, per-user salt (WebCrypto-native; Workers caps PBKDF2 at 100k iterations — exceeding it throws on real Workers. Verifier is already an Argon2id-derived key, never the password; iteration count is stored in the hash string so it can change) |

## Key hierarchy

```
MasterPassword ──Argon2id(salt)──► MasterKey (32B)
                                     ├─ HKDF info "openpass/auth/v1" ─► AuthVerifier (sent to server)
                                     └─ HKDF info "openpass/kek/v1"  ─► KEK
VaultKey (random 32B) ── wrapped by KEK ─────────────► stored on server
                      ── wrapped by RecoveryKey ─────► stored on server
                      ── wrapped by per-device biometric key ─► on-device only
ItemKey (random 32B per item) ── wrapped by VaultKey
Item plaintext JSON ── encrypted by ItemKey (XChaCha20-Poly1305, AAD = item id)
FileKey (random, per file) ── wrapped by VaultKey; file encrypted in 64 KiB AEAD chunks (Phase 3)
Identity keypair X25519 (sharing, post-v1): private key wrapped by VaultKey
```

Password change: re-derive MasterKey, re-wrap VaultKey. Items untouched.
AuthVerifier compromise alone cannot decrypt: it is a one-way HKDF output, domain-separated from KEK.

## Biometric unlock

Per device: Secure Enclave (macOS) / Android Keystore generates a non-exportable key gated by biometrics (`biometryCurrentSet` / `setInvalidatedByBiometricEnrollment(true)`). VaultKey is wrapped to this key and stored in Keychain/Keystore. Enrollment change invalidates the wrap → master-password fallback by design.

## Versioning

Every wrapped/encrypted blob carries format version byte `0x01`. Item plaintext JSON carries `v: 1`. Algorithm migration = new version, decrypt-old/encrypt-new on unlock.

## Non-goals / prohibitions

- No custom primitives, no AES-ECB, no nonce reuse (random 192-bit nonces), no plaintext item metadata on server.
- Master password and AuthVerifier are never logged anywhere, including crash reports.
- Keys zeroized on lock (`zeroize` crate; `mlock` where available is post-v1).
