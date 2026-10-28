# OpenPass Architecture (v1)

## Decisions (locked 2026-10-28)

| # | Decision |
|---|---|
| Auth model | Single master password (Bitwarden model). Auth and encryption keys cryptographically separated via HKDF. |
| Backend auth | Custom narrow auth protocol. No generic web-auth framework in the vault path. No email password reset. |
| Registration | Open (configurable: `ALLOW_REGISTRATION=false` for private instances). |
| Minimum OS | macOS 14+, Android 10+ (Credential Manager provider requires Android 14+). |
| Extensions | macOS credential provider, Safari web extension, Chrome/Firefox Manifest V3. |
| Device trust | New devices require approval from an existing approved device (Bitwarden style). |
| Clients | macOS, Android, Web vault, browser extensions. |
| Sharing | Not in v1 (individual vault only). Key wrapping anticipates it. |

## System

```
macOS (SwiftUI + ASCredentialProviderExtension)
Android (Kotlin/Compose + AutofillService + Credential Manager provider)
Web vault (React + TS, Argon2-WASM + WebCrypto, crypto in Web Worker)
Browser extensions (MV3: Chrome/Firefox, Safari wrapper)
        │  all clients share: Rust core (crates/openpass-core via UniFFI / WASM)
        │  HTTPS — ciphertext + derived auth verifier only
Cloudflare Worker (TypeScript + Hono)
  ├─ D1: users, devices, sessions, pending_devices, vaults, items (ciphertext), audit_log
  ├─ R2: encrypted file blobs (Phase 3)
  └─ Durable Objects: rate limiting (Phase 1 hardening)
```

## Principles

1. Zero-knowledge: server never receives master password, master key, vault key, TOTP seeds, card data, or passkey private keys.
2. Offline-first: local encrypted DB on every client; server is a sync relay.
3. Item titles, URLs, usernames live **inside** ciphertext. Server sees only IDs, type tag, timestamps, size, revision.
4. All crypto in one shared Rust core with cross-platform test vectors. No reimplementation per client.

## Item types (plaintext, client-only)

`login`, `card`, `identity` (incl. addresses), `secure_note`, `totp`, `passkey`, `file`.
Schemas: `packages/shared/src/items.ts`. Server stores `type` only for client filtering convenience — treated as non-sensitive.

## Sync

Per-item `revision` (monotonic, client-incremented, server-checked → 409 on conflict, server copy wins and client must surface conflict; never silent overwrite). Tombstones for deletes. Pull by `updated_at` cursor; push via `PUT /items/:id` or `POST /sync/push`.

## Repo layout

```
crates/openpass-core/   Rust crypto core (KDF, wrapping, item encryption, TOTP, generator)
services/api/           Cloudflare Worker + D1 migrations
packages/shared/        TS types + Zod item/API schemas (web + extension + API validation)
apps/web/               Web vault
apps/macos/             SwiftUI app + credential provider extension
apps/android/           Kotlin/Compose app + Autofill/Credential services
apps/extension/         Chrome/Firefox MV3 + Safari source
docs/                   Specs
```

## Self-hosting

One-command Cloudflare deploy: see `docs/DEPLOYMENT.md`. Portable interfaces (Hono + SQL store abstraction) keep a future Docker target possible.
