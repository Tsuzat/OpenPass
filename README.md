# OpenPass

Open-source, self-hostable, zero-knowledge password manager.

Store passwords, cards, identities/addresses, secure notes, TOTP authenticator codes,
files, and synced passkeys — encrypted on your devices, synced as ciphertext through
your own Cloudflare account.

## Status

Phase 0/1 in progress: crypto core + backend API implemented and tested.
Native clients scaffolded. **Not yet audited — do not store real credentials.**

## Architecture

See `docs/`: [ARCHITECTURE](docs/ARCHITECTURE.md) · [CRYPTO](docs/CRYPTO.md) ·
[AUTH](docs/AUTH.md) · [NATIVE-INTEGRATION](docs/NATIVE-INTEGRATION.md) ·
[DEPLOYMENT](docs/DEPLOYMENT.md) · [ROADMAP](docs/ROADMAP.md)

Key properties:
- Master password never leaves the device; server receives only an HKDF-derived verifier.
- All items encrypted with per-item keys under a vault key (XChaCha20-Poly1305, Argon2id KDF).
- New devices require approval from an existing device.
- One shared Rust crypto core (`crates/openpass-core`) for all clients, with RFC test vectors.

## Quick start (backend)

```bash
bun install
bun run setup        # provision D1 + R2 on your Cloudflare account and deploy
bun test             # API + crypto core tests
```

## Layout

`crates/openpass-core` Rust crypto · `services/api` Cloudflare Worker (Hono + D1) ·
`packages/shared` TS schemas · `apps/web` web vault · `apps/macos` SwiftUI ·
`apps/android` Kotlin/Compose · `apps/extension` Chrome/Firefox/Safari

## License

AGPL-3.0-or-later.
