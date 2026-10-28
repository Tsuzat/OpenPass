# Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Threat model, crypto/auth specs, Rust core + test vectors, Workers Argon2 spike, credential-provider prototype | **In progress** — specs written, core implemented |
| 1 | Backend MVP: register/login, device approval, sessions, ciphertext sync, rate limiting | **In progress** — API implemented with in-memory + D1 stores |
| 2 | Client MVPs: macOS + Android + web vault: unlock (password + biometric), CRUD login/card/note/identity/TOTP, offline DB, password AutoFill both platforms, browser extensions | Scaffolded |
| 3 | Files (R2 chunked AEAD), import (Bitwarden/1Password/CSV), encrypted export | Planned |
| 4 | Synced passkeys (provider APIs), card/address autofill polish | Planned |
| 5 | External audit, pentest, reproducible builds, Docker target evaluation | Planned |

First usable milestone: Phase 1 API + Rust core test vectors green + one client (macOS) doing register → create login → sync → unlock-on-second-run with Touch ID.
