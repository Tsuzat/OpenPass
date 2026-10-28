# Native OS Integration

## macOS 14+ (SwiftUI)

- **AutoFill + passkeys:** `ASCredentialProviderExtension`. Shares encrypted DB via App Group,
  wrapped VaultKey via Keychain access group. Extension unlocks independently (Touch ID),
  decrypts only the selected credential, auto-locks on dismissal.
- **Biometrics:** Touch ID / `LocalAuthentication`; VaultKey copy sealed to Secure Enclave
  key with `.biometryCurrentSet`.
- **Extras:** menu-bar item, global hotkey, lock on sleep. Safari extension wraps the MV3
  extension (Xcode Safari Web Extension converter target).

## Android 10+ (Kotlin / Jetpack Compose)

- **AutoFill:** `AutofillService` with inline autofill; strict matching on web domain /
  app signing-cert hash. Never fill on mismatch.
- **Passkeys:** Credential Manager **provider** service (Android 14+; below 14, OpenPass
  offers passwords via Autofill only). User verification via `BiometricPrompt`
  (`BIOMETRIC_STRONG`) + Keystore key invalidated on enrollment change.
- **Extras:** `FLAG_SECURE` on vault screens, quick-settings tile, QR scan for TOTP import.

## Browser extensions (Chrome/Firefox MV3, Safari wrapper)

Same TypeScript codebase (`apps/extension`). Communicate with the web vault origin only
over the public HTTPS API — extensions hold their own unlocked session (derived in the
extension via WASM core) and use native messaging to the desktop app only as an optional
unlock bridge (post-v1).

## Synced passkeys (Phase 4, protocol spike in Phase 0)

Vault item stores WebAuthn private key (encrypted), RP ID, counter, UV flags.
Creation/assertion implemented natively per platform; attestation `none`/self.
Server involvement: none — relying parties talk to the OS credential provider, which talks to us.
