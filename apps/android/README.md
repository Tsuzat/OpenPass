# OpenPass for Android (10+)

Kotlin + Jetpack Compose. Min SDK 29 (Android 10); Credential Manager passkey provider requires Android 14+.

Services declared in `AndroidManifest.xml`:
- `OpenPassAutofillService` — passwords/cards (Autofill framework, strict domain/app-cert matching)
- `OpenPassCredentialProviderService` — synced passkeys + passwords (Credential Manager)

Build requires JDK 17 + Android SDK 35 + Gradle (not available in the current dev environment — sources are scaffolds pending toolchain validation):

```bash
./gradlew assembleDebug   # wrapper generated on first Android Studio import
```

Crypto delegates to `crates/openpass-core` via UniFFI AAR (Phase 2). Never reimplement primitives in Kotlin.
Biometric unlock: `BiometricPrompt` (BIOMETRIC_STRONG) gating an Android Keystore key with
`setInvalidatedByBiometricEnrollment(true)`.
