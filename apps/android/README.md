# OpenPass for Android (10+)

Kotlin + Jetpack Compose. Min SDK 29 (Android 10); Credential Manager passkey provider requires Android 14+.

Services declared in `AndroidManifest.xml`:
- `OpenPassAutofillService` — passwords/cards (Autofill framework, strict domain/app-cert matching)
- `OpenPassCredentialProviderService` — synced passkeys + passwords (Credential Manager)

Build (toolchain verified on macOS: OpenJDK 17, SDK 35, Gradle wrapper 8.9):

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
bash ../../scripts/build-android-core.sh   # Rust core -> jniLibs (.so per ABI)
./gradlew assembleDebug                    # -> app/build/outputs/apk/debug/app-debug.apk
```

Verified: APK builds, installs, and launches on an Android 35 (arm64) emulator.
Notes:
- Provider classes ship inside `androidx.credentials:credentials` — there is no
  `credentials-provider` artifact on Google Maven (checked directly).
- UniFFI bindings load `libopenpass_core.so` through JNA; without the jniLibs
  step the app compiles but crypto calls fail at runtime.

Crypto delegates to `crates/openpass-core` via UniFFI AAR (Phase 2). Never reimplement primitives in Kotlin.
Biometric unlock: `BiometricPrompt` (BIOMETRIC_STRONG) gating an Android Keystore key with
`setInvalidatedByBiometricEnrollment(true)`.
