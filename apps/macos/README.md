# OpenPass for macOS (14+)

SwiftUI app + `ASCredentialProviderExtension` for system AutoFill of passwords and synced passkeys.

## Build

Requires full Xcode. If `xcode-select` still points at Command Line Tools, either
run `sudo xcode-select -s /Applications/Xcode.app` once, or prefix commands with
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

```bash
brew install xcodegen
bash ../../scripts/build-macos-core.sh   # Rust core -> Frameworks/OpenPassCoreFFI.xcframework
cd apps/macos && xcodegen generate       # project.yml -> OpenPass.xcodeproj (gitignored)
xcodebuild -project OpenPass.xcodeproj -scheme OpenPassMac -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO build          # signing off for local verification builds
```

Verified: app target (app + embedded `CredentialProvider.appex`) builds and launches;
VaultKit XCTest suite passes (`cd VaultKit && swift test`).

For a runnable signed build, set your development team in Xcode (targets
`OpenPassMac` and `CredentialProvider`); App Group `group.app.openpass` must match
your team entitlements.

Layout:
- `Sources/OpenPassMac` — SwiftUI app (lock screen, vault list, decrypt-on-open details,
  Touch ID via Secure Enclave plan, real API unlock flow)
- `Sources/OpenPassCoreFFI` — UniFFI-generated Swift bindings (regenerate with
  `scripts/generate-bindings.sh`); app code calls them through `OpenPassCrypto`
- `CredentialProvider/` — `ASCredentialProviderExtension` (assertion flow uses
  VaultKit `WebAuthn` + Rust core signing)
- `VaultKit/` — pure-Foundation local vault store + sync engine + WebAuthn builders

All crypto delegates to `crates/openpass-core`. Never reimplement primitives in Swift.
