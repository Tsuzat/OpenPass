# OpenPass for macOS (14+)

SwiftUI app + `ASCredentialProviderExtension` for system AutoFill of passwords and synced passkeys.

- `swift build` requires **full Xcode** (SwiftUI macros are unavailable in Command Line Tools only). Sources pass `swiftc -parse` under CLT.
- In Xcode: create an app project embedding `Sources/OpenPassMac`, add the extension target from `CredentialProvider/`, enable App Groups + Keychain Sharing between app and extension, add the `autofill-credential-provider` entitlement.
- All crypto calls go to `crates/openpass-core` via UniFFI (binding generation is Phase 2). Never reimplement primitives in Swift.
