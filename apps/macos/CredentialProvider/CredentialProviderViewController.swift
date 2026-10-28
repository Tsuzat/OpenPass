import AuthenticationServices

/// AutoFill + synced passkey provider (macOS 14+).
/// Requires Xcode target with:
/// - com.apple.developer.authentication-services.autofill-credential-provider entitlement
/// - App Group shared with the main app (encrypted DB) + shared Keychain access group (wrapped VaultKey)
/// Extension unlocks independently with Touch ID, decrypts ONLY the selected credential, then locks.
final class CredentialProviderViewController: ASCredentialProviderViewController {

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // TODO Phase 2/4: unlock (biometric) -> query local DB by serviceIdentifier -> list matches.
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        // Only for previously user-verified, low-risk requests; otherwise:
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        // TODO: present unlock + selection UI, then complete with ASPasswordCredential / ASPasskeyAssertionCredential.
    }
}
