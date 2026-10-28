import AuthenticationServices
import VaultKit

/// AutoFill + synced passkey provider (macOS 14+).
/// Requires Xcode target with:
/// - com.apple.developer.authentication-services.autofill-credential-provider entitlement
/// - App Group shared with the main app (vault file via VaultKit VaultFileStore) + shared Keychain group
/// Extension unlocks independently with Touch ID, decrypts ONLY the selected credential, then locks.
///
/// Assertion signing path (passkeys):
///   request rpId -> load passkey item -> WebAuthn.rpIdMatches (exact) -> biometric UV
///   -> WebAuthn.makeAssertion(sign: OpenPassCrypto.passkeySign) -> ASPasskeyAssertionCredential
///   -> increment item counter + sync via VaultKit SyncEngine
final class CredentialProviderViewController: ASCredentialProviderViewController {

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        // TODO Xcode wiring: unlock vault (KeychainBiometricKeyStore), decrypt item
        // summaries, filter by service identifier domain with strict matching.
    }

    // Password AutoFill (one-time, without UI for previously verified requests)
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        if let passkeyRequest = credentialRequest as? ASPasskeyCredentialRequest {
            handlePasskeyRequest(passkeyRequest)
            return
        }
        // Password: present unlock + selection UI, then complete with ASPasswordCredential.
    }

    private func handlePasskeyRequest(_ request: ASPasskeyCredentialRequest) {
        // Pseudocode shape for the Xcode implementation (types verified against
        // AuthenticationServices on macOS 14):
        //
        // guard let assertionRequest = request as? ASPasskeyCredentialAssertionRequest else {
        //     // Registration: generate keypair in the Rust core, store passkey item,
        //     // build attested authenticator data via WebAuthn.registrationAuthenticatorData,
        //     // complete with ASPasskeyRegistrationCredential.
        //     return
        // }
        // 1. rpId = assertionRequest.relyingPartyIdentifier
        // 2. Load passkey item by credential ID; guard WebAuthn.rpIdMatches(requestRpId: rpId, storedRpId: item.rpId)
        // 3. Biometric UV (LAContext), then:
        //    let assertion = try WebAuthn.makeAssertion(
        //        rpId: rpId, credentialId: credentialIdData, clientDataHash: assertionRequest.clientDataHash,
        //        signCount: item.counter + 1, userHandle: item.userHandle) { signed in
        //            try OpenPassCrypto.passkeySign(privateKeyPkcs8: item.privateKey, data: signed)
        //        }
        // 4. extensionContext.completeAssertionRequest(using:
        //        ASPasskeyAssertionCredential(userHandle: assertion.userHandle ?? Data(),
        //            credentialID: assertion.credentialId, clientDataHash: assertionRequest.clientDataHash,
        //            authenticatorData: assertion.authenticatorData, signature: assertion.signature))
        // 5. Persist counter + 1 and sync.
        _ = request
    }
}
