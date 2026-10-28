import Foundation
import LocalAuthentication
#if canImport(VaultKit)
import VaultKit
#endif

/// Vault state machine: locked (cold) -> biometric-armed -> unlocked.
/// All cryptography delegates to the Rust core (crates/openpass-core via UniFFI) —
/// Swift never implements primitives directly. Bindings: scripts/generate-bindings.sh (Phase 2).
@MainActor
final class VaultStore: ObservableObject {
    @Published var isUnlocked = false
    @Published var serverURL = "https://your-worker.example.com"
    private var autoLockTask: Task<Void, Never>?

    /// Biometric availability for arming device-local wrapped VaultKey (Secure Enclave).
    var biometricsAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func unlockWithBiometrics() async throws {
        let context = LAContext()
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                         localizedReason: "Unlock your OpenPass vault")
        #if canImport(VaultKit)
        // Load the biometry-gated wrapped vault key blob (Keychain access control
        // drives its own Touch ID prompt), then unwrap via the Rust core:
        //   let blob = try KeychainBiometricKeyStore().loadWrappedVaultKey()
        //   vaultKey = try OpenPassCrypto.unwrapKey(wrapper: deviceKey, blob: blob)
        _ = try KeychainBiometricKeyStore().loadWrappedVaultKey()
        #endif
        isUnlocked = true
        scheduleAutoLock(minutes: 5)
    }

    func unlockWithMasterPassword(_ password: String) async throws {
        // Full flow (auth layer): prelogin -> OpenPassCrypto.deriveAuthMaterial ->
        // POST /auth/login -> OpenPassCrypto.unwrapKey(kek, wrappedVaultKey) ->
        // VaultKit SyncEngine pull -> decrypt items on demand via OpenPassCrypto.
        _ = password
        isUnlocked = true
        scheduleAutoLock(minutes: 5)
    }

    func lock() {
        isUnlocked = false
        autoLockTask?.cancel()
        // TODO Phase 2: zeroize key material via Rust core handle drop.
    }

    private func scheduleAutoLock(minutes: Int) {
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(minutes * 60))
            self?.lock()
        }
    }
}
