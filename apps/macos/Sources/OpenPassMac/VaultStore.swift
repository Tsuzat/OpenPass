import Foundation
import LocalAuthentication

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
        // TODO Phase 2: unwrap VaultKey copy sealed to Secure Enclave key, load encrypted DB.
        isUnlocked = true
        scheduleAutoLock(minutes: 5)
    }

    func unlockWithMasterPassword(_ password: String) async throws {
        // TODO Phase 2: Rust core derive_master_key -> fetch wrapped VaultKey -> unwrap -> open local DB.
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
