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
    @Published var email = ""
    private var autoLockTask: Task<Void, Never>?
    private(set) var accessToken: String?
    private var vaultKey: Data?

    var deviceId: String {
        if let id = UserDefaults.standard.string(forKey: "openpass.deviceId") { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: "openpass.deviceId")
        return id
    }

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
        guard let base = URL(string: serverURL) else { throw APIClient.APIError.decoding }
        let client = APIClient(baseURL: base)
        let pre = try await client.prelogin(email: email)
        let params = KdfParams(memoryKib: pre.kdfParams.memoryKib, iterations: pre.kdfParams.iterations,
                               parallelism: pre.kdfParams.parallelism, saltB64: pre.kdfSaltB64)
        let auth = try OpenPassCrypto.deriveAuthMaterial(password: password, params: params)
        let resp = try await client.login(email: email, authVerifier: auth.authVerifier,
                                          deviceId: deviceId, deviceName: Host.current().localizedName ?? "Mac")
        guard let wrapped = Data(base64Encoded: resp.wrappedVaultKeyB64) else { throw APIClient.APIError.decoding }
        vaultKey = try OpenPassCrypto.unwrapKey(wrapper: auth.kek, blob: wrapped)
        accessToken = resp.accessToken
        // NOTE: VaultKit SyncEngine pull + Secure Enclave re-wrap of vaultKey for
        // Touch ID are wired in the Xcode target (App Group container choice pending).
        isUnlocked = true
        scheduleAutoLock(minutes: 5)
    }

    /// In-memory vault key for item decryption via OpenPassCrypto. Never persisted unwrapped.
    func withVaultKey<T>(_ body: (Data) throws -> T) throws -> T {
        guard let vaultKey else { throw APIClient.APIError.decoding }
        return try body(vaultKey)
    }

    func lock() {
        isUnlocked = false
        accessToken = nil
        vaultKey = nil // Data release; Rust-side keys are zeroized by the core on drop
        autoLockTask?.cancel()
    }

    private func scheduleAutoLock(minutes: Int) {
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(minutes * 60))
            self?.lock()
        }
    }
}
