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
    /// Set once after registration — the UI must show it to the user a single time.
    @Published var recoveryKeyToShow: String?
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

    /// Create a new account + vault on this device (bootstrap device is auto-approved).
    func register(email: String, password: String) async throws {
        guard let base = URL(string: serverURL) else { throw APIClient.APIError.decoding }
        let client = APIClient(baseURL: base)
        let kdf = try OpenPassCrypto.newKdfParams()
        let params = APIClient.Prelogin.Params(memoryKib: kdf.memoryKib, iterations: kdf.iterations, parallelism: kdf.parallelism)
        let auth = try OpenPassCrypto.deriveAuthMaterial(password: password, params: kdf)
        let newVaultKey = OpenPassCrypto.randomVaultKey()
        let recovery = OpenPassCrypto.generateRecoveryKey()
        let resp = try await client.register(
            email: email, authVerifier: auth.authVerifier,
            kdfSaltB64: kdf.saltB64, kdfParams: params,
            wrappedVaultKey: try OpenPassCrypto.wrapKey(wrapper: auth.kek, key: newVaultKey),
            recoveryWrappedVaultKey: try OpenPassCrypto.wrapKey(wrapper: recovery.key, key: newVaultKey),
            recoveryAuthProof: try OpenPassCrypto.recoveryAuthProof(recoveryKey: recovery.key),
            identityPublicKey: OpenPassCrypto.randomVaultKey(), // placeholder until sharing (post-v1)
            wrappedIdentityPrivateKey: try OpenPassCrypto.wrapKey(wrapper: newVaultKey, key: OpenPassCrypto.randomVaultKey()),
            deviceId: deviceId, deviceName: Host.current().localizedName ?? "Mac")
        vaultKey = newVaultKey
        accessToken = resp.accessToken
        recoveryKeyToShow = recovery.text
        self.email = email
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

    struct ItemSummary: Identifiable, Equatable {
        let id: String; let name: String; let type: String; let username: String
    }
    @Published var items: [ItemSummary] = []
    private var ciphertextById: [String: APIClient.CipherItemDTO] = [:]

    /// Fetch ciphertext items and decrypt summaries (name/type/username) in memory.
    /// Full plaintext is decrypted on demand when an item is opened, never stored.
    func refreshItems() async {
        guard let accessToken, let vaultKey, let base = URL(string: serverURL) else { return }
        do {
            let resp = try await APIClient(baseURL: base).items(token: accessToken)
            ciphertextById = Dictionary(uniqueKeysWithValues: resp.items.map { ($0.id, $0) })
            items = resp.items.filter { !$0.deleted }.compactMap { dto in
                guard let ct = Data(base64Encoded: dto.ciphertextB64),
                      let wrapped = Data(base64Encoded: dto.wrappedItemKeyB64) else { return nil }
                let enc = EncryptedItem(ciphertextB64: dto.ciphertextB64, wrappedItemKeyB64: dto.wrappedItemKeyB64)
                _ = ct; _ = wrapped
                guard let plain = try? OpenPassCrypto.decryptItem(vaultKey: vaultKey, itemId: dto.id, item: enc),
                      let obj = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return nil }
                if obj["system"] != nil { return nil }
                return ItemSummary(id: dto.id, name: obj["name"] as? String ?? "(unnamed)",
                                   type: dto.type, username: obj["username"] as? String ?? "")
            }.sorted { $0.name < $1.name }
        } catch {
            // Offline: VaultKit cache takes over in the Xcode wiring; keep current list.
        }
    }

    func lock() {
        isUnlocked = false
        accessToken = nil
        vaultKey = nil // Data release; Rust-side keys are zeroized by the core on drop
        autoLockTask?.cancel()
    }

    /// Decrypt one item's full plaintext on open. Result is a flat string map for
    /// display; it lives in view state only and is dropped on selection change/lock.
    func decryptDetails(id: String) -> [String: String]? {
        guard let dto = ciphertextById[id], let vaultKey else { return nil }
        let enc = EncryptedItem(ciphertextB64: dto.ciphertextB64, wrappedItemKeyB64: dto.wrappedItemKeyB64)
        guard let plain = try? OpenPassCrypto.decryptItem(vaultKey: vaultKey, itemId: id, item: enc),
              let obj = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return nil }
        var out: [String: String] = [:]
        for (k, v) in obj {
            if let s = v as? String { out[k] = s }
            else if let n = v as? NSNumber { out[k] = n.stringValue }
            else if let arr = v as? [[String: Any]], k == "uris" { out[k] = arr.compactMap { $0["uri"] as? String }.joined(separator: ", ") }
            else if let tags = v as? [String] { out[k] = tags.map { "#\($0)" }.joined(separator: " ") }
        }
        return out
    }

    private func scheduleAutoLock(minutes: Int) {
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(minutes * 60))
            self?.lock()
        }
    }
}
