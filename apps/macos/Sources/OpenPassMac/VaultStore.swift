import Foundation
import LocalAuthentication
#if canImport(VaultKit)
import VaultKit
#endif

/// Vault state machine: locked (cold) -> biometric-armed -> unlocked.
/// All cryptography delegates to the Rust core (crates/openpass-core via UniFFI) —
/// Swift never implements primitives directly.
@MainActor
final class VaultStore: ObservableObject {
    @Published var isUnlocked = false
    @Published var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: "openpass.serverURL") }
    }
    @Published var email: String {
        didSet { UserDefaults.standard.set(email, forKey: "openpass.email") }
    }
    /// Set once after registration — the UI must show it to the user a single time.
    @Published var recoveryKeyToShow: String?
    @Published var items: [ItemSummary] = []
    /// nil = not checked, true/false = last /health result for the server field.
    @Published var serverReachable: Bool?

    private var autoLockTask: Task<Void, Never>?
    private(set) var accessToken: String?
    private var vaultKey: Data?
    private var ciphertextById: [String: APIClient.CipherItemDTO] = [:]

    init() {
        serverURL = UserDefaults.standard.string(forKey: "openpass.serverURL") ?? "https://your-worker.example.com"
        email = UserDefaults.standard.string(forKey: "openpass.email") ?? ""
    }

    var deviceId: String {
        if let id = UserDefaults.standard.string(forKey: "openpass.deviceId") { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: "openpass.deviceId")
        return id
    }

    /// Normalize user input: trim, drop trailing slashes, default to https.
    var normalizedServerURL: URL? {
        var s = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasSuffix("/") { s.removeLast() }
        if !s.contains("://") { s = "https://" + s }
        return URL(string: s)
    }

    var biometricsAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func friendlyMessage(for error: Error) -> String {
        if let api = error as? APIClient.APIError { return api.userMessage }
        if let urlError = error as? URLError {
            switch urlError.code {
            case .cannotFindHost, .dnsLookupFailed: return "Cannot find that server. Check the server URL."
            case .cannotConnectToHost: return "Cannot connect to the server. Is the URL right, and is the API deployed?"
            case .secureConnectionFailed, .serverCertificateUntrusted: return "TLS connection failed. Check the server URL (https)."
            case .timedOut: return "Connection timed out."
            default: return "Network error: \(urlError.localizedDescription)"
            }
        }
        return "\(error)"
    }

    func checkServer() async {
        guard let base = normalizedServerURL else { serverReachable = false; return }
        serverReachable = await APIClient(baseURL: base).health()
    }

    // MARK: - Auth

    func register(email: String, password: String) async throws {
        guard let base = normalizedServerURL else { throw APIClient.APIError.decoding }
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
        await refreshItems()
    }

    func unlockWithMasterPassword(_ password: String) async throws {
        guard let base = normalizedServerURL else { throw APIClient.APIError.decoding }
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
        isUnlocked = true
        scheduleAutoLock(minutes: 5)
        await refreshItems()
    }

    func unlockWithBiometrics() async throws {
        let context = LAContext()
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                         localizedReason: "Unlock your OpenPass vault")
        // Biometric unlock is armed only after the Secure Enclave device-key wrap
        // lands; until then fail honestly instead of opening a keyless session.
        throw NSError(domain: "OpenPass", code: 11, userInfo: [
            NSLocalizedDescriptionKey: "Touch ID unlock is not set up yet. Use your master password.",
        ])
    }

    func lock() {
        isUnlocked = false
        accessToken = nil
        vaultKey = nil
        items = []
        ciphertextById = [:]
        autoLockTask?.cancel()
    }

    private func scheduleAutoLock(minutes: Int) {
        autoLockTask?.cancel()
        autoLockTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(minutes * 60))
            self?.lock()
        }
    }

    // MARK: - Items

    struct ItemSummary: Identifiable, Equatable {
        let id: String; let name: String; let type: String; let username: String
    }

    func refreshItems() async {
        guard let accessToken, let vaultKey, let base = normalizedServerURL else { return }
        do {
            let resp = try await APIClient(baseURL: base).items(token: accessToken)
            ciphertextById = Dictionary(uniqueKeysWithValues: resp.items.map { ($0.id, $0) })
            items = resp.items.filter { !$0.deleted }.compactMap { dto in
                let enc = EncryptedItem(ciphertextB64: dto.ciphertextB64, wrappedItemKeyB64: dto.wrappedItemKeyB64)
                guard let plain = try? OpenPassCrypto.decryptItem(vaultKey: vaultKey, itemId: dto.id, item: enc),
                      let obj = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return nil }
                if obj["system"] != nil { return nil }
                let subtitle = (obj["username"] as? String) ?? (obj["issuer"] as? String) ?? (obj["rpId"] as? String) ?? ""
                return ItemSummary(id: dto.id, name: obj["name"] as? String ?? "(unnamed)", type: dto.type, username: subtitle)
            }.sorted { $0.name < $1.name }
        } catch {
            // Keep current list on transient failures.
        }
    }

    /// Full decrypted plaintext for one item (view state only, never persisted).
    func decryptItem(id: String) -> [String: Any]? {
        guard let dto = ciphertextById[id], let vaultKey else { return nil }
        let enc = EncryptedItem(ciphertextB64: dto.ciphertextB64, wrappedItemKeyB64: dto.wrappedItemKeyB64)
        guard let plain = try? OpenPassCrypto.decryptItem(vaultKey: vaultKey, itemId: id, item: enc),
              let obj = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return nil }
        return obj
    }

    /// Current TOTP code for a totp item, plus seconds remaining in the window.
    func totp(forItemId id: String) -> (code: String, remaining: Int)? {
        guard let obj = decryptItem(id: id), let secret = obj["secretBase32"] as? String else { return nil }
        let digits = (obj["digits"] as? NSNumber)?.uint32Value ?? 6
        let sha256 = (obj["algorithm"] as? String) == "SHA256"
        guard let code = try? OpenPassCrypto.totpCode(secretBase32: secret, digits: digits, sha256: sha256) else { return nil }
        let remaining = 30 - Int(Date().timeIntervalSince1970) % 30
        return (code, remaining)
    }

    /// Download + decrypt a file item; returns decrypted bytes for the caller to save.
    func downloadFile(id: String) async throws -> (name: String, data: Data)? {
        guard let obj = decryptItem(id: id), let vaultKey,
              let attachmentId = obj["attachmentId"] as? String,
              let wrappedFileKey = obj["wrappedFileKeyB64"] as? String,
              let accessToken, let base = normalizedServerURL else { return nil }
        var req = URLRequest(url: base.appendingPathComponent("attachments/\(attachmentId)"))
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        let (cipher, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw APIClient.APIError.decoding }
        let fileKey = try OpenPassCrypto.unwrapKey(wrapper: vaultKey, blob: Data(base64Encoded: wrappedFileKey) ?? Data())
        let data = try OpenPassCrypto.decryptFile(vaultKey: fileKey, blob: cipher)
        return (obj["fileName"] as? String ?? "download", data)
    }
}
