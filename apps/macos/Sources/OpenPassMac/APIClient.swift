import Foundation

/// Minimal auth API client for the macOS app. Sync of ciphertext items is
/// handled by VaultKit's SyncEngine (URLSessionVaultClient); this client covers
/// the auth endpoints that return wrapped keys.
struct APIClient {
    let baseURL: URL

    struct Prelogin: Decodable {
        let kdfSaltB64: String
        let kdfParams: Params
        struct Params: Decodable { let memoryKib: UInt32; let iterations: UInt32; let parallelism: UInt32 }
    }
    struct LoginResponse: Decodable {
        let accessToken: String
        let refreshToken: String
        let wrappedVaultKeyB64: String
        let recoveryWrappedVaultKeyB64: String
        let vaultId: String
    }
    enum APIError: Error { case http(Int, String), decoding }

    private func post<T: Decodable>(_ path: String, _ body: [String: Any], token: String? = nil) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status < 400 else { throw APIError.http(status, String(data: data, encoding: .utf8) ?? "") }
        do { return try JSONDecoder().decode(T.self, from: data) } catch { throw APIError.decoding }
    }

    struct RegisterResponse: Decodable {
        let accessToken: String
        let refreshToken: String
        let vaultId: String
        let userId: String
    }

    func prelogin(email: String) async throws -> Prelogin {
        try await post("/auth/prelogin", ["email": email])
    }

    func register(email: String, authVerifier: Data, kdfSaltB64: String,
                  kdfParams: Prelogin.Params, wrappedVaultKey: Data, recoveryWrappedVaultKey: Data,
                  recoveryAuthProof: Data, identityPublicKey: Data, wrappedIdentityPrivateKey: Data,
                  deviceId: String, deviceName: String) async throws -> RegisterResponse {
        try await post("/auth/register", [
            "email": email,
            "authVerifierB64": authVerifier.base64EncodedString(),
            "kdfSaltB64": kdfSaltB64,
            "kdfParams": ["memoryKib": kdfParams.memoryKib, "iterations": kdfParams.iterations, "parallelism": kdfParams.parallelism],
            "wrappedVaultKeyB64": wrappedVaultKey.base64EncodedString(),
            "recoveryWrappedVaultKeyB64": recoveryWrappedVaultKey.base64EncodedString(),
            "recoveryAuthProofB64": recoveryAuthProof.base64EncodedString(),
            "identityPublicKeyB64": identityPublicKey.base64EncodedString(),
            "wrappedIdentityPrivateKeyB64": wrappedIdentityPrivateKey.base64EncodedString(),
            "device": ["id": deviceId, "name": deviceName, "platform": "macos"],
        ])
    }

    struct CipherItemDTO: Decodable {
        let id: String; let type: String; let ciphertextB64: String; let wrappedItemKeyB64: String
        let revision: Int; let deleted: Bool; let updatedAt: String
    }
    struct ItemsResponse: Decodable { let items: [CipherItemDTO]; let cursor: String? }

    func items(token: String) async throws -> ItemsResponse {
        var req = URLRequest(url: baseURL.appendingPathComponent("/items"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await URLSession.shared.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw APIError.decoding }
        return try JSONDecoder().decode(ItemsResponse.self, from: data)
    }

    func login(email: String, authVerifier: Data, deviceId: String, deviceName: String) async throws -> LoginResponse {
        try await post("/auth/login", [
            "email": email,
            "authVerifierB64": authVerifier.base64EncodedString(),
            "device": ["id": deviceId, "name": deviceName, "platform": "macos"],
        ])
    }
}
