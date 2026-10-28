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

    func prelogin(email: String) async throws -> Prelogin {
        try await post("/auth/prelogin", ["email": email])
    }

    func login(email: String, authVerifier: Data, deviceId: String, deviceName: String) async throws -> LoginResponse {
        try await post("/auth/login", [
            "email": email,
            "authVerifierB64": authVerifier.base64EncodedString(),
            "device": ["id": deviceId, "name": deviceName, "platform": "macos"],
        ])
    }
}
