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
    enum APIError: Error {
        case http(Int, String)
        case decoding
        /// Structured error code from the API body: {"error":{"code":"..."}}
        case server(code: String, status: Int)

        var userMessage: String {
            switch self {
            case .server(let code, _):
                switch code {
                case "DEVICE_APPROVAL_REQUIRED":
                    return "This Mac is a new device. Approve it from a device you're already signed in on (Web Vault → Devices), then try again."
                case "INVALID_CREDENTIALS": return "Invalid email or master password."
                case "EMAIL_TAKEN": return "An account with this email already exists. Use Log in instead."
                case "REGISTRATION_CLOSED": return "Registration is closed on this server."
                case "RATE_LIMITED": return "Too many attempts. Wait a minute and try again."
                case "UNAUTHORIZED": return "Session expired. Please sign in again."
                default: return "Server error: \(code)"
                }
            case .http(let status, _):
                if status >= 500 {
                    return "The server hit an internal error (HTTP \(status)). If you just deployed, make sure the D1 migrations were applied (wrangler d1 migrations apply openpass --remote), then redeploy."
                }
                return "Server returned HTTP \(status). Check the server URL."
            case .decoding: return "Unexpected response from the server. Check the server URL is your OpenPass API."
            }
        }
    }

    private struct ErrorBody: Decodable { struct Inner: Decodable { let code: String }; let error: Inner }

    func health() async -> Bool {
        guard let url = URL(string: baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/health") else { return false }
        guard let (_, response) = try? await URLSession.shared.data(from: url) else { return false }
        return (response as? HTTPURLResponse)?.statusCode == 200
    }

    private func post<T: Decodable>(_ path: String, _ body: [String: Any], token: String? = nil) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status < 400 else {
            if let body = try? JSONDecoder().decode(ErrorBody.self, from: data) {
                throw APIError.server(code: body.error.code, status: status)
            }
            throw APIError.http(status, String(data: data, encoding: .utf8) ?? "")
        }
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
