import Foundation

public struct HTTPRequest: Sendable {
    public var method: String
    public var path: String
    public var body: Data?
    public var accessToken: String?
    public init(method: String, path: String, body: Data? = nil, accessToken: String? = nil) {
        self.method = method; self.path = path; self.body = body; self.accessToken = accessToken
    }
}

public protocol VaultHTTPClient: Sendable {
    func send(_ request: HTTPRequest) async throws -> (data: Data, status: Int)
}

/// URLSession implementation for the real app.
public struct URLSessionVaultClient: VaultHTTPClient {
    public let baseURL: URL
    public init(baseURL: URL) { self.baseURL = baseURL }
    public func send(_ request: HTTPRequest) async throws -> (data: Data, status: Int) {
        var req = URLRequest(url: baseURL.appendingPathComponent(request.path))
        req.httpMethod = request.method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = request.accessToken { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        req.httpBody = request.body
        let (data, response) = try await URLSession.shared.data(for: req)
        return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
    }
}

public enum SyncError: Error, Equatable { case http(Int), decoding }

private struct ItemsResponse: Decodable {
    struct Item: Decodable {
        let id: String; let type: String; let ciphertextB64: String; let wrappedItemKeyB64: String
        let revision: Int; let deleted: Bool; let updatedAt: String
    }
    let items: [Item]; let cursor: String?
}
private struct ConflictResponse: Decodable {
    struct ErrorBody: Decodable {
        struct ServerItem: Decodable {
            let id: String; let type: String; let ciphertextB64: String; let wrappedItemKeyB64: String
            let revision: Int; let deleted: Bool; let updatedAt: String
        }
        let code: String; let serverItem: ServerItem?
    }
    let error: ErrorBody
}

/// Pull-merge-push sync against the OpenPass API. Server wins on revision
/// conflicts, but the losing local ciphertext is preserved in
/// `snapshot.conflicts` and can be force-pushed (same item id, so the AEAD
/// AAD binding remains valid) or discarded — never silently dropped.
public actor SyncEngine {
    private let store: VaultFileStore
    private let client: VaultHTTPClient
    public private(set) var snapshot: VaultSnapshot

    public init(store: VaultFileStore, client: VaultHTTPClient, snapshot: VaultSnapshot) {
        self.store = store; self.client = client; self.snapshot = snapshot
    }

    public static func load(store: VaultFileStore, client: VaultHTTPClient, fresh: VaultSnapshot) throws -> SyncEngine {
        SyncEngine(store: store, client: client, snapshot: try store.load() ?? fresh)
    }

    public func upsertLocal(_ item: CipherItemRecord) throws {
        var item = item; item.dirty = true
        snapshot.items[item.id] = item
        try store.save(snapshot)
    }

    public func pull(accessToken: String) async throws {
        var path = "/items"
        if let cursor = snapshot.syncCursor { path += "?since=\(cursor.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? cursor)" }
        let (data, status) = try await client.send(HTTPRequest(method: "GET", path: path, accessToken: accessToken))
        guard status == 200 else { throw SyncError.http(status) }
        guard let decoded = try? JSONDecoder().decode(ItemsResponse.self, from: data) else { throw SyncError.decoding }
        for remote in decoded.items {
            if let local = snapshot.items[remote.id], local.dirty { continue } // push/conflict resolution owns dirty rows
            snapshot.items[remote.id] = CipherItemRecord(
                id: remote.id, type: remote.type, ciphertextB64: remote.ciphertextB64,
                wrappedItemKeyB64: remote.wrappedItemKeyB64, revision: remote.revision,
                deleted: remote.deleted, updatedAt: remote.updatedAt, dirty: false)
        }
        if let cursor = decoded.cursor { snapshot.syncCursor = cursor }
        try store.save(snapshot)
    }

    public func push(accessToken: String) async throws {
        // Sorted by id so push order (and conflict handling) is deterministic across runs.
        for item in snapshot.items.values.filter({ $0.dirty }).sorted(by: { $0.id < $1.id }) {
            let body = try JSONSerialization.data(withJSONObject: [
                "type": item.type, "ciphertextB64": item.ciphertextB64,
                "wrappedItemKeyB64": item.wrappedItemKeyB64, "revision": item.revision,
            ])
            let (data, status) = try await client.send(HTTPRequest(method: "PUT", path: "/items/\(item.id)", body: body, accessToken: accessToken))
            if status == 200 {
                snapshot.items[item.id]?.dirty = false
            } else if status == 409, let conflict = try? JSONDecoder().decode(ConflictResponse.self, from: data),
                      let server = conflict.error.serverItem {
                snapshot.conflicts[item.id] = ConflictRecord(itemId: item.id, localItem: item, serverRevision: server.revision)
                snapshot.items[item.id] = CipherItemRecord(
                    id: server.id, type: server.type, ciphertextB64: server.ciphertextB64,
                    wrappedItemKeyB64: server.wrappedItemKeyB64, revision: server.revision,
                    deleted: server.deleted, updatedAt: server.updatedAt, dirty: false)
            } else {
                throw SyncError.http(status)
            }
        }
        try store.save(snapshot)
    }

    public func sync(accessToken: String) async throws {
        try await push(accessToken: accessToken)
        try await pull(accessToken: accessToken)
    }

    /// Force the conflicted local ciphertext back as the next server revision.
    public func resolveConflictKeepMine(itemId: String, accessToken: String) async throws {
        guard let conflict = snapshot.conflicts[itemId], var local = Optional(conflict.localItem) else { return }
        local.revision = conflict.serverRevision + 1
        local.dirty = true
        snapshot.items[itemId] = local
        snapshot.conflicts[itemId] = nil
        try store.save(snapshot)
        try await push(accessToken: accessToken)
    }

    public func resolveConflictKeepServer(itemId: String) throws {
        snapshot.conflicts[itemId] = nil
        try store.save(snapshot)
    }
}
