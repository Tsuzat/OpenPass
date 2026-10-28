import XCTest
@testable import VaultKit

final class MockClient: VaultHTTPClient, @unchecked Sendable {
    var responses: [(path: String, status: Int, body: String)] = []
    var sent: [HTTPRequest] = []
    func send(_ request: HTTPRequest) async throws -> (data: Data, status: Int) {
        sent.append(request)
        let idx = sent.count - 1
        guard idx < responses.count else { return (Data(), 500) }
        let r = responses[idx]
        return (Data(r.body.utf8), r.status)
    }
}

final class VaultKitTests: XCTestCase {
    private func tempStore() -> VaultFileStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("openpass-test-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("vault.json")
        return VaultFileStore(fileURL: url)
    }
    private func snapshot() -> VaultSnapshot {
        VaultSnapshot(email: "a@b.com", wrappedVaultKeyB64: "w==", recoveryWrappedVaultKeyB64: "r==",
                      kdfSaltB64: "c2FsdA==", kdfParamsJson: "{}")
    }
    private func item(_ id: String, revision: Int, dirty: Bool = false) -> CipherItemRecord {
        CipherItemRecord(id: id, type: "login", ciphertextB64: "Y3Q=", wrappedItemKeyB64: "a2V5",
                         revision: revision, updatedAt: "2026-01-01T00:00:00Z", dirty: dirty)
    }

    func testFileStoreRoundtripAndPermissions() throws {
        let store = tempStore()
        let snap = snapshot()
        try store.save(snap)
        XCTAssertEqual(try store.load(), snap)
        let perms = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testPullMergesAndAdvancesCursor() async throws {
        let store = tempStore()
        let mock = MockClient()
        mock.responses = [("/items", 200, """
        {"items":[{"id":"i1","type":"login","ciphertextB64":"Y3Q=","wrappedItemKeyB64":"a2V5","revision":1,"deleted":false,"updatedAt":"2026-01-01T00:00:00Z"}],"cursor":"2026-01-01T00:00:00Z"}
        """)]
        let engine = SyncEngine(store: store, client: mock, snapshot: snapshot())
        try await engine.pull(accessToken: "t")
        var snap = await engine.snapshot
        XCTAssertEqual(snap.items["i1"]?.revision, 1)
        XCTAssertEqual(snap.syncCursor, "2026-01-01T00:00:00Z")

        // second engine over same file sees persisted data
        let engine2 = try SyncEngine.load(store: store, client: mock, fresh: snapshot())
        snap = await engine2.snapshot
        XCTAssertEqual(snap.items.count, 1)
    }

    func testPushClearsDirtyAndConflictPreservesLocal() async throws {
        let store = tempStore()
        let mock = MockClient()
        // PUT i1 -> ok; PUT i2 -> 409 with server item
        mock.responses = [
            ("/items/i1", 200, "{}"),
            ("/items/i2", 409, """
            {"error":{"code":"REVISION_CONFLICT","serverItem":{"id":"i2","type":"login","ciphertextB64":"c2VydmVy","wrappedItemKeyB64":"a2V5","revision":5,"deleted":false,"updatedAt":"2026-01-02T00:00:00Z"}}}
            """),
            ("/items/i2", 200, "{}"), // resolveConflictKeepMine re-push
        ]
        let engine = SyncEngine(store: store, client: mock, snapshot: snapshot())
        try await engine.upsertLocal(item("i1", revision: 1))
        try await engine.upsertLocal(item("i2", revision: 2))
        try await engine.push(accessToken: "t")

        var snap = await engine.snapshot
        XCTAssertEqual(snap.items["i1"]?.dirty, false)
        XCTAssertEqual(snap.items["i2"]?.revision, 5) // server version adopted
        XCTAssertEqual(snap.conflicts["i2"]?.localItem.revision, 2) // local preserved
        XCTAssertEqual(snap.conflicts["i2"]?.serverRevision, 5)

        try await engine.resolveConflictKeepMine(itemId: "i2", accessToken: "t")
        snap = await engine.snapshot
        XCTAssertNil(snap.conflicts["i2"])
        XCTAssertEqual(snap.items["i2"]?.revision, 6)
        XCTAssertEqual(snap.items["i2"]?.dirty, false)
    }

    func testBiometricStoreInMemory() throws {
        let store = InMemoryBiometricKeyStore()
        XCTAssertNil(try store.loadWrappedVaultKey())
        try store.saveWrappedVaultKey(Data([1, 2, 3]))
        XCTAssertEqual(try store.loadWrappedVaultKey(), Data([1, 2, 3]))
        try store.deleteWrappedVaultKey()
        XCTAssertNil(try store.loadWrappedVaultKey())
    }
}
