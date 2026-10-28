import Foundation
import VaultKit

// Executable mirror of Tests/VaultKitTests for environments without XCTest
// (e.g. Command Line Tools only). Exits non-zero on the first failure.
func check(_ cond: Bool, _ name: String) {
    print("\(cond ? "PASS" : "FAIL"): \(name)")
    if !cond { exit(1) }
}

final class MockClient: VaultHTTPClient, @unchecked Sendable {
    var responses: [(Int, String)] = []
    var count = 0
    func send(_ request: HTTPRequest) async throws -> (data: Data, status: Int) {
        defer { count += 1 }
        let r = responses[count]
        return (Data(r.1.utf8), r.0)
    }
}

let tmp = FileManager.default.temporaryDirectory
    .appendingPathComponent("openpass-checks-\(UUID().uuidString)", isDirectory: true)
    .appendingPathComponent("vault.json")
let store = VaultFileStore(fileURL: tmp)
let fresh = VaultSnapshot(email: "a@b.com", wrappedVaultKeyB64: "w==", recoveryWrappedVaultKeyB64: "r==",
                          kdfSaltB64: "c2FsdA==", kdfParamsJson: "{}")
try store.save(fresh)
check(try store.load() == fresh, "file store roundtrip")
let perms = try FileManager.default.attributesOfItem(atPath: tmp.path)[.posixPermissions] as? Int
check(perms == 0o600, "file permissions 0600")

func item(_ id: String, _ rev: Int) -> CipherItemRecord {
    CipherItemRecord(id: id, type: "login", ciphertextB64: "Y3Q=", wrappedItemKeyB64: "a2V5",
                     revision: rev, updatedAt: "2026-01-01T00:00:00Z")
}

let mock = MockClient()
mock.responses = [(200, """
{"items":[{"id":"i1","type":"login","ciphertextB64":"Y3Q=","wrappedItemKeyB64":"a2V5","revision":1,"deleted":false,"updatedAt":"2026-01-01T00:00:00Z"}],"cursor":"2026-01-01T00:00:00Z"}
""")]
let engine = SyncEngine(store: store, client: mock, snapshot: fresh)
try await engine.pull(accessToken: "t")
var snap = await engine.snapshot
check(snap.items["i1"]?.revision == 1 && snap.syncCursor != nil, "pull merges + cursor")

let mock2 = MockClient()
mock2.responses = [
    (200, "{}"),
    (409, "{\"error\":{\"code\":\"REVISION_CONFLICT\",\"serverItem\":{\"id\":\"i2\",\"type\":\"login\",\"ciphertextB64\":\"c2VydmVy\",\"wrappedItemKeyB64\":\"a2V5\",\"revision\":5,\"deleted\":false,\"updatedAt\":\"2026-01-02T00:00:00Z\"}}}"),
    (200, "{}"),
]
let engine2 = SyncEngine(store: store, client: mock2, snapshot: try store.load()!)
try await engine2.upsertLocal(item("i1", 2))
try await engine2.upsertLocal(item("i2", 2))
try await engine2.push(accessToken: "t")
snap = await engine2.snapshot
check(snap.items["i1"]?.dirty == false, "push clears dirty")
check(snap.items["i2"]?.revision == 5 && snap.conflicts["i2"]?.serverRevision == 5, "conflict preserved")
try await engine2.resolveConflictKeepMine(itemId: "i2", accessToken: "t")
snap = await engine2.snapshot
check(snap.conflicts["i2"] == nil && snap.items["i2"]?.revision == 6 && snap.items["i2"]?.dirty == false, "keep-mine resolves at revision 6")

let bio = InMemoryBiometricKeyStore()
try bio.saveWrappedVaultKey(Data([1, 2, 3]))
check(try bio.loadWrappedVaultKey() == Data([1, 2, 3]), "biometric store roundtrip")

// WebAuthn authenticator data
let authData = WebAuthn.assertionAuthenticatorData(rpId: "github.com", flags: .syncedAssertion, signCount: 7)
check(authData.count == 37, "assertion authData is 37 bytes")
check(authData[32] == 0x1D, "assertion flags UP|UV|BE|BS = 0x1D")
check(authData[36] == 7, "signCount big-endian")
let regData = WebAuthn.registrationAuthenticatorData(rpId: "github.com", flags: .syncedAssertion, signCount: 0,
                                                     credentialId: Data([0xAA, 0xBB]), cosePublicKey: Data([0xA5]))
check(regData.count == 37 + 16 + 2 + 2 + 1 && regData[32] == 0x5D, "registration authData has AT flag + attested data")
check(WebAuthn.rpIdMatches(requestRpId: "github.com", storedRpId: "github.com"), "rpId exact match")
check(!WebAuthn.rpIdMatches(requestRpId: "github.com.evil.com", storedRpId: "github.com"), "rpId mismatch rejected")

print("All VaultKit checks passed")
