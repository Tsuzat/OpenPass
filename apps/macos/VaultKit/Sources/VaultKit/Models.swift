import Foundation

/// Ciphertext item exactly as the server stores it.
///
/// Security rationale for plaintext-at-rest storage of these records: every field
/// that could identify content (name, username, URL, TOTP seed, card number) lives
/// inside `ciphertextB64`, AEAD-encrypted under a per-item key wrapped by the vault
/// key. The local file therefore has the same confidentiality as the server
/// database. The vault key itself is only ever stored wrapped (by KEK, recovery
/// key, or the per-device Secure Enclave key). File-level protections are
/// defense-in-depth: atomic writes, 0600 permissions, complete file protection.
public struct CipherItemRecord: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var type: String
    public var ciphertextB64: String
    public var wrappedItemKeyB64: String
    public var revision: Int
    public var deleted: Bool
    public var updatedAt: String
    /// Local-only: not yet pushed to the server.
    public var dirty: Bool

    public init(id: String, type: String, ciphertextB64: String, wrappedItemKeyB64: String,
                revision: Int, deleted: Bool = false, updatedAt: String, dirty: Bool = false) {
        self.id = id; self.type = type; self.ciphertextB64 = ciphertextB64
        self.wrappedItemKeyB64 = wrappedItemKeyB64; self.revision = revision
        self.deleted = deleted; self.updatedAt = updatedAt; self.dirty = dirty
    }
}

public struct ConflictRecord: Codable, Equatable, Sendable {
    public var itemId: String
    /// The local (losing) ciphertext that collided with a newer server revision.
    public var localItem: CipherItemRecord
    public var serverRevision: Int
}

public struct VaultSnapshot: Codable, Equatable, Sendable {
    public var email: String
    public var wrappedVaultKeyB64: String
    public var recoveryWrappedVaultKeyB64: String
    public var kdfSaltB64: String
    public var kdfParamsJson: String
    public var syncCursor: String?
    public var items: [String: CipherItemRecord]
    public var conflicts: [String: ConflictRecord]

    public init(email: String, wrappedVaultKeyB64: String, recoveryWrappedVaultKeyB64: String,
                kdfSaltB64: String, kdfParamsJson: String) {
        self.email = email; self.wrappedVaultKeyB64 = wrappedVaultKeyB64
        self.recoveryWrappedVaultKeyB64 = recoveryWrappedVaultKeyB64
        self.kdfSaltB64 = kdfSaltB64; self.kdfParamsJson = kdfParamsJson
        self.syncCursor = nil; self.items = [:]; self.conflicts = [:]
    }
}
