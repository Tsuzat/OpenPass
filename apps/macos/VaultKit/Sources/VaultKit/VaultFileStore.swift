import Foundation

/// Persists a VaultSnapshot as JSON in the app's (or App Group's) container.
/// In the Xcode app, place this file in the App Group container so the main app
/// and the credential provider extension share one vault file.
public final class VaultFileStore: @unchecked Sendable {
    public let fileURL: URL
    private let lock = NSLock()

    public init(fileURL: URL) { self.fileURL = fileURL }

    public func load() throws -> VaultSnapshot? {
        lock.lock(); defer { lock.unlock() }
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(VaultSnapshot.self, from: data)
    }

    public func save(_ snapshot: VaultSnapshot) throws {
        lock.lock(); defer { lock.unlock() }
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(snapshot)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    public func delete() throws {
        lock.lock(); defer { lock.unlock() }
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }
}
