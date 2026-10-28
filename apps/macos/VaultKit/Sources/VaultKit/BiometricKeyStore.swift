import Foundation
import LocalAuthentication
import Security

/// Stores the per-device, biometric-wrapped copy of the vault key.
/// The wrap itself is produced by the Rust core (vault key sealed to a
/// Secure Enclave key); this type only persists the resulting blob behind
/// a biometry-gated Keychain access control.
public protocol BiometricKeyStore: Sendable {
    func saveWrappedVaultKey(_ data: Data) throws
    func loadWrappedVaultKey() throws -> Data?
    func deleteWrappedVaultKey() throws
}

public enum BiometricKeyStoreError: Error { case keychain(OSStatus), accessControlUnavailable }

public final class KeychainBiometricKeyStore: BiometricKeyStore, @unchecked Sendable {
    public let service: String
    public let account: String
    public init(service: String = "app.openpass.vault", account: String = "wrapped-vault-key") {
        self.service = service; self.account = account
    }

    private func baseQuery() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func saveWrappedVaultKey(_ data: Data) throws {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &accessError)
        else { throw BiometricKeyStoreError.accessControlUnavailable }

        try deleteWrappedVaultKeySilently()
        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessControl as String] = access
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw BiometricKeyStoreError.keychain(status) }
    }

    public func loadWrappedVaultKey() throws -> Data? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Biometric prompt is driven by the Keychain access control on read.
        query[kSecUseAuthenticationContext as String] = LAContext()
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw BiometricKeyStoreError.keychain(status) }
        return item as? Data
    }

    public func deleteWrappedVaultKey() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BiometricKeyStoreError.keychain(status)
        }
    }

    private func deleteWrappedVaultKeySilently() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BiometricKeyStoreError.keychain(status)
        }
    }
}

/// In-memory implementation for tests and previews.
public final class InMemoryBiometricKeyStore: BiometricKeyStore, @unchecked Sendable {
    private var data: Data?
    private let lock = NSLock()
    public init() {}
    public func saveWrappedVaultKey(_ data: Data) throws { lock.lock(); defer { lock.unlock() }; self.data = data }
    public func loadWrappedVaultKey() throws -> Data? { lock.lock(); defer { lock.unlock() }; return data }
    public func deleteWrappedVaultKey() throws { lock.lock(); defer { lock.unlock() }; data = nil }
}
