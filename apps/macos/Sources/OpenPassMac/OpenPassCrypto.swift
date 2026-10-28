import Foundation

/// Thin wrapper over the UniFFI-generated bindings (Sources/OpenPassCoreFFI/openpass_core.swift).
/// The Xcode app target must include the OpenPassCoreFFI sources + link libopenpass_core (XCFramework).
/// No cryptography is implemented in Swift — everything delegates to the Rust core.
enum OpenPassCrypto {
    struct AuthMaterial { let authVerifier: Data; let kek: Data; let masterKey: Data }

    static func deriveAuthMaterial(password: String, params: KdfParams) throws -> AuthMaterial {
        let master = try ffiDeriveMasterKey(password: password, params: params)
        return AuthMaterial(
            authVerifier: try ffiAuthVerifier(masterKey: master, params: params),
            kek: try ffiKeyEncryptionKey(masterKey: master, params: params),
            masterKey: master
        )
    }

    static func newKdfParams() throws -> KdfParams { try ffiNewKdfParams() }
    static func randomVaultKey() -> Data { ffiRandomKey() }
    static func wrapKey(wrapper: Data, key: Data) throws -> Data { try ffiWrapKey(wrapper: wrapper, key: key) }
    static func unwrapKey(wrapper: Data, blob: Data) throws -> Data { try ffiUnwrapKey(wrapper: wrapper, blob: blob) }

    static func encryptItem(vaultKey: Data, itemId: String, plaintextJSON: Data) throws -> EncryptedItem {
        try ffiEncryptItem(vaultKey: vaultKey, itemId: itemId, plaintext: plaintextJSON)
    }
    static func decryptItem(vaultKey: Data, itemId: String, item: EncryptedItem) throws -> Data {
        try ffiDecryptItem(vaultKey: vaultKey, itemId: itemId, item: item)
    }

    static func recoveryAuthProof(recoveryKey: Data) throws -> Data { try ffiRecoveryAuthProof(recoveryKey: recoveryKey) }
    static func generateRecoveryKey() -> RecoveryKey { ffiGenerateRecoveryKey() }
    static func parseRecoveryKey(text: String) throws -> Data { try ffiParseRecoveryKey(text: text) }

    static func totp(secret: Data, at date: Date = Date(), digits: UInt32 = 6) -> String {
        ffiTotpAt(secret: secret, unixSeconds: UInt64(date.timeIntervalSince1970), period: 30, digits: digits, algorithm: .sha1)
    }
    static func generatePassword(length: UInt32 = 20) -> String { ffiGeneratePassword(length: length) }
}
