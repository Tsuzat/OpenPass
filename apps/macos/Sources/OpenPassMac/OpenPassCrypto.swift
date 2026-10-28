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

    static func generatePasskeyKeypair() -> PasskeyKeyPairFfi { ffiGeneratePasskeyKeypair() }
    static func passkeyCosePublicKey(publicKeySec1: Data) throws -> Data { try ffiPasskeyCosePublicKey(publicKeySec1: publicKeySec1) }
    static func passkeySign(privateKeyPkcs8: Data, data: Data) throws -> Data { try ffiPasskeySign(privateKeyPkcs8: privateKeyPkcs8, data: data) }

    static func encryptFile(vaultKey: Data, data: Data) throws -> Data { try ffiEncryptFile(fileKey: vaultKey, plaintext: data) }
    static func decryptFile(vaultKey: Data, blob: Data) throws -> Data { try ffiDecryptFile(fileKey: vaultKey, blob: blob) }

    static func recoveryAuthProof(recoveryKey: Data) throws -> Data { try ffiRecoveryAuthProof(recoveryKey: recoveryKey) }
    static func generateRecoveryKey() -> RecoveryKey { ffiGenerateRecoveryKey() }
    static func parseRecoveryKey(text: String) throws -> Data { try ffiParseRecoveryKey(text: text) }

    static func totp(secret: Data, at date: Date = Date(), digits: UInt32 = 6) -> String {
        ffiTotpAt(secret: secret, unixSeconds: UInt64(date.timeIntervalSince1970), period: 30, digits: digits, algorithm: .sha1)
    }

    /// TOTP code from a Base32 secret (as stored in totp vault items).
    static func totpCode(secretBase32: String, at date: Date = Date(), digits: UInt32 = 6, sha256: Bool = false) throws -> String {
        let secret = try ffiBase32Decode(text: secretBase32)
        return ffiTotpAt(secret: secret, unixSeconds: UInt64(date.timeIntervalSince1970),
                         period: 30, digits: digits, algorithm: sha256 ? .sha256 : .sha1)
    }
    static func base32Decode(_ text: String) throws -> Data { try ffiBase32Decode(text: text) }
    static func generatePassword(length: UInt32 = 20) -> String { ffiGeneratePassword(length: length) }
}
