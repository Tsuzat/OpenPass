package app.openpass.core

import app.openpass.core.ffi.EncryptedItem
import app.openpass.core.ffi.KdfParams
import app.openpass.core.ffi.TotpAlgorithm
import app.openpass.core.ffi.ffiAuthVerifier
import app.openpass.core.ffi.ffiDecryptItem
import app.openpass.core.ffi.ffiDeriveMasterKey
import app.openpass.core.ffi.ffiEncryptItem
import app.openpass.core.ffi.ffiGeneratePassword
import app.openpass.core.ffi.ffiGenerateRecoveryKey
import app.openpass.core.ffi.ffiKeyEncryptionKey
import app.openpass.core.ffi.ffiNewKdfParams
import app.openpass.core.ffi.ffiRandomKey
import app.openpass.core.ffi.ffiTotpAt
import app.openpass.core.ffi.ffiUnwrapKey
import app.openpass.core.ffi.ffiWrapKey

/**
 * Thin wrapper over the UniFFI-generated bindings (core/ffi/openpass_core.kt, JNA).
 * No cryptography is implemented in Kotlin — everything delegates to the Rust core.
 * Requires the core .so packaged via the UniFFI AAR / jniLibs (see scripts/generate-bindings.sh).
 */
object OpenPassCrypto {
    data class AuthMaterial(val authVerifier: ByteArray, val kek: ByteArray, val masterKey: ByteArray)

    fun deriveAuthMaterial(password: String, params: KdfParams): AuthMaterial {
        val master = ffiDeriveMasterKey(password, params)
        return AuthMaterial(ffiAuthVerifier(master, params), ffiKeyEncryptionKey(master, params), master)
    }

    fun newKdfParams(): KdfParams = ffiNewKdfParams()
    fun randomVaultKey(): ByteArray = ffiRandomKey()
    fun wrapKey(wrapper: ByteArray, key: ByteArray): ByteArray = ffiWrapKey(wrapper, key)
    fun unwrapKey(wrapper: ByteArray, blob: ByteArray): ByteArray = ffiUnwrapKey(wrapper, blob)

    fun encryptItem(vaultKey: ByteArray, itemId: String, plaintextJson: ByteArray): EncryptedItem =
        ffiEncryptItem(vaultKey, itemId, plaintextJson)

    fun decryptItem(vaultKey: ByteArray, itemId: String, item: EncryptedItem): ByteArray =
        ffiDecryptItem(vaultKey, itemId, item)

    fun totp(secret: ByteArray, unixSeconds: Long, digits: UInt = 6u): String =
        ffiTotpAt(secret, unixSeconds.toULong(), 30u, digits, TotpAlgorithm.SHA1)

    fun generatePassword(length: UInt = 20u): String = ffiGeneratePassword(length)
    fun generateRecoveryKey() = ffiGenerateRecoveryKey()
}
