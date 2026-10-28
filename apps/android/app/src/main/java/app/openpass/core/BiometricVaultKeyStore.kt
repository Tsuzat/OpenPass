package app.openpass.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Per-device biometric wrapping of the vault key.
 * A non-exportable Android Keystore AES key (invalidated when new biometrics are
 * enrolled) encrypts the vault key; the resulting blob (IV + ciphertext) is kept
 * in app-private storage. Decryption requires a fresh BiometricPrompt
 * authentication via BiometricPrompt.CryptoObject.
 */
class BiometricVaultKeyStore(context: Context) {
    private val prefs = context.getSharedPreferences("openpass-device", Context.MODE_PRIVATE)

    companion object {
        private const val ALIAS = "openpass_vault_wrap"
        private const val PREF_BLOB = "wrapped_vault_key_b64"
    }

    private fun keyStoreKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return gen.generateKey()
    }

    /** Call after a successful master-password unlock to arm biometric unlock. */
    fun armBiometricUnlock(vaultKey: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keyStoreKey())
        val blob = cipher.iv + cipher.doFinal(vaultKey)
        prefs.edit().putString(PREF_BLOB, android.util.Base64.encodeToString(blob, android.util.Base64.NO_WRAP)).apply()
    }

    fun hasArmedKey(): Boolean = prefs.contains(PREF_BLOB)

    /** Cipher to hand to BiometricPrompt as a CryptoObject for unlocking. */
    fun unlockCipher(): Cipher {
        val blob = android.util.Base64.decode(prefs.getString(PREF_BLOB, "")!!, android.util.Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keyStoreKey(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        return cipher
    }

    /** After BiometricPrompt success, decrypt with the authenticated cipher from the result. */
    fun decryptVaultKey(authenticatedCipher: Cipher): ByteArray {
        val blob = android.util.Base64.decode(prefs.getString(PREF_BLOB, "")!!, android.util.Base64.NO_WRAP)
        return authenticatedCipher.doFinal(blob.copyOfRange(12, blob.size))
    }

    fun cryptoObjectForUnlock(): BiometricPrompt.CryptoObject = BiometricPrompt.CryptoObject(unlockCipher())

    fun disarm() { prefs.edit().remove(PREF_BLOB).apply() }
}
