package app.openpass.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * Vault state + biometric-gated device key.
 * All cryptography delegates to the Rust core (UniFFI AAR, Phase 2) — Kotlin never implements primitives.
 * The Keystore AES key below only WRAPS the VaultKey copy for biometric unlock; it is invalidated
 * when new biometrics are enrolled, forcing master-password fallback by design.
 */
class VaultStore(private val context: Context) {
    @Volatile var isUnlocked: Boolean = false
        private set

    fun biometricKey(alias: String = "openpass_vault_wrap") {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) return
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        gen.generateKey()
    }

    fun unlockWithBiometrics(activity: FragmentActivity, onResult: (Boolean) -> Unit) {
        val can = BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (can != BiometricManager.BIOMETRIC_SUCCESS) { onResult(false); return }
        val prompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // TODO Phase 2: decrypt VaultKey copy with result.cryptoObject cipher, open local DB.
                isUnlocked = true; onResult(true)
            }
            override fun onAuthenticationFailed() { onResult(false) }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock OpenPass")
            .setSubtitle("Use your fingerprint or face")
            .setNegativeButtonText("Use master password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        biometricKey()
        prompt.authenticate(info) // Phase 2: pass CryptoObject wrapping the Keystore cipher
    }

    fun unlockWithMasterPassword(password: String): Boolean {
        // TODO Phase 2: Rust core derive -> fetch wrapped VaultKey -> unwrap -> open local DB.
        if (password.isBlank()) return false
        isUnlocked = true
        return true
    }

    fun lock() { isUnlocked = false /* TODO: zeroize key material via Rust core handle */ }
}
