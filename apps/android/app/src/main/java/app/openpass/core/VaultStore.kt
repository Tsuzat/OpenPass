package app.openpass.core

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.io.File

/**
 * Vault session state. All cryptography delegates to the Rust core via
 * OpenPassCrypto (UniFFI) — Kotlin never implements primitives.
 * Local persistence (ciphertext only) is handled by VaultFileStore + SyncEngine.
 */
class VaultStore(context: Context) {
    @Volatile var isUnlocked: Boolean = false
        private set

    private var vaultKey: ByteArray? = null
    @Volatile var accessToken: String? = null
    val biometricStore = BiometricVaultKeyStore(context.applicationContext)
    val fileStore = VaultFileStore(File(context.applicationContext.filesDir, "vault.json"))

    /** The vault key is memory-only; lock() zeroizes our copy. Callers must not retain it. */
    fun currentVaultKey(): ByteArray? = vaultKey

    fun unlockWithBiometrics(activity: FragmentActivity, onResult: (Boolean) -> Unit) {
        val can = BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (can != BiometricManager.BIOMETRIC_SUCCESS || !biometricStore.hasArmedKey()) { onResult(false); return }
        val prompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val cipher = result.cryptoObject?.cipher
                if (cipher == null) { onResult(false); return }
                runCatching { biometricStore.decryptVaultKey(cipher) }
                    .onSuccess { key -> vaultKey = key; isUnlocked = true; onResult(true) }
                    .onFailure { onResult(false) }
            }
            override fun onAuthenticationFailed() { onResult(false) }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { onResult(false) }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock OpenPass")
            .setSubtitle("Use your fingerprint or face")
            .setNegativeButtonText("Use master password")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, biometricStore.cryptoObjectForUnlock())
    }

    /**
     * Master-password unlock. [deriveAndUnwrap] is supplied by the auth layer:
     * it derives KEK via OpenPassCrypto, unwraps the vault key, and returns it.
     * On success the biometric store is (re)armed for next time.
     */
    fun unlockWithMasterKey(deriveAndUnwrap: () -> ByteArray?): Boolean {
        val key = runCatching { deriveAndUnwrap() }.getOrNull() ?: return false
        vaultKey = key
        isUnlocked = true
        runCatching { biometricStore.armBiometricUnlock(key) }
        return true
    }

    fun unlockWithMasterPassword(password: String): Boolean {
        // Convenience for the current UI; real wiring passes a deriveAndUnwrap
        // closure that fetches KDF params + wrapped key from the API/local snapshot.
        if (password.isBlank()) return false
        return unlockWithMasterKey { null }
    }

    fun lock() {
        vaultKey?.fill(0)
        vaultKey = null
        isUnlocked = false
    }
}
