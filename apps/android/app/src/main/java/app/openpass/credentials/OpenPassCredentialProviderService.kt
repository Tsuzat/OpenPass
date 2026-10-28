package app.openpass.credentials

import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.ProviderGetCredentialRequest

/**
 * Synced passkey + password provider via Credential Manager (Android 14+).
 * Based on the Jetpack androidx.credentials.provider.CredentialProviderService.
 * Private keys live encrypted in the vault; assertions are produced locally after
 * biometric user verification. Phase 4, protocol spike in Phase 0.
 * NOTE: scaffold — validate exact provider API signatures against the pinned
 * androidx.credentials version when the Android SDK toolchain is set up.
 */
class OpenPassCredentialProviderService : CredentialProviderService() {
    override fun onBeginGetCredential(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // For each vault passkey matching the requested rpId, a real implementation
        // adds a PublicKeyCredentialEntry whose PendingIntent opens
        // PasskeyAssertionActivity (biometric UV + signing happen there).
        // Matching requires the decrypted vault index; when locked, return no
        // entries rather than leaking which sites the user has passkeys for.
        // TODO Phase 4: enumerate unlocked vault passkeys filtered by rpId from
        // BeginGetPublicKeyCredentialOption.requestJson (allowCredentials + rpId).
        callback.onResult(BeginGetCredentialResponse())
    }

    override fun onGetCredential(
        request: ProviderGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<androidx.credentials.GetCredentialResponse, GetCredentialException>,
    ) {
        // TODO Phase 4: biometric UV -> decrypt passkey private key (Rust core) -> sign assertion.
        callback.onError(GetCredentialException("Not implemented yet (Phase 4)"))
    }

    override fun onBeginCreateCredential(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        // TODO Phase 4: create passkey, store encrypted private key as a vault item.
        callback.onResult(BeginCreateCredentialResponse())
    }

    override fun onClearCredentialState(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }
}
