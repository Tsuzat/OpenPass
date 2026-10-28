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

/**
 * Synced passkey + password provider via Credential Manager (Android 14+).
 * Signatures verified against androidx.credentials 1.5.0 (provider classes ship
 * inside the `credentials` artifact — there is no credentials-provider artifact).
 *
 * Private keys live encrypted in the vault; assertions are produced locally
 * after biometric user verification in PasskeyAssertionActivity.
 * When the vault is locked, return no entries rather than leaking which sites
 * the user has credentials for.
 */
class OpenPassCredentialProviderService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        // Phase 4: enumerate unlocked vault passkeys filtered by rpId from
        // BeginGetPublicKeyCredentialOption.requestJson (allowCredentials + rpId),
        // adding one PublicKeyCredentialEntry per match with a PendingIntent to
        // PasskeyAssertionActivity.
        callback.onResult(BeginGetCredentialResponse())
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        // Phase 4: create passkey (Rust core keypair), store encrypted private key
        // as a vault item, return a create entry pointing at the registration UI.
        callback.onResult(BeginCreateCredentialResponse())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // No server-side session to clear (zero-knowledge); local lock is user-driven.
        callback.onResult(null)
    }
}
