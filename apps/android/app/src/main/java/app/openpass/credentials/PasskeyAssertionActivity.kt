package app.openpass.credentials

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import org.json.JSONObject

/**
 * Handles a passkey assertion after the user selects an OpenPass credential entry.
 * Flow: extract ProviderGetCredentialRequest -> biometric UV -> load passkey item ->
 * validate rpId -> sign authenticatorData||clientDataHash in the Rust core -> respond.
 *
 * The vault-loading step requires the unlocked VaultStore/session from the main app
 * process; when locked, this activity must first route through the unlock screen.
 */
class PasskeyAssertionActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.firstOrNull()

        // TODO (requires Android SDK validation):
        // 1. Parse option.requestJson: { rpId, challenge, allowCredentials }
        // 2. BiometricPrompt (BIOMETRIC_STRONG) for user verification
        // 3. Load matching passkey item from the vault; WebAuthn.rpIdMatches check
        // 4. clientDataHash = SHA-256 of the request's clientDataJSON (supplied by the framework flow)
        // 5. authData = WebAuthn.assertionAuthenticatorData(rpId, counter + 1)
        //    signature = OpenPassCrypto.passkeySign(privateKeyPkcs8, authData || clientDataHash)
        // 6. Build response JSON and return it (shape below), increment + sync the item counter.
        if (option == null) { finish(); return }

        val responseJson = JSONObject()
            .put("id", "<credentialIdB64Url>")
            .put("rawId", "<credentialIdB64Url>")
            .put("type", "public-key")
            .put("response", JSONObject()
                .put("authenticatorData", "<authDataB64Url>")
                .put("clientDataJSON", "<clientDataJSONB64Url>")
                .put("signature", "<signatureB64Url>")
                .put("userHandle", "<userHandleB64Url>"))
            .put("authenticatorAttachment", "platform")
            .put("clientExtensionResults", JSONObject())

        val resultIntent = android.content.Intent()
        PendingIntentHandler.setGetCredentialResponse(
            resultIntent,
            GetCredentialResponse(PublicKeyCredential(responseJson.toString())),
        )
        setResult(RESULT_OK, resultIntent)
        finish()
    }
}
