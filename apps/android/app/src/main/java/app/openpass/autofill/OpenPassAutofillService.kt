package app.openpass.autofill

import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest

/**
 * Password/card AutoFill. Strict matching rules (anti-phishing):
 * - Web: match on registrable domain extracted from AssistStructure web scheme/host; never fill on mismatch.
 * - Apps: match on package + signing certificate hash recorded at save time.
 * Datasets require device credential / biometric auth for cards and passkeys.
 * Implementation lands in Phase 2 with the local encrypted DB.
 */
class OpenPassAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: android.os.CancellationSignal, callback: FillCallback) {
        // TODO Phase 2: parse AssistStructure, find vault matches, return FillResponse with auth-gated datasets.
        callback.onSuccess(null)
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // TODO Phase 2: offer to save new/updated credentials into the vault.
        callback.onSuccess()
    }
}
