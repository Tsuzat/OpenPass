package app.openpass.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillContext
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import app.openpass.ui.MainActivity

/**
 * Password/card AutoFill.
 *
 * Flow: parse the AssistStructure for credential fields and the origin
 * (web domain or app package). The service never holds plaintext while locked:
 * it returns a single authentication dataset that opens MainActivity; after
 * unlock + strict origin matching, the locked dataset is fulfilled.
 *
 * Anti-phishing rules enforced at fill time (Phase 2 repository wiring):
 * - Web: registrable domain must match the saved URI rule; subdomains follow the item's match type.
 * - Apps: package name + signing-cert hash must match what was recorded at save time.
 */
class OpenPassAutofillService : AutofillService() {

    data class CredentialFields(
        val usernameIds: List<AutofillId>,
        val passwordIds: List<AutofillId>,
        val webDomain: String?,
        val packageName: String,
    )

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val context: FillContext = request.fillContexts.lastOrNull() ?: run { callback.onSuccess(null); return }
        val fields = parseStructure(context.structure)
        if (fields.passwordIds.isEmpty() && fields.usernameIds.isEmpty()) { callback.onSuccess(null); return }

        val origin = fields.webDomain ?: fields.packageName
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "OpenPass — unlock to fill ($origin)")
        }
        val unlockIntent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_AUTOFILL_ORIGIN, origin)
            putExtra(EXTRA_AUTOFILL_WEB_DOMAIN, fields.webDomain)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val authIntent = PendingIntent.getActivity(
            this, 0, unlockIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        ).intentSender

        val datasetBuilder = Dataset.Builder(presentation)
            .setAuthentication(authIntent)
        // Placeholder values are replaced only after authenticated unlock in MainActivity.
        fields.usernameIds.forEach { datasetBuilder.setValue(it, AutofillValue.forText(""), presentation) }
        fields.passwordIds.forEach { datasetBuilder.setValue(it, AutofillValue.forText(""), presentation) }

        // Inline presentation (keyboard suggestions) is attached by the IME flow in Phase 2;
        callback.onSuccess(FillResponse.Builder().addDataset(datasetBuilder.build()).build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Save prompts are offered by MainActivity after a successful sign-in
        // (SaveInfo flow lands with the repository wiring in Phase 2).
        callback.onSuccess()
    }

    private fun parseStructure(structure: AssistStructure): CredentialFields {
        val usernames = mutableListOf<AutofillId>()
        val passwords = mutableListOf<AutofillId>()
        var webDomain: String? = null

        fun visit(node: AssistStructure.ViewNode) {
            val hints = node.autofillHints?.toList().orEmpty()
            val id = node.autofillId
            if (id != null) {
                when {
                    hints.contains(ViewHints.USERNAME) || hints.contains(ViewHints.EMAIL) -> usernames.add(id)
                    hints.contains(ViewHints.PASSWORD) || hints.contains(ViewHints.NEW_PASSWORD) -> passwords.add(id)
                }
            }
            if (webDomain == null) node.webDomain?.let { webDomain = it }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)
        return CredentialFields(usernames, passwords, webDomain, structure.activityComponent.packageName)
    }

    private object ViewHints {
        const val USERNAME = "username"
        const val EMAIL = "emailAddress"
        const val PASSWORD = "password"
        const val NEW_PASSWORD = "newPassword"
    }

    companion object {
        const val EXTRA_AUTOFILL_ORIGIN = "app.openpass.AUTOFILL_ORIGIN"
        const val EXTRA_AUTOFILL_WEB_DOMAIN = "app.openpass.AUTOFILL_WEB_DOMAIN"
    }
}
