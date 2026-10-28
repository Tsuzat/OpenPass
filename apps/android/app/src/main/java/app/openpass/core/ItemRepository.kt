package app.openpass.core

import android.util.Base64
import app.openpass.core.ffi.EncryptedItem
import org.json.JSONObject

data class VaultItemSummary(val id: String, val type: String, val name: String, val username: String, val plaintext: JSONObject)

/**
 * Fetches ciphertext items and decrypts summaries in memory via the Rust core.
 * Full plaintext is decrypted on demand in the detail screen, never persisted.
 * Blocking — call off the main thread.
 */
class ItemRepository(private val http: VaultHttpClient) {
    fun listSummaries(accessToken: String, vaultKey: ByteArray): List<VaultItemSummary> {
        val (status, body) = http.send("GET", "/items", null, accessToken)
        check(status == 200) { "items fetch failed: $status" }
        val items = JSONObject(body).getJSONArray("items")
        val out = mutableListOf<VaultItemSummary>()
        for (i in 0 until items.length()) {
            val dto = items.getJSONObject(i)
            if (dto.optBoolean("deleted")) continue
            val plainBytes = runCatching {
                OpenPassCrypto.decryptItem(
                    vaultKey, dto.getString("id"),
                    EncryptedItem(dto.getString("ciphertextB64"), dto.getString("wrappedItemKeyB64")),
                )
            }.getOrNull() ?: continue
            val plain = JSONObject(String(plainBytes, Charsets.UTF_8))
            if (plain.has("system")) continue // folder/settings system items are not vault entries
            out += VaultItemSummary(
                id = dto.getString("id"),
                type = dto.getString("type"),
                name = plain.optString("name", "(unnamed)"),
                username = plain.optString("username"),
                plaintext = plain,
            )
        }
        return out.sortedBy { it.name.lowercase() }
    }

    companion object {
        fun b64Decode(text: String): ByteArray = Base64.decode(text, Base64.NO_WRAP)
    }
}
