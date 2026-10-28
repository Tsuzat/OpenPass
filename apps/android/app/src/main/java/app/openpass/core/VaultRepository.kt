package app.openpass.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Local vault storage + sync, mirroring the Swift VaultKit design.
 * The file stores ONLY ciphertext records and wrapped keys (same confidentiality
 * as the server database). Plaintext exists in memory after unlock only.
 * All functions are blocking — call from an IO dispatcher/thread.
 */

data class CipherItemRecord(
    val id: String, val type: String, val ciphertextB64: String, val wrappedItemKeyB64: String,
    val revision: Int, val deleted: Boolean = false, val updatedAt: String, val dirty: Boolean = false,
) {
    fun toJson() = JSONObject()
        .put("id", id).put("type", type).put("ciphertextB64", ciphertextB64)
        .put("wrappedItemKeyB64", wrappedItemKeyB64).put("revision", revision)
        .put("deleted", deleted).put("updatedAt", updatedAt).put("dirty", dirty)

    companion object {
        fun fromJson(j: JSONObject) = CipherItemRecord(
            j.getString("id"), j.getString("type"), j.getString("ciphertextB64"),
            j.getString("wrappedItemKeyB64"), j.getInt("revision"),
            j.optBoolean("deleted"), j.optString("updatedAt"), j.optBoolean("dirty"),
        )
    }
}

data class ConflictRecord(val itemId: String, val localItem: CipherItemRecord, val serverRevision: Int)

class VaultSnapshot(
    val email: String, val wrappedVaultKeyB64: String, val recoveryWrappedVaultKeyB64: String,
    val kdfSaltB64: String, val kdfParamsJson: String,
    var syncCursor: String? = null,
    val items: MutableMap<String, CipherItemRecord> = mutableMapOf(),
    val conflicts: MutableMap<String, ConflictRecord> = mutableMapOf(),
) {
    fun toJson(): JSONObject {
        val itemsArr = JSONArray().apply { items.values.forEach { put(it.toJson().put("dirty", it.dirty)) } }
        val confObj = JSONObject().apply {
            conflicts.forEach { (k, v) -> put(k, JSONObject().put("localItem", v.localItem.toJson()).put("serverRevision", v.serverRevision)) }
        }
        return JSONObject()
            .put("email", email).put("wrappedVaultKeyB64", wrappedVaultKeyB64)
            .put("recoveryWrappedVaultKeyB64", recoveryWrappedVaultKeyB64)
            .put("kdfSaltB64", kdfSaltB64).put("kdfParamsJson", kdfParamsJson)
            .put("syncCursor", syncCursor ?: JSONObject.NULL).put("items", itemsArr).put("conflicts", confObj)
    }

    companion object {
        fun fromJson(j: JSONObject): VaultSnapshot {
            val snap = VaultSnapshot(
                j.getString("email"), j.getString("wrappedVaultKeyB64"), j.getString("recoveryWrappedVaultKeyB64"),
                j.getString("kdfSaltB64"), j.getString("kdfParamsJson"),
                if (j.isNull("syncCursor")) null else j.getString("syncCursor"),
            )
            val arr = j.optJSONArray("items") ?: JSONArray()
            for (i in 0 until arr.length()) { val item = CipherItemRecord.fromJson(arr.getJSONObject(i)); snap.items[item.id] = item }
            val conf = j.optJSONObject("conflicts") ?: JSONObject()
            conf.keys().forEach { k ->
                val c = conf.getJSONObject(k)
                snap.conflicts[k] = ConflictRecord(k, CipherItemRecord.fromJson(c.getJSONObject("localItem")), c.getInt("serverRevision"))
            }
            return snap
        }
    }
}

/** Atomic JSON file store in app-private storage. */
class VaultFileStore(private val file: File) {
    @Synchronized
    fun load(): VaultSnapshot? = if (file.exists()) VaultSnapshot.fromJson(JSONObject(file.readText())) else null

    @Synchronized
    fun save(snapshot: VaultSnapshot) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(snapshot.toJson().toString())
        tmp.setReadable(true, true); tmp.setWritable(true, true)
        check(tmp.renameTo(file)) { "atomic rename failed" }
    }

    @Synchronized
    fun delete() { if (file.exists()) file.delete() }
}

interface VaultHttpClient {
    /** Returns (status, body). Blocking. */
    fun send(method: String, path: String, body: String?, accessToken: String?): Pair<Int, String>
}

class UrlConnectionVaultClient(private val baseUrl: String) : VaultHttpClient {
    override fun send(method: String, path: String, body: String?, accessToken: String?): Pair<Int, String> {
        val conn = java.net.URL(baseUrl.trimEnd('/') + path).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = method
        conn.setRequestProperty("Content-Type", "application/json")
        if (accessToken != null) conn.setRequestProperty("Authorization", "Bearer $accessToken")
        if (body != null) {
            conn.doOutput = true
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val status = conn.responseCode
        val stream = if (status in 200..299) conn.inputStream else conn.errorStream
        return status to (stream?.bufferedReader()?.readText() ?: "")
    }
}

/**
 * Pull-merge-push sync. Server wins conflicts; the losing local ciphertext is
 * preserved and can be force-pushed at the next revision (same item id keeps
 * the AEAD AAD binding valid) or discarded. Blocking — call off the main thread.
 */
class SyncEngine(private val store: VaultFileStore, private val client: VaultHttpClient, var snapshot: VaultSnapshot) {
    fun upsertLocal(item: CipherItemRecord) {
        snapshot.items[item.id] = item.copy(dirty = true)
        store.save(snapshot)
    }

    fun pull(accessToken: String) {
        val path = "/items" + (snapshot.syncCursor?.let { "?since=" + java.net.URLEncoder.encode(it, "UTF-8") } ?: "")
        val (status, body) = client.send("GET", path, null, accessToken)
        check(status == 200) { "pull failed: $status" }
        val root = JSONObject(body)
        val arr = root.getJSONArray("items")
        for (i in 0 until arr.length()) {
            val remote = CipherItemRecord.fromJson(arr.getJSONObject(i))
            if (snapshot.items[remote.id]?.dirty == true) continue
            snapshot.items[remote.id] = remote.copy(dirty = false)
        }
        if (!root.isNull("cursor")) snapshot.syncCursor = root.getString("cursor")
        store.save(snapshot)
    }

    fun push(accessToken: String) {
        // Sorted by id so push order (and conflict handling) is deterministic.
        for (item in snapshot.items.values.filter { it.dirty }.sortedBy { it.id }) {
            val body = JSONObject()
                .put("type", item.type).put("ciphertextB64", item.ciphertextB64)
                .put("wrappedItemKeyB64", item.wrappedItemKeyB64).put("revision", item.revision).toString()
            val (status, resp) = client.send("PUT", "/items/${item.id}", body, accessToken)
            when {
                status == 200 -> snapshot.items[item.id] = item.copy(dirty = false)
                status == 409 -> {
                    val server = JSONObject(resp).getJSONObject("error").getJSONObject("serverItem")
                    val serverItem = CipherItemRecord.fromJson(server)
                    snapshot.conflicts[item.id] = ConflictRecord(item.id, item, serverItem.revision)
                    snapshot.items[item.id] = serverItem.copy(dirty = false)
                }
                else -> error("push failed: $status")
            }
        }
        store.save(snapshot)
    }

    fun sync(accessToken: String) { push(accessToken); pull(accessToken) }

    fun resolveConflictKeepMine(itemId: String, accessToken: String) {
        val conflict = snapshot.conflicts[itemId] ?: return
        snapshot.items[itemId] = conflict.localItem.copy(revision = conflict.serverRevision + 1, dirty = true)
        snapshot.conflicts.remove(itemId)
        store.save(snapshot)
        push(accessToken)
    }

    fun resolveConflictKeepServer(itemId: String) {
        snapshot.conflicts.remove(itemId)
        store.save(snapshot)
    }
}
