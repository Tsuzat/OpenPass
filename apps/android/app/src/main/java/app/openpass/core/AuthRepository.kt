package app.openpass.core

import android.util.Base64
import app.openpass.core.ffi.KdfParams
import org.json.JSONObject
import java.util.UUID

class DeviceApprovalRequired : Exception("New device must be approved from an existing device")
class InvalidCredentials : Exception("Invalid email or master password")

/**
 * Auth flows against the OpenPass API. All key derivation/unwrapping runs in the
 * Rust core via OpenPassCrypto; this class only moves base64 blobs over HTTPS.
 * Blocking — call off the main thread.
 */
class AuthRepository(private val http: VaultHttpClient, private val deviceId: () -> String) {

    data class Session(val accessToken: String, val refreshToken: String, val vaultKey: ByteArray, val vaultId: String)

    private fun b64(data: ByteArray) = Base64.encodeToString(data, Base64.NO_WRAP)
    private fun unb64(text: String) = Base64.decode(text, Base64.NO_WRAP)

    private fun paramsFromPrelogin(pre: JSONObject): KdfParams {
        val p = pre.getJSONObject("kdfParams")
        return KdfParams(
            memoryKib = p.getInt("memoryKib").toUInt(),
            iterations = p.getInt("iterations").toUInt(),
            parallelism = p.getInt("parallelism").toUInt(),
            saltB64 = pre.getString("kdfSaltB64"),
        )
    }

    fun login(email: String, password: String, deviceName: String): Session {
        val (preStatus, preBody) = http.send("POST", "/auth/prelogin", JSONObject().put("email", email).toString(), null)
        check(preStatus == 200) { "prelogin failed: $preStatus" }
        val params = paramsFromPrelogin(JSONObject(preBody))
        val auth = OpenPassCrypto.deriveAuthMaterial(password, params)

        val device = JSONObject().put("id", deviceId()).put("name", deviceName).put("platform", "android")
        val body = JSONObject().put("email", email).put("authVerifierB64", b64(auth.authVerifier)).put("device", device)
        val (status, resp) = http.send("POST", "/auth/login", body.toString(), null)
        when (status) {
            200 -> Unit
            401 -> throw InvalidCredentials()
            403 -> throw DeviceApprovalRequired()
            else -> error("login failed: $status")
        }
        val json = JSONObject(resp)
        val vaultKey = OpenPassCrypto.unwrapKey(auth.kek, unb64(json.getString("wrappedVaultKeyB64")))
        return Session(json.getString("accessToken"), json.getString("refreshToken"), vaultKey, json.getString("vaultId"))
    }

    /** Returns the recovery key text — show it once and never store it. */
    fun register(email: String, password: String, deviceName: String): Pair<Session, String> {
        val params = OpenPassCrypto.newKdfParams()
        val auth = OpenPassCrypto.deriveAuthMaterial(password, params)
        val vaultKey = OpenPassCrypto.randomVaultKey()
        val recovery = OpenPassCrypto.generateRecoveryKey()
        val device = JSONObject().put("id", deviceId()).put("name", deviceName).put("platform", "android")
        val body = JSONObject()
            .put("email", email)
            .put("authVerifierB64", b64(auth.authVerifier))
            .put("kdfSaltB64", params.saltB64)
            .put("kdfParams", JSONObject().put("memoryKib", params.memoryKib.toInt()).put("iterations", params.iterations.toInt()).put("parallelism", params.parallelism.toInt()))
            .put("wrappedVaultKeyB64", b64(OpenPassCrypto.wrapKey(auth.kek, vaultKey)))
            .put("recoveryWrappedVaultKeyB64", b64(OpenPassCrypto.wrapKey(recovery.key, vaultKey)))
            .put("recoveryAuthProofB64", b64(OpenPassCrypto.recoveryAuthProof(recovery.key)))
            .put("identityPublicKeyB64", b64(OpenPassCrypto.randomVaultKey())) // placeholder until sharing (post-v1)
            .put("wrappedIdentityPrivateKeyB64", b64(OpenPassCrypto.wrapKey(vaultKey, OpenPassCrypto.randomVaultKey())))
            .put("device", device)
        val (status, resp) = http.send("POST", "/auth/register", body.toString(), null)
        check(status == 201) { "register failed: $status $resp" }
        val json = JSONObject(resp)
        return Session(json.getString("accessToken"), json.getString("refreshToken"), vaultKey, json.getString("vaultId")) to recovery.text
    }

    companion object {
        fun deviceIdProvider(prefs: android.content.SharedPreferences): () -> String = {
            prefs.getString("openpass.deviceId", null) ?: UUID.randomUUID().toString().also {
                prefs.edit().putString("openpass.deviceId", it).apply()
            }
        }
    }
}
