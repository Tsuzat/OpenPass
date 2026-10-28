package app.openpass.credentials

import java.security.MessageDigest

/** WebAuthn authenticator data construction — mirrors the Swift VaultKit implementation. */
object WebAuthn {
    const val FLAG_UP: Int = 0x01
    const val FLAG_UV: Int = 0x04
    const val FLAG_BE: Int = 0x08
    const val FLAG_BS: Int = 0x10
    const val FLAG_AT: Int = 0x40
    const val SYNCED_ASSERTION_FLAGS: Int = FLAG_UP or FLAG_UV or FLAG_BE or FLAG_BS // 0x1D

    fun rpIdHash(rpId: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))

    fun assertionAuthenticatorData(rpId: String, signCount: Int, flags: Int = SYNCED_ASSERTION_FLAGS): ByteArray {
        val out = ByteArray(37)
        rpIdHash(rpId).copyInto(out, 0)
        out[32] = flags.toByte()
        out[33] = (signCount ushr 24).toByte()
        out[34] = (signCount ushr 16).toByte()
        out[35] = (signCount ushr 8).toByte()
        out[36] = signCount.toByte()
        return out
    }

    fun registrationAuthenticatorData(rpId: String, signCount: Int, credentialId: ByteArray, cosePublicKey: ByteArray): ByteArray {
        val base = assertionAuthenticatorData(rpId, signCount, SYNCED_ASSERTION_FLAGS or FLAG_AT)
        val out = ByteArray(37 + 16 + 2 + credentialId.size + cosePublicKey.size)
        base.copyInto(out, 0)
        // AAGUID: 16 zero bytes (none attestation) at offset 37
        out[53] = (credentialId.size ushr 8).toByte()
        out[54] = credentialId.size.toByte()
        credentialId.copyInto(out, 55)
        cosePublicKey.copyInto(out, 55 + credentialId.size)
        return out
    }

    fun rpIdMatches(requestRpId: String, storedRpId: String): Boolean = requestRpId == storedRpId

    fun b64Url(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
}
