package org.owasp.mastg.uncrackable5

import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Wire model. */
@Serializable class ChallengeResponse(val challenge: String, val expiresIn: Int = 120)
@Serializable class AttestRequest(val challenge: String, val chain: List<String>, val pop: String)
/** The response model declares `flag`; the value is processed at runtime and never shown or logged. */
@Serializable class FlagResponse(val tier: Int, val flag: String, val reason: String? = null)
@Serializable class ErrorResponse(val error: String)

internal val protocolJson = Json { ignoreUnknownKeys = true; explicitNulls = false }

/** Canonical challenge: `ver(1) || ts(8) || nonce(32) || tag(16)` = 57 bytes, base64url, no padding. */
object Challenge {
    const val SIZE = 57
    const val ENCODED_LENGTH = 76

    fun decode(encoded: String): ByteArray {
        if (encoded.length != ENCODED_LENGTH) throw IllegalArgumentException("challenge length")
        val bytes = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("challenge encoding")
        }
        if (bytes.size != SIZE || bytes[0] != 1.toByte() ||
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) != encoded) throw IllegalArgumentException("challenge format")
        return bytes
    }
}
