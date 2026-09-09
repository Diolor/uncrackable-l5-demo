package org.owasp.uncrackable.server

import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable class ChallengeResponse(val challenge: String, val expiresIn: Int = 120)
@Serializable class AttestRequest(val challenge: String, val chain: List<String>, val pop: String)
@Serializable class FlagResponse(val tier: Int, val flag: String, val reason: String? = null)
@Serializable class ErrorResponse(val error: String)
@Serializable class HealthResponse(val status: String = "ok")

// Messages deliberately contain only fixed codes, never submitted data or secrets.
class Rejected(val code: String) : RuntimeException(code)
class Unavailable : RuntimeException("verification_unavailable")

/** Production implementation must provide atomic create-if-absent across instances. */
fun interface ReplayStore {
    fun consume(id: String, expiresAt: Instant): Boolean
}
fun interface AttestationEvidenceVerifier {
    fun verify(request: AttestRequest, challenge: ByteArray): Int
}
