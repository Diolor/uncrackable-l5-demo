package org.owasp.uncrackable.server

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Clock
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class Challenges(key: ByteArray, private val clock: Clock, private val random: SecureRandom = SecureRandom()) {
    private val key = key.copyOf().also { require(it.size >= 32) }
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun issue(): ChallengeResponse {
        val nonce = ByteArray(32).also(random::nextBytes)
        val payload = ByteBuffer.allocate(41).put(1).putLong(clock.instant().epochSecond).put(nonce).array()
        return ChallengeResponse(encoder.encodeToString(payload + tag(payload)))
    }

    fun verify(encoded: String): ByteArray {
        if (encoded.length != 76) throw Rejected("attestation_invalid")
        val bytes = try { Base64.getUrlDecoder().decode(encoded) } catch (_: IllegalArgumentException) {
            throw Rejected("attestation_invalid")
        }
        if (bytes.size != 57 || encoder.encodeToString(bytes) != encoded || bytes[0] != 1.toByte() ||
            !MessageDigest.isEqual(tag(bytes.copyOfRange(0, 41)), bytes.copyOfRange(41, 57))) {
            throw Rejected("attestation_invalid")
        }
        val issued = ByteBuffer.wrap(bytes, 1, 8).long
        val now = clock.instant().epochSecond
        if (issued < 0 || issued > now || now - issued >= 120) throw Rejected("challenge_expired")
        return bytes
    }

    fun expiresAt(bytes: ByteArray): Instant = Instant.ofEpochSecond(ByteBuffer.wrap(bytes, 1, 8).long + 120)
    fun id(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()
    private fun tag(payload: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256")); doFinal(payload).copyOf(16)
    }
}
internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }

class AttestationService(
    private val challenges: Challenges,
    private val verifier: AttestationEvidenceVerifier,
    private val replay: ReplayStore,
    private val tier1: String,
    private val tier2: String,
) {
    init { require(tier1.isNotBlank() && tier2.isNotBlank() && tier1 != tier2) }
    fun challenge(): ChallengeResponse = challenges.issue()
    fun attest(request: AttestRequest): FlagResponse {
        val bytes = challenges.verify(request.challenge)
        val tier = verifier.verify(request, bytes)
        check(tier == 1 || tier == 2)
        challenges.verify(request.challenge) // Verification may have taken the request past its deadline.
        val consumed = try { replay.consume(challenges.id(bytes), challenges.expiresAt(bytes)) }
            catch (_: Exception) { throw Unavailable() }
        if (!consumed) throw Rejected("challenge_replayed")
        challenges.verify(request.challenge) // A slow replay store must not permit expired issuance either.
        return FlagResponse(tier, if (tier == 2) tier2 else tier1, if (tier == 1) "device_integrity" else null)
    }
}
