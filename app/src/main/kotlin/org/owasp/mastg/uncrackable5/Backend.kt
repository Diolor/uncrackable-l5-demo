package org.owasp.mastg.uncrackable5

import kotlinx.serialization.SerializationException
import okhttp3.ConnectionSpec
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Outcome of one full challenge → attest round trip. Carries a flag only on acceptance. */
sealed class AttestOutcome {
    class Accepted(val tier: Int, val flag: ByteArray) : AttestOutcome()
    class Rejected(val code: String) : AttestOutcome()
    object Unavailable : AttestOutcome()
}

/** Thrown when the server answered with something outside the documented protocol. */
class ProtocolException(message: String) : IOException(message)

/** The only network client: pinned, fail-closed TLS, no retry, redirects, cache or logging. */
class Backend(baseUrl: String, private val attestation: Attestation) {
    private val base: HttpUrl = baseUrl.toHttpUrl()
    private val client: OkHttpClient = OkHttpClient.Builder()
        // Only a debug build with an http:// base URL can dial cleartext (local integration).
        .connectionSpecs(
            if (BuildConfig.DEBUG && base.scheme == "http") listOf(ConnectionSpec.RESTRICTED_TLS, ConnectionSpec.CLEARTEXT)
            else listOf(ConnectionSpec.RESTRICTED_TLS),
        )
        .certificatePinner(Pins.pinner(base.host))
        .callTimeout(15, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .cache(null)
        .build()

    /** Performs one attempt. Network and TLS failures propagate as [IOException] subclasses. */
    @Throws(IOException::class)
    fun attest(): AttestOutcome {
        val issued = challenge() ?: return AttestOutcome.Unavailable
        val challengeBytes = try { Challenge.decode(issued) } catch (e: IllegalArgumentException) {
            throw ProtocolException("challenge")
        }
        val proof = attestation.prove(challengeBytes)
        val body = protocolJson.encodeToString(AttestRequest.serializer(), AttestRequest(issued, proof.chain, proof.pop))
        val request = Request.Builder()
            .url(base.resolve("/v1/attest")!!)
            .post(body.toRequestBody(JSON))
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .build()
        client.newCall(request).execute().use { response ->
            val text = response.bounded()
            return when (response.code) {
                200 -> {
                    val parsed = decode(FlagResponse.serializer(), text)
                    if (parsed.tier != 2) throw ProtocolException("tier")
                    AttestOutcome.Accepted(parsed.tier, parsed.flag.encodeToByteArray())
                }
                403 -> AttestOutcome.Rejected(decode(ErrorResponse.serializer(), text).error)
                429, 503 -> AttestOutcome.Unavailable
                else -> throw ProtocolException("status")
            }
        }
    }

    /** Null when the service answered 429 or 503; any other non-200 status is a protocol error. */
    private fun challenge(): String? {
        val request = Request.Builder()
            .url(base.resolve("/v1/challenge")!!)
            .get()
            .header("Accept", "application/json")
            .header("Cache-Control", "no-store")
            .build()
        client.newCall(request).execute().use { response ->
            return when (response.code) {
                200 -> decode(ChallengeResponse.serializer(), response.bounded()).challenge
                429, 503 -> null
                else -> throw ProtocolException("challenge status")
            }
        }
    }

    private fun <T> decode(serializer: kotlinx.serialization.KSerializer<T>, text: String): T = try {
        protocolJson.decodeFromString(serializer, text)
    } catch (e: SerializationException) {
        throw ProtocolException("body")
    } catch (e: IllegalArgumentException) {
        throw ProtocolException("body")
    }

    /** Reads at most [MAX_BODY] bytes; anything larger is outside the protocol. */
    private fun Response.bounded(): String {
        val source = body?.source() ?: throw ProtocolException("empty")
        if (!source.request(MAX_BODY.toLong() + 1)) return source.readUtf8()
        throw ProtocolException("too large")
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
        const val MAX_BODY = 8 * 1024
    }
}
