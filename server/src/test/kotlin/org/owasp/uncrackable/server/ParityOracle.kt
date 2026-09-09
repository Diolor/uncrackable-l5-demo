package org.owasp.uncrackable.server

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

/**
 * Parity oracle for the TypeScript verifier port (test sources only).
 *
 * Reads JSON lines of [ParityCase] from the file named by PARITY_IN and writes one JSON line of
 * [ParityVerdict] per case to PARITY_OUT. Only the production [AndroidVerifier] is exercised;
 * challenge authentication, replay and revocation fetching are outside its scope (the challenge
 * bytes are the base64url decoding of the request's challenge string, as in RecordedAttestationTest).
 *
 * Run: ./gradlew :server:runLocal -PlocalMain=org.owasp.uncrackable.server.ParityOracleKt
 */
@Serializable
class ParityCase(
    val id: String,
    val request: AttestRequest,
    val now: String,
    val packageName: String,
    val signer: String,
    val roots: String,
    val serials: List<String> = emptyList(),
)

@Serializable class ParityVerdict(val id: String, val code: String)

private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

fun main() {
    val input = File(System.getenv("PARITY_IN") ?: error("PARITY_IN required"))
    val output = File(System.getenv("PARITY_OUT") ?: error("PARITY_OUT required"))
    val factory = CertificateFactory.getInstance("X.509")
    val anchorCache = HashMap<String, Set<TrustAnchor>>()
    output.bufferedWriter().use { out ->
        input.forEachLine { line ->
            if (line.isBlank()) return@forEachLine
            val case = json.decodeFromString<ParityCase>(line)
            val code = try {
                val anchors = anchorCache.getOrPut(case.roots) {
                    factory.generateCertificates(case.roots.byteInputStream())
                        .map { TrustAnchor(it as X509Certificate, null) }.toSet()
                }
                val clock = Clock.fixed(Instant.parse(case.now), ZoneOffset.UTC)
                val signer = case.signer.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val serials = case.serials.toSet()
                val verifier = AndroidVerifier(anchors, case.packageName, signer, clock,
                    Revocations(clock) { StatusDownload(json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(),
                        kotlinx.serialization.json.buildJsonObject {
                            put("entries", kotlinx.serialization.json.buildJsonObject {
                                for (s in serials) put(s, kotlinx.serialization.json.buildJsonObject { put("status", kotlinx.serialization.json.JsonPrimitive("REVOKED")) })
                            })
                        })) })
                val challenge = try { Base64.getUrlDecoder().decode(case.request.challenge) }
                    catch (_: IllegalArgumentException) { throw Rejected("attestation_invalid") }
                "ok:" + verifier.verify(case.request, challenge)
            } catch (e: Rejected) { e.code }
              catch (_: Unavailable) { "unavailable" }
              catch (e: Exception) { "error:" + e::class.simpleName }
            out.write(json.encodeToString(ParityVerdict.serializer(), ParityVerdict(case.id, code)))
            out.newLine()
        }
    }
}
