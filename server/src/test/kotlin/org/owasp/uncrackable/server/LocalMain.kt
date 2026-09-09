package org.owasp.uncrackable.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.io.File
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Local integration launcher (test sources only; never in the runtime artifact).
 *
 * Binds loopback, uses an in-memory replay store and a random per-run HMAC key, and accepts the
 * debug package/signer of a locally built client. Verification policy, revocation checking and
 * challenge handling are the production classes, unchanged. Use with `adb reverse tcp:8080 tcp:8080`
 * and a debug build pointed at `http://127.0.0.1:8080`.
 *
 * Environment:
 *  - LOCAL_APP_SIGNER_SHA256  required, 64 hex chars (SHA-256 of the debug signing certificate)
 *  - LOCAL_APP_PACKAGE        default org.owasp.mastg.uncrackable5.debug
 *  - LOCAL_ATTESTATION_ROOTS  default server/roots/google-attestation-roots.pem
 *  - LOCAL_RECORD_DIR         optional; every /v1/attest request body is written there as a fixture
 *  - PORT                     default 8080
 */
fun main() {
    val env = System.getenv()
    val signerHex = env["LOCAL_APP_SIGNER_SHA256"]?.takeIf { it.matches(Regex("[a-fA-F0-9]{64}")) }
        ?: error("LOCAL_APP_SIGNER_SHA256 must be 64 hex characters")
    val signer = signerHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val packageName = env["LOCAL_APP_PACKAGE"] ?: "org.owasp.mastg.uncrackable5.debug"
    val rootsFile = File(env["LOCAL_ATTESTATION_ROOTS"] ?: "server/roots/google-attestation-roots.pem")
    val recordDir = env["LOCAL_RECORD_DIR"]?.let { File(it).apply { mkdirs() } }
    val port = env["PORT"]?.toInt() ?: 8080

    val factory = CertificateFactory.getInstance("X.509")
    val anchors = rootsFile.inputStream().use { factory.generateCertificates(it) }
        .map { TrustAnchor(it as X509Certificate, null) }.toSet()
    require(anchors.isNotEmpty()) { "No roots in $rootsFile" }

    val clock = Clock.systemUTC()
    val hmac = ByteArray(32).also(SecureRandom()::nextBytes)
    val verifier = AndroidVerifier(anchors, packageName, signer, clock, Revocations(clock, GoogleStatusFetcher()))
    val replay = object : ReplayStore {
        val ids = ConcurrentHashMap.newKeySet<String>()
        override fun consume(id: String, expiresAt: Instant) = ids.add(id)
    }
    val logging = AttestationEvidenceVerifier { request, challenge ->
        recordDir?.let { dir ->
            val name = "attest-" + Instant.now().toString().replace(":", "") + ".json"
            File(dir, name).writeText(protocolJsonForRecording.encodeToString(AttestRequest.serializer(), request))
            println("local: recorded ${dir.resolve(name)}")
        }
        val started = System.nanoTime()
        try {
            verifier.verify(request, challenge).also {
                println("local: accepted tier=$it chainLength=${request.chain.size} in ${(System.nanoTime() - started) / 1_000_000} ms")
            }
        } catch (e: Rejected) {
            println("local: rejected code=${e.code} chainLength=${request.chain.size} in ${(System.nanoTime() - started) / 1_000_000} ms"); throw e
        } catch (e: Unavailable) {
            println("local: unavailable (revocation feed)"); throw e
        }
    }
    val service = AttestationService(Challenges(hmac, clock), logging, replay, "LOCAL-TIER1-" + hex(4), "LOCAL-TIER2-" + hex(4))
    println("local: package=$packageName signer=$signerHex roots=${anchors.size} port=$port record=${recordDir ?: "off"}")
    embeddedServer(Netty, host = "127.0.0.1", port = port) { crackme(service) }.start(wait = true)
}

private fun hex(n: Int) = ByteArray(n).also(SecureRandom()::nextBytes).toHex()
private val protocolJsonForRecording = kotlinx.serialization.json.Json { prettyPrint = true }
