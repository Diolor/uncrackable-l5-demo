package org.owasp.uncrackable.server

import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Base64

/** Cloud Run injects pinned Secret Manager versions as environment variables. No secret toString. */
class RuntimeConfig private constructor(
    val port: Int,
    val projectId: String,
    val hmacKey: ByteArray,
    val tier1: String,
    val tier2: String,
    val packageName: String,
    val signer: ByteArray,
    val anchors: Set<TrustAnchor>,
) {
    companion object {
        fun load(env: Map<String, String> = System.getenv()): RuntimeConfig {
            fun required(name: String): String = env[name]?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("Missing configuration: $name")
            fun <T> parse(name: String, block: () -> T): T = try { block() }
                catch (_: Exception) { throw IllegalArgumentException("Invalid configuration: $name") }
            require(!env.containsKey("FIRESTORE_EMULATOR_HOST")) { "Emulator is forbidden in production launcher" }
            val port = parse("PORT") { (env["PORT"] ?: "8080").toInt().also { require(it in 1..65535) } }
            val project = required("GOOGLE_CLOUD_PROJECT")
            require(project.matches(Regex("[a-z][a-z0-9-]{4,28}[a-z0-9]"))) { "Invalid configuration: GOOGLE_CLOUD_PROJECT" }
            val key = parse("CHALLENGE_HMAC_KEY") {
                Base64.getDecoder().decode(required("CHALLENGE_HMAC_KEY")).also { require(it.size >= 32) }
            }
            val tier1 = required("FLAG_TIER1")
            val tier2 = required("FLAG_TIER2")
            require(tier1 != tier2) { "Flags must be distinct" }
            val packageName = required("APP_PACKAGE")
            require(packageName == "org.owasp.mastg.uncrackable5") { "Invalid configuration: APP_PACKAGE" }
            val signer = parse("APP_SIGNER_SHA256") {
                required("APP_SIGNER_SHA256").also { require(it.matches(Regex("[a-fA-F0-9]{64}"))) }
                    .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
            val anchors = parse("ATTESTATION_ROOTS") {
                val pem = required("ATTESTATION_ROOTS")
                require(pem.length <= 64 * 1024)
                val pattern = Regex("-----BEGIN CERTIFICATE-----[\\sA-Za-z0-9+/=]+-----END CERTIFICATE-----")
                val blocks = pattern.findAll(pem).toList()
                require(blocks.size in 1..16 && pattern.replace(pem, "").isBlank())
                blocks.map { block ->
                    val cert = CertificateFactory.getInstance("X.509")
                        .generateCertificate(block.value.byteInputStream()) as X509Certificate
                    require(cert.basicConstraints >= 0 && cert.subjectX500Principal == cert.issuerX500Principal)
                    cert.verify(cert.publicKey)
                    TrustAnchor(cert, null)
                }.toSet()
            }
            return RuntimeConfig(port, project, key, tier1, tier2, packageName, signer, anchors)
        }
    }
}
