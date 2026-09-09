package org.owasp.uncrackable.server

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher
import com.google.common.collect.ImmutableList
import com.google.protobuf.ByteString
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.Signature
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.util.Base64
import java.util.Date

/** Trust anchors and signer are mandatory inputs; no test/production defaults. */
class AndroidVerifier(
    anchors: Set<TrustAnchor>,
    packageName: String,
    signerSha256: ByteArray,
    private val clock: Clock,
    private val revocations: Revocations,
) : AttestationEvidenceVerifier {
    private val anchors = anchors.toSet()
    private val signer = ByteString.copyFrom(signerSha256)
    init {
        require(anchors.isNotEmpty() && anchors.all { it.trustedCert != null })
        require(packageName.isNotBlank() && signerSha256.size == 32)
    }
    private val config = ConstraintConfig(
        additionalConstraints = ImmutableList.of(
            SecurityLevelConstraint.MATCHES_CERTIFICATE,
            AttributeConstraint.STRICT("App identity", true) { description ->
                val app = description.softwareEnforced.attestationApplicationId
                app != null && app.packages.size == 1 && app.packages.single().name == packageName &&
                    app.signatures == setOf(signer)
            },
            AttributeConstraint.STRICT("Device integrity", true) { description ->
                val boot = description.hardwareEnforced.rootOfTrust
                boot != null && boot.deviceLocked && boot.verifiedBootState == VerifiedBootState.VERIFIED
            },
            AttributeConstraint.STRICT("Signing key", true) { description ->
                val auth = description.hardwareEnforced
                auth.purposes == setOf(BigInteger.valueOf(2)) && // KeyMint SIGN
                    auth.algorithms == BigInteger.valueOf(3) && // EC
                    auth.keySize == BigInteger.valueOf(256) &&
                    auth.ecCurve == BigInteger.valueOf(1) && // P-256
                    auth.digests == setOf(BigInteger.valueOf(4)) // SHA-256
            },
        ),
    )

    override fun verify(request: AttestRequest, challenge: ByteArray): Int {
        if (request.chain.size !in 2..6 || request.pop.length !in 1..128) throw Rejected("attestation_invalid")
        val chain = try {
            request.chain.map { encoded ->
                if (encoded.length !in 1..5464) throw IllegalArgumentException()
                val der = Base64.getDecoder().decode(encoded)
                if (der.size > 4096) throw IllegalArgumentException()
                val stream = ByteArrayInputStream(der)
                val cert = CertificateFactory.getInstance("X.509").generateCertificate(stream) as X509Certificate
                // Accept a single DER certificate, not a PEM wrapper or trailing payload.
                if (stream.available() != 0 || !cert.encoded.contentEquals(der)) throw IllegalArgumentException()
                cert
            }.toMutableList().apply {
                if (last().subjectX500Principal != last().issuerX500Principal) {
                    val tail = last()
                    val root = anchors.map { it.trustedCert }.singleOrNull { root ->
                        tail.issuerX500Principal == root.subjectX500Principal &&
                            runCatching { tail.verify(root.publicKey) }.isSuccess
                    } ?: throw IllegalArgumentException()
                    add(root)
                }
            }
        } catch (_: Exception) { throw Rejected("attestation_invalid") }

        val serials = revocations.current()
        rejectListed(chain, serials)
        val result = try {
            // No LogHook: upstream hooks may contain the entire proof.
            Verifier({ anchors }, { serials }, { clock.instant() }, config)
                .verify(chain, ChallengeMatcher(ByteString.copyFrom(challenge)))
        } catch (_: Exception) { throw Rejected("attestation_invalid") }
        when (result) {
            is VerificationResult.Success -> {
                try {
                    // Upstream intentionally omits leaf validity; this protocol requires it.
                    chain.first().checkValidity(Date.from(clock.instant()))
                    val key = result.publicKey as? ECPublicKey ?: throw IllegalArgumentException()
                    val expected = AlgorithmParameters.getInstance("EC").apply {
                        init(ECGenParameterSpec("secp256r1"))
                    }.getParameterSpec(ECParameterSpec::class.java)
                    require(key.params.curve == expected.curve && key.params.generator == expected.generator &&
                        key.params.order == expected.order && key.params.cofactor == expected.cofactor)
                    val signature = Base64.getDecoder().decode(request.pop)
                    val valid = Signature.getInstance("SHA256withECDSA").run {
                        initVerify(key); update(challenge); verify(signature)
                    }
                    if (!valid) throw IllegalArgumentException()
                } catch (_: Exception) { throw Rejected("attestation_invalid") }
                // A long verification must not outlive revocation freshness.
                rejectListed(chain, revocations.current())
                return 2 // Legacy response number; there is no weaker tier-one fallback.
            }
            is VerificationResult.ConstraintViolation -> throw Rejected(when (result.constraintLabel) {
                "App identity" -> "app_integrity"
                "Device integrity" -> "device_integrity"
                "Security level" -> "no_hardware_attestation"
                else -> "attestation_invalid"
            })
            else -> throw Rejected("attestation_invalid")
        }
    }

    private fun rejectListed(chain: List<X509Certificate>, serials: Set<String>) {
        if (chain.any { it.serialNumber.toString(16) in serials }) throw Rejected("attestation_invalid")
    }
}
