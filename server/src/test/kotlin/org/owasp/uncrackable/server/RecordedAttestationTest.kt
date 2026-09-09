package org.owasp.uncrackable.server

import kotlinx.serialization.json.Json
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RecordedAttestationTest {
    private val request = resource("oneplus9pro-android14-tee-tier2.json").bufferedReader().use {
        Json.decodeFromString<AttestRequest>(it.readText())
    }
    private val challenge = Base64.getUrlDecoder().decode(request.challenge)
    // The recorded leaf expires five minutes after capture. Never use today's clock here.
    private val clock = Clock.fixed(Instant.parse("2026-09-09T18:52:11Z"), ZoneOffset.UTC)
    private val anchors = resource("google-attestation-roots.pem").use {
        CertificateFactory.getInstance("X.509").generateCertificates(it)
            .map { cert -> TrustAnchor(cert as X509Certificate, null) }.toSet()
    }
    private val debugSigner = "5bb26e313b60dcb38bf264e8e152111fc76ed51e12ec77d1073be3323beb53be"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun verifier(packageName: String = "org.owasp.mastg.uncrackable5.debug") = AndroidVerifier(
        anchors, packageName, debugSigner, clock,
        // Offline compatibility evidence only, not a claim about current revocation status.
        Revocations(clock) { StatusDownload("""{"entries":{}}""") },
    )

    @Test fun `recorded OnePlus TEE chain and proof pass tier two verification`() {
        assertEquals(4, request.chain.size)
        assertEquals(2, verifier().verify(request, challenge))
    }

    @Test fun `recorded debug identity does not qualify as release package`() {
        assertEquals("app_integrity", assertFailsWith<Rejected> {
            verifier("org.owasp.mastg.uncrackable5").verify(request, challenge)
        }.code)
    }

    private fun resource(name: String) = requireNotNull(javaClass.getResourceAsStream("/$name")) {
        "Missing test resource: $name"
    }
}
