package org.owasp.uncrackable.server

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.KeyAttestationCertPathFactory
import com.google.protobuf.ByteString
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.TrustAnchor
import java.security.spec.ECGenParameterSpec
import java.time.*
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Callable
import kotlin.test.*

private class MutableClock(var time: Instant = Instant.parse("2024-10-20T12:00:00Z")) : Clock() {
    override fun instant() = time
    override fun getZone() = ZoneOffset.UTC
    override fun withZone(zone: ZoneId): Clock = this
    fun advance(seconds: Long) { time = time.plusSeconds(seconds) }
}
private class MemoryReplay : ReplayStore {
    val ids = ConcurrentHashMap.newKeySet<String>()
    override fun consume(id: String, expiresAt: Instant) = ids.add(id)
}
private class Fixture {
    val clock = MutableClock()
    val challenges = Challenges(ByteArray(32) { 7 }, clock)
    val replay = MemoryReplay()
    val factory = KeyAttestationCertPathFactory(FakeCalendar())
    val signer = ByteArray(32) { 4 }
    val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    var status = """{"entries":{}}"""
    val revocations = Revocations(clock) { StatusDownload(status) }
    val verifier = AndroidVerifier(setOf(TrustAnchor(factory.root, null)), "org.owasp.mastg.uncrackable5", signer, clock, revocations)
    val service = AttestationService(challenges, verifier, replay, "synthetic-tier-one", "synthetic-tier-two")

    fun request(tier: Int = 2, change: (KeyDescription) -> KeyDescription = { it }): AttestRequest {
        val token = challenges.issue().challenge
        val bytes = challenges.verify(token)
        val desc = change(KeyDescription(
            BigInteger.valueOf(300), SecurityLevel.TRUSTED_ENVIRONMENT,
            BigInteger.valueOf(300), SecurityLevel.TRUSTED_ENVIRONMENT,
            ByteString.copyFrom(bytes), ByteString.EMPTY,
            AuthorizationList(attestationApplicationId = AttestationApplicationId(
                setOf(AttestationPackageInfo("org.owasp.mastg.uncrackable5", BigInteger.ONE)),
                setOf(ByteString.copyFrom(signer)),
            )),
            AuthorizationList(
                purposes = setOf(BigInteger.valueOf(2)), algorithms = BigInteger.valueOf(3),
                keySize = BigInteger.valueOf(256), ecCurve = BigInteger.ONE,
                digests = setOf(BigInteger.valueOf(4)), origin = Origin.GENERATED,
                rootOfTrust = RootOfTrust(ByteString.copyFrom(ByteArray(32)), tier == 2,
                    if (tier == 2) VerifiedBootState.VERIFIED else VerifiedBootState.UNVERIFIED),
            ),
        ))
        val chain = factory.generateCertPath(desc, leafKey = key.public).certificatesWithAnchor
        val pop = Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(bytes); sign() }
        return AttestRequest(token, chain.map { Base64.getEncoder().encodeToString(it.encoded) }, Base64.getEncoder().encodeToString(pop))
    }
}

class BackendTest {
    @Test fun `valid signed chains issue the correct tiers`() {
        val f = Fixture()
        assertEquals(1, f.service.attest(f.request(1)).tier)
        val result = f.service.attest(f.request(2))
        assertEquals(2, result.tier)
        assertEquals("synthetic-tier-two", result.flag)
    }
    @Test fun `StrongBox is accepted`() {
        val f = Fixture()
        val request = f.request { it.copy(attestationSecurityLevel = SecurityLevel.STRONG_BOX, keyMintSecurityLevel = SecurityLevel.STRONG_BOX) }
        assertEquals(2, f.service.attest(request).tier)
    }
    @Test fun `root omitted by client is completed only from trusted anchors`() {
        val f = Fixture(); val r = f.request()
        assertEquals(2, f.service.attest(AttestRequest(r.challenge, r.chain.dropLast(1), r.pop)).tier)
    }
    @Test fun `bad proof does not consume challenge`() {
        val f = Fixture(); val r = f.request()
        assertFailsWith<Rejected> { f.service.attest(AttestRequest(r.challenge, r.chain, "AAAA")) }
        assertTrue(f.replay.ids.isEmpty())
        assertEquals(2, f.service.attest(r).tier)
    }
    @Test fun `different attested challenge is rejected`() {
        val f = Fixture()
        val r = f.request { it.copy(attestationChallenge = ByteString.copyFromUtf8("wrong")) }
        assertFailsWith<Rejected> { f.service.attest(r) }
        assertTrue(f.replay.ids.isEmpty())
    }
    @Test fun `resigned app and software security levels are rejected`() {
        val f = Fixture()
        val r = f.request { it.copy(softwareEnforced = it.softwareEnforced.copy(attestationApplicationId = AttestationApplicationId(
            setOf(AttestationPackageInfo("org.owasp.mastg.uncrackable5", BigInteger.ONE)), setOf(ByteString.copyFrom(ByteArray(32)))))) }
        assertEquals("app_integrity", assertFailsWith<Rejected> { f.service.attest(r) }.code)
        val software = f.request { it.copy(attestationSecurityLevel = SecurityLevel.SOFTWARE, keyMintSecurityLevel = SecurityLevel.SOFTWARE) }
        assertEquals("no_hardware_attestation", assertFailsWith<Rejected> { f.service.attest(software) }.code)
    }
    @Test fun `wrong package and extra signer are rejected`() {
        for (extraSigner in listOf(false, true)) {
            val f = Fixture()
            val r = f.request { it.copy(softwareEnforced = it.softwareEnforced.copy(attestationApplicationId = AttestationApplicationId(
                setOf(AttestationPackageInfo(if (extraSigner) "org.owasp.mastg.uncrackable5" else "wrong", BigInteger.ONE)),
                if (extraSigner) setOf(ByteString.copyFrom(f.signer), ByteString.copyFrom(ByteArray(32))) else setOf(ByteString.copyFrom(f.signer))))) }
            assertEquals("app_integrity", assertFailsWith<Rejected> { f.service.attest(r) }.code)
        }
    }
    @Test fun `unexpected key purpose is rejected`() {
        val f = Fixture()
        val r = f.request { it.copy(hardwareEnforced = it.hardwareEnforced.copy(purposes = setOf(BigInteger.valueOf(2), BigInteger.valueOf(3)))) }
        assertFailsWith<Rejected> { f.service.attest(r) }
    }
    @Test fun `untrusted root is rejected`() {
        val f = Fixture()
        val otherKey = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val otherRoot = KeyAttestationCertPathFactory(hardcodedRootKey = otherKey).root
        val verifier = AndroidVerifier(setOf(TrustAnchor(otherRoot, null)), "org.owasp.mastg.uncrackable5", f.signer, f.clock, f.revocations)
        val r = f.request()
        assertFailsWith<Rejected> { verifier.verify(r, f.challenges.verify(r.challenge)) }
    }
    @Test fun `revoked suspended and unknown listed status are rejected`() {
        for (status in listOf("REVOKED", "SUSPENDED", "FUTURE_STATUS")) {
            val f = Fixture(); val r = f.request()
            f.status = """{"entries":{"${f.factory.root.serialNumber.toString(16)}":{"status":"$status"}}}"""
            assertFailsWith<Rejected> { f.service.attest(r) }
            assertTrue(f.replay.ids.isEmpty())
        }
    }
    @Test fun `listed intermediate and corrupted certificate are rejected`() {
        val f = Fixture(); val r = f.request()
        val factory = java.security.cert.CertificateFactory.getInstance("X.509")
        val intermediate = factory.generateCertificate(Base64.getDecoder().decode(r.chain[1]).inputStream()) as java.security.cert.X509Certificate
        f.status = """{"entries":{"${intermediate.serialNumber.toString(16)}":{"status":"SUSPENDED"}}}"""
        assertFailsWith<Rejected> { f.service.attest(r) }
        val clean = Fixture(); val original = clean.request()
        val altered = original.chain.toMutableList()
        val der = Base64.getDecoder().decode(altered[0])
        der[der.lastIndex] = (der.last().toInt() xor 1).toByte()
        altered[0] = Base64.getEncoder().encodeToString(der)
        assertFailsWith<Rejected> { clean.service.attest(AttestRequest(original.challenge, altered, original.pop)) }
    }
    @Test fun `expiry during replay store does not issue a flag`() {
        val f = Fixture()
        val service = AttestationService(f.challenges, f.verifier, { _, _ -> f.clock.advance(120); true }, "one", "two")
        assertEquals("challenge_expired", assertFailsWith<Rejected> { service.attest(f.request()) }.code)
    }
    @Test fun `certificate expiration is rejected`() {
        val f = Fixture()
        f.clock.advance(8 * 24 * 3600)
        assertFailsWith<Rejected> { f.service.attest(f.request()) }
        assertTrue(f.replay.ids.isEmpty())
    }
    @Test fun `malformed revocation response fails closed`() {
        val f = Fixture(); val r = f.request(); f.status = "{}"
        assertFailsWith<Unavailable> { f.service.attest(r) }
        assertTrue(f.replay.ids.isEmpty())
    }
    @Test fun `concurrent valid requests have one winner`() {
        val f = Fixture(); val r = f.request(); val pool = Executors.newFixedThreadPool(8)
        try {
            val outcomes = pool.invokeAll((1..16).map { Callable {
                try { f.service.attest(r); "ok" } catch (e: Rejected) { e.code }
            } }).map { it.get() }
            assertEquals(1, outcomes.count { it == "ok" })
            assertEquals(15, outcomes.count { it == "challenge_replayed" })
        } finally { pool.shutdownNow() }
    }
    @Test fun `expiry during verification fails before consumption`() {
        val f = Fixture()
        val service = AttestationService(f.challenges, { _, _ -> f.clock.advance(120); 2 }, f.replay, "one", "two")
        assertEquals("challenge_expired", assertFailsWith<Rejected> { service.attest(f.request()) }.code)
        assertTrue(f.replay.ids.isEmpty())
    }
    @Test fun `replay store outage cannot issue a flag`() {
        val f = Fixture()
        val service = AttestationService(f.challenges, f.verifier, { _, _ -> error("offline") }, "one", "two")
        assertFailsWith<Unavailable> { service.attest(f.request()) }
    }
    @Test fun `challenge is canonical authenticated and expires exactly at deadline`() {
        val clock = MutableClock(); val c = Challenges(ByteArray(32) { 1 }, clock)
        val token = c.issue().challenge
        assertEquals(57, c.verify(token).size)
        assertFailsWith<Rejected> { c.verify(token + "=") }
        val tampered = Base64.getUrlDecoder().decode(token).apply { this[10] = (this[10].toInt() xor 1).toByte() }
        assertFailsWith<Rejected> { c.verify(Base64.getUrlEncoder().withoutPadding().encodeToString(tampered)) }
        clock.advance(-1)
        assertEquals("challenge_expired", assertFailsWith<Rejected> { c.verify(token) }.code)
        clock.advance(120); c.verify(token)
        clock.advance(1)
        assertEquals("challenge_expired", assertFailsWith<Rejected> { c.verify(token) }.code)
    }
    @Test fun `stale revocation cache does not become empty on outage`() {
        val clock = MutableClock(); var calls = 0
        val revocations = Revocations(clock) {
            calls++
            if (calls > 1) error("offline")
            StatusDownload("""{"entries":{"00AB":{"status":"SUSPENDED"}}}""", 60)
        }
        assertEquals(setOf("ab"), revocations.current())
        clock.advance(59); assertEquals(setOf("ab"), revocations.current()); assertEquals(1, calls)
        clock.advance(1); assertFailsWith<Unavailable> { revocations.current() }
        assertFailsWith<Unavailable> { revocations.current() }
    }
    @Test fun `HTTP endpoints run through real verifier and return sanitized errors`() = testApplication {
        val f = Fixture()
        application { crackme(f.service) }
        assertEquals(HttpStatusCode.OK, client.get("/v1/health").status)
        val challenge = client.get("/v1/challenge")
        assertEquals("no-store", challenge.headers[HttpHeaders.CacheControl])
        assertEquals(76, Json.parseToJsonElement(challenge.bodyAsText()).jsonObject["challenge"]!!.jsonPrimitive.content.length)
        val r = f.request()
        val body = buildJsonObject {
            put("challenge", r.challenge); put("pop", r.pop)
            putJsonArray("chain") { r.chain.forEach { add(it) } }
        }.toString()
        val response = client.post("/v1/attest") { contentType(ContentType.Application.Json); setBody(body) }
        assertEquals(HttpStatusCode.OK, response.status, response.bodyAsText())
        assertTrue(response.bodyAsText().contains("synthetic-tier-two"))
        val replay = client.post("/v1/attest") { contentType(ContentType.Application.Json); setBody(body) }
        assertEquals(HttpStatusCode.Forbidden, replay.status)
        assertEquals("""{"error":"challenge_replayed"}""", replay.bodyAsText())
        val bad = client.post("/v1/attest") { contentType(ContentType.Application.Json); setBody("{broken") }
        assertEquals(HttpStatusCode.BadRequest, bad.status)
        val large = client.post("/v1/attest") { contentType(ContentType.Application.Json); setBody("x".repeat(41000)) }
        assertEquals(HttpStatusCode.PayloadTooLarge, large.status)
    }
}
