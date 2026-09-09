package org.owasp.uncrackable.server

import com.android.keyattestation.verifier.testing.FakeCalendar
import com.android.keyattestation.verifier.testing.KeyAttestationCertPathFactory
import com.google.api.core.ApiFutures
import com.google.api.core.SettableApiFuture
import com.google.api.gax.rpc.ApiException
import com.google.api.gax.rpc.StatusCode
import java.time.Instant
import java.util.Base64
import kotlin.test.*

class ProductionTest {
    private fun environment(): Map<String, String> {
        val root = KeyAttestationCertPathFactory(FakeCalendar()).root
        return mapOf(
            "GOOGLE_CLOUD_PROJECT" to "test-project",
            "CHALLENGE_HMAC_KEY" to Base64.getEncoder().encodeToString(ByteArray(32) { 7 }),
            "FLAG_TIER1" to "synthetic-one", "FLAG_TIER2" to "synthetic-two",
            "APP_PACKAGE" to "org.owasp.mastg.uncrackable5", "APP_SIGNER_SHA256" to "ab".repeat(32),
            "ATTESTATION_ROOTS" to "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString(root.encoded) + "\n-----END CERTIFICATE-----",
        )
    }

    @Test fun `explicit configuration loads without exposing secrets`() {
        val config = RuntimeConfig.load(environment())
        assertEquals(8080, config.port)
        assertEquals(32, config.hmacKey.size)
        assertEquals(1, config.anchors.size)
        assertFalse(config.toString().contains("synthetic-one"))
    }

    @Test fun `missing malformed and emulator configuration fails closed`() {
        val env = environment()
        for (name in env.keys) assertFailsWith<IllegalArgumentException> { RuntimeConfig.load(env - name) }
        for ((name, value) in listOf(
            "PORT" to "0", "CHALLENGE_HMAC_KEY" to "sensitive-invalid-value",
            "APP_SIGNER_SHA256" to "bad-signer", "ATTESTATION_ROOTS" to "not-a-root",
            "ATTESTATION_ROOTS" to env.getValue("ATTESTATION_ROOTS") + "trailing-data",
            "APP_PACKAGE" to "other.package", "FLAG_TIER2" to "synthetic-one",
            "FIRESTORE_EMULATOR_HOST" to "localhost:8081",
        )) {
            val failure = assertFailsWith<IllegalArgumentException> { RuntimeConfig.load(env + (name to value)) }
            assertFalse(failure.toString().contains("sensitive-invalid-value"))
            assertNull(failure.cause)
        }
    }

    private val id = "ab".repeat(32)
    private val expiry = Instant.parse("2026-09-09T12:00:00Z")
    private fun apiFailure(code: StatusCode.Code) = ApiException(null, object : StatusCode {
        override fun getCode() = code
        override fun getTransportCode(): Any = code
    }, false)

    @Test fun `create receives digest and expiry and only success consumes`() {
        val store = FirestoreReplayStore({ actualId, actualExpiry ->
            assertEquals(id, actualId)
            assertEquals(expiry, actualExpiry)
            ApiFutures.immediateFuture(Unit)
        })
        assertTrue(store.consume(id, expiry))
        assertFailsWith<IllegalArgumentException> { store.consume("../bad", expiry) }
    }

    @Test fun `only already exists is a replay and other statuses are unavailable`() {
        for (code in listOf(StatusCode.Code.ALREADY_EXISTS, StatusCode.Code.PERMISSION_DENIED,
            StatusCode.Code.UNAVAILABLE, StatusCode.Code.DEADLINE_EXCEEDED)) {
            val store = FirestoreReplayStore({ _, _ -> ApiFutures.immediateFailedFuture<Unit>(apiFailure(code)) })
            if (code == StatusCode.Code.ALREADY_EXISTS) assertFalse(store.consume(id, expiry))
            else assertFailsWith<Unavailable> { store.consume(id, expiry) }
        }
        assertFailsWith<Unavailable> {
            FirestoreReplayStore({ _, _ -> throw IllegalStateException("private detail") }).consume(id, expiry)
        }
    }

    @Test fun `uncertain writes time out and never issue`() {
        val pending = SettableApiFuture.create<Unit>()
        assertFailsWith<Unavailable> { FirestoreReplayStore({ _, _ -> pending }, 1).consume(id, expiry) }
        assertTrue(pending.isCancelled)
    }
}
