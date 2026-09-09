package org.owasp.mastg.uncrackable5

import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import kotlin.test.Test
import kotlin.test.assertEquals

class StatusTest {
    @Test fun serverCodes() {
        assertEquals(R.string.status_tier2, Status.forOutcome(AttestOutcome.Accepted(2, ByteArray(1))))
        assertEquals(R.string.status_tier1, Status.forOutcome(AttestOutcome.Accepted(1, ByteArray(1))))
        assertEquals(R.string.status_app_integrity, Status.forOutcome(AttestOutcome.Rejected("app_integrity")))
        assertEquals(R.string.status_no_hardware, Status.forOutcome(AttestOutcome.Rejected("no_hardware_attestation")))
        assertEquals(R.string.status_expired, Status.forOutcome(AttestOutcome.Rejected("challenge_expired")))
        assertEquals(R.string.status_expired, Status.forOutcome(AttestOutcome.Rejected("challenge_replayed")))
        assertEquals(R.string.status_invalid, Status.forOutcome(AttestOutcome.Rejected("attestation_invalid")))
        assertEquals(R.string.status_invalid, Status.forOutcome(AttestOutcome.Rejected("something_new")))
        assertEquals(R.string.status_unavailable, Status.forOutcome(AttestOutcome.Unavailable))
    }

    @Test fun trustFailuresAreMitm() {
        assertEquals(R.string.status_untrusted, Status.forFailure(SSLPeerUnverifiedException("pin")))
        assertEquals(R.string.status_untrusted, Status.forFailure(SSLHandshakeException("chain")))
        assertEquals(R.string.status_untrusted,
            Status.forFailure(java.io.IOException("wrapped", CertificateException("untrusted"))))
    }

    @Test fun networkFailures() {
        assertEquals(R.string.status_no_connection, Status.forFailure(UnknownHostException()))
        assertEquals(R.string.status_no_connection, Status.forFailure(ConnectException()))
        assertEquals(R.string.status_no_connection, Status.forFailure(SocketTimeoutException()))
        assertEquals(R.string.status_no_connection, Status.forFailure(java.io.IOException("reset")))
        assertEquals(R.string.status_invalid, Status.forFailure(ProtocolException("tier")))
        assertEquals(R.string.status_invalid, Status.forFailure(IllegalStateException("keystore")))
    }
}
