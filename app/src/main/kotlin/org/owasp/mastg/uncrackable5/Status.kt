package org.owasp.mastg.uncrackable5

import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Maps every attempt outcome to exactly one of the documented status strings. The mapping is
 * deliberately instructive: each failure names the control that rejected the attempt. No HTTP
 * status, exception text or other detail ever reaches the UI.
 */
object Status {
    fun forOutcome(outcome: AttestOutcome): Int = when (outcome) {
        is AttestOutcome.Accepted -> if (outcome.tier == 2) R.string.status_tier2 else R.string.status_tier1
        is AttestOutcome.Rejected -> when (outcome.code) {
            "app_integrity" -> R.string.status_app_integrity
            "no_hardware_attestation" -> R.string.status_no_hardware
            "challenge_expired", "challenge_replayed" -> R.string.status_expired
            else -> R.string.status_invalid
        }
        AttestOutcome.Unavailable -> R.string.status_unavailable
    }

    /** Client-side failure mapping. A trust or pin failure is detectable before any request is served. */
    fun forFailure(failure: Throwable): Int = when {
        // OkHttp's CertificatePinner rejected a chain the platform trusted (e.g. a system-installed proxy CA).
        failure is SSLPeerUnverifiedException -> R.string.status_untrusted
        // The framework's NetworkSecurityTrustManager rejected the chain (unknown or user-installed CA).
        failure is SSLHandshakeException || failure.hasCause<CertificateException>() -> R.string.status_untrusted
        failure is UnknownHostException || failure is ConnectException || failure is SocketTimeoutException ->
            R.string.status_no_connection
        failure is ProtocolException -> R.string.status_invalid
        failure is IOException -> R.string.status_no_connection
        // Key generation or signing failed locally (no attestation support, keystore error).
        else -> R.string.status_invalid
    }

    private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
        var current: Throwable? = this
        var depth = 0
        while (current != null && depth++ < 8) {
            if (current is T) return true
            current = current.cause
        }
        return false
    }
}
