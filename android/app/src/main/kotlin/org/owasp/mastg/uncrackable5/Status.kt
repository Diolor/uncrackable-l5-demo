package org.owasp.mastg.uncrackable5

import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

class FlagStorageException : Exception()

/** Maps every outcome to one status string; no HTTP status or exception text reaches the UI. */
object Status {
    fun forOutcome(outcome: AttestOutcome): Int = when (outcome) {
        is AttestOutcome.Accepted -> if (outcome.tier == 2) R.string.status_tier2 else R.string.status_invalid
        is AttestOutcome.Rejected -> when (outcome.code) {
            "device_integrity" -> R.string.status_device_integrity
            "app_integrity" -> R.string.status_app_integrity
            "no_hardware_attestation" -> R.string.status_no_hardware
            "challenge_expired", "challenge_replayed" -> R.string.status_expired
            else -> R.string.status_invalid
        }
        AttestOutcome.Unavailable -> R.string.status_unavailable
    }

    fun forFailure(failure: Throwable): Int = when {
        failure is FlagStorageException -> R.string.status_storage_failed
        // Pin failure (chain the platform trusted), then platform trust failure.
        failure is SSLPeerUnverifiedException -> R.string.status_untrusted
        failure is SSLHandshakeException || failure.hasCause<CertificateException>() -> R.string.status_untrusted
        failure is UnknownHostException || failure is ConnectException || failure is SocketTimeoutException ->
            R.string.status_no_connection
        failure is ProtocolException -> R.string.status_invalid
        failure is IOException -> R.string.status_no_connection
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
