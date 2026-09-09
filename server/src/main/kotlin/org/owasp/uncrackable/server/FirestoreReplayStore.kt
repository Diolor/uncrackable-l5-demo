package org.owasp.uncrackable.server

import com.google.api.core.ApiFuture
import com.google.api.gax.rpc.ApiException
import com.google.api.gax.rpc.StatusCode
import com.google.cloud.Timestamp
import com.google.cloud.firestore.Firestore
import java.time.Instant
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/** A timeout may have committed: never retry issuance or treat uncertainty as success. */
class FirestoreReplayStore internal constructor(
    private val create: (String, Instant) -> ApiFuture<*>,
    private val timeoutMillis: Long = 3000,
) : ReplayStore {
    constructor(firestore: Firestore) : this({ id, expiry ->
        firestore.collection("used_challenges").document(id).create(
            mapOf("expireAt" to Timestamp.ofTimeSecondsAndNanos(expiry.epochSecond, expiry.nano)),
        )
    })

    override fun consume(id: String, expiresAt: Instant): Boolean {
        require(id.matches(Regex("[0-9a-f]{64}")))
        val pending = try { create(id, expiresAt) } catch (_: Exception) { throw Unavailable() }
        try {
            pending.get(timeoutMillis, TimeUnit.MILLISECONDS)
            return true
        } catch (failure: ExecutionException) {
            val cause = failure.cause
            if (cause is ApiException && cause.statusCode.code == StatusCode.Code.ALREADY_EXISTS) return false
            throw Unavailable()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            throw Unavailable()
        } catch (_: Exception) {
            throw Unavailable()
        } finally {
            if (!pending.isDone) pending.cancel(true)
        }
    }
}
