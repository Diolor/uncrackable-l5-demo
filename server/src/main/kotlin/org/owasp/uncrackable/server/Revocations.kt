package org.owasp.uncrackable.server

import kotlinx.serialization.json.*
import java.net.URI
import java.net.HttpURLConnection
import java.math.BigInteger
import java.time.Clock
import java.time.Instant

class StatusDownload(val body: String, val maxAgeSeconds: Long = 300)
fun interface StatusFetcher { fun fetch(): StatusDownload }

/** No configurable URL, redirects, unbounded reads or trust-all transport. */
class GoogleStatusFetcher : StatusFetcher {
    override fun fetch(): StatusDownload {
        val connection = URI("https://android.googleapis.com/attestation/status").toURL().openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 3000
            connection.readTimeout = 3000
            connection.instanceFollowRedirects = false
            if (connection.responseCode != 200) throw Unavailable()
            val bytes = connection.inputStream.use { it.readNBytes(4 * 1024 * 1024 + 1) }
            if (bytes.size > 4 * 1024 * 1024) throw Unavailable()
            val cache = connection.getHeaderField("Cache-Control").orEmpty()
            val ttl = if (cache.contains("no-cache", true) || cache.contains("no-store", true)) 0 else
                Regex("(?i)(?:^|,)\\s*max-age=(\\d+)").find(cache)?.groupValues?.get(1)?.toLongOrNull() ?: 300
            val age = connection.getHeaderField("Age")?.toLongOrNull()?.coerceAtLeast(0) ?: 0
            return StatusDownload(bytes.toString(Charsets.UTF_8), (minOf(ttl, 300) - age).coerceAtLeast(0))
        } finally { connection.disconnect() }
    }
}

class Revocations(private val clock: Clock, private val fetcher: StatusFetcher) {
    private class Snapshot(val serials: Set<String>, val expires: Instant)
    private var snapshot: Snapshot? = null

    @Synchronized fun current(): Set<String> {
        val now = clock.instant()
        snapshot?.let { if (now.isBefore(it.expires)) return it.serials }
        try {
            val response = fetcher.fetch()
            val serials = parse(response.body)
            // Measure freshness from start, not completion of a slow download.
            val expires = now.plusSeconds(response.maxAgeSeconds.coerceIn(0, 300))
            if (!clock.instant().isBefore(expires)) throw Unavailable()
            snapshot = Snapshot(serials, expires)
            return serials
        } catch (_: Exception) { throw Unavailable() }
    }

    companion object {
        internal fun parse(body: String): Set<String> {
            val entries = Json.parseToJsonElement(body).jsonObject["entries"]?.jsonObject ?: throw Unavailable()
            return entries.map { (serial, entry) ->
                if (!serial.matches(Regex("[0-9a-fA-F]{1,128}"))) throw Unavailable()
                val status = entry.jsonObject["status"] as? JsonPrimitive ?: throw Unavailable()
                if (!status.isString || status.content.isBlank()) throw Unavailable()
                // Reject EVERY listed serial, including SUSPENDED and future statuses.
                BigInteger(serial, 16).toString(16)
            }.toSet()
        }
    }
}
