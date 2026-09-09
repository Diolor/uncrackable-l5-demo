package org.owasp.uncrackable.server

import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/** Runs against the disposable demo database when explicitly configured. */
@EnabledIfEnvironmentVariable(named = "DEMO_DATABASE_URL", matches = ".+")
class PostgresDemoStoreTest {
    @Test fun `concurrent inserts have one winner and a new adapter still rejects replay`() {
        val url = System.getenv("DEMO_DATABASE_URL")
        val store = PostgresDemoStore.fromUrl(url)
        store.initialize()
        val id = MessageDigest.getInstance("SHA-256").digest(UUID.randomUUID().toString().toByteArray()).toHex()
        val expiry = Instant.now().plusSeconds(120)
        val executor = Executors.newFixedThreadPool(4)
        try {
            val winners = executor.invokeAll((1..8).map { Callable { store.consume(id, expiry) } })
                .count { it.get() }
            assertEquals(1, winners)
            assertFalse(PostgresDemoStore.fromUrl(url).consume(id, expiry))
        } finally { executor.shutdownNow() }
    }
}
