package org.owasp.uncrackable.server

import java.net.URI
import java.sql.Connection
import java.sql.DriverManager
import java.sql.Timestamp
import java.time.Instant
import java.util.Properties

/** Demo storage shared by every process; no in-memory or local-file replay fallback. */
class PostgresDemoStore(private val connect: () -> Connection) : ReplayStore {
    fun initialize() = connect().use { connection ->
        connection.createStatement().use {
            it.queryTimeout = 3
            it.execute("CREATE TABLE IF NOT EXISTS demo_used_challenges (id VARCHAR(64) PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL)")
            it.execute("CREATE TABLE IF NOT EXISTS demo_request_budget (minute BIGINT PRIMARY KEY, requests INTEGER NOT NULL)")
        }
    }

    override fun consume(id: String, expiresAt: Instant): Boolean = connect().use { connection ->
        require(id.matches(Regex("[0-9a-f]{64}")))
        connection.prepareStatement("INSERT INTO demo_used_challenges(id, expires_at) VALUES (?, ?) ON CONFLICT (id) DO NOTHING").use {
            it.queryTimeout = 3
            it.setString(1, id)
            it.setTimestamp(2, Timestamp.from(expiresAt))
            it.executeUpdate() == 1
        }
    }

    /** Global 60 requests/minute demo ceiling, independent of spoofable proxy headers. */
    fun allowRequest(): Boolean = connect().use { connection ->
        connection.createStatement().use {
            it.queryTimeout = 3
            it.executeQuery("""
                INSERT INTO demo_request_budget(minute, requests)
                VALUES (floor(extract(epoch FROM clock_timestamp()) / 60)::bigint, 1)
                ON CONFLICT (minute) DO UPDATE SET requests = demo_request_budget.requests + 1
                WHERE demo_request_budget.requests < 60
                RETURNING requests
            """.trimIndent()).use { result -> result.next() }
        }
    }

    companion object {
        /** External Render hostname with public PKI verification, even from the hosted service. */
        fun fromUrl(value: String): PostgresDemoStore {
            val uri = try { URI(value) } catch (_: Exception) { error("Invalid DEMO_DATABASE_URL") }
            require(uri.scheme == "postgresql" && uri.host?.endsWith(".render.com") == true &&
                uri.query == null && uri.fragment == null && uri.path.matches(Regex("/[a-zA-Z0-9_]+"))) {
                "Invalid DEMO_DATABASE_URL"
            }
            val credentials = uri.userInfo?.split(":", limit = 2)
            require(credentials?.size == 2) { "Invalid DEMO_DATABASE_URL credentials" }
            val props = Properties().apply {
                setProperty("user", credentials[0]); setProperty("password", credentials[1])
                setProperty("sslmode", "verify-full")
                setProperty("sslfactory", "org.postgresql.ssl.DefaultJavaSSLFactory")
                setProperty("connectTimeout", "3"); setProperty("socketTimeout", "5")
                setProperty("options", "-c statement_timeout=3000")
            }
            val jdbc = "jdbc:postgresql://${uri.host}:${if (uri.port == -1) 5432 else uri.port}${uri.path}"
            return PostgresDemoStore { DriverManager.getConnection(jdbc, props) }
        }
    }
}
