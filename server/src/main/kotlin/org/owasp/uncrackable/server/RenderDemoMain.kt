package org.owasp.uncrackable.server

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Clock

/** Explicit temporary demo entry point; production MainKt and release identity remain unchanged. */
fun main() {
    val env = System.getenv()
    val appPackage = when (env["DEMO_MODE"]) {
        "render-debug" -> "org.owasp.mastg.uncrackable5.debug"
        "render-release" -> "org.owasp.mastg.uncrackable5"
        else -> error("DEMO_MODE must be render-debug or render-release")
    }
    require(listOf("FLAG_TIER1", "FLAG_TIER2").all { env[it]?.startsWith("DEMO-") == true }) {
        "Demo flags must start with DEMO-"
    }
    // Reuse strict secret/root validation. This separate launcher selects one explicit demo app identity.
    val config = RuntimeConfig.load(env + mapOf(
        "GOOGLE_CLOUD_PROJECT" to "uncrackable-l5-demo",
        "APP_PACKAGE" to "org.owasp.mastg.uncrackable5",
    ))
    val store = PostgresDemoStore.fromUrl(requireNotNull(env["DEMO_DATABASE_URL"]) { "Missing DEMO_DATABASE_URL" })
    store.initialize()
    val clock = Clock.systemUTC()
    val verifier = AndroidVerifier(config.anchors, appPackage, config.signer,
        clock, Revocations(clock, GoogleStatusFetcher()))
    val loggedVerifier = AttestationEvidenceVerifier { request, challenge ->
        try {
            verifier.verify(request, challenge).also { println("demo: evidence accepted tier=$it") }
        } catch (e: Rejected) {
            println("demo: evidence rejected code=${e.code}"); throw e
        } catch (e: Unavailable) {
            println("demo: verification unavailable"); throw e
        }
    }
    val service = AttestationService(Challenges(config.hmacKey, clock), loggedVerifier, store, config.tier1, config.tier2)
    embeddedServer(Netty, host = "0.0.0.0", port = config.port) {
        crackme(service)
        intercept(ApplicationCallPipeline.Plugins) {
            if (call.request.path() != "/v1/health") {
                val allowed = try { withContext(Dispatchers.IO) { store.allowRequest() } }
                    catch (_: Exception) { throw Unavailable() }
                if (!allowed) {
                    call.respond(HttpStatusCode.TooManyRequests, ErrorResponse("rate_limited"))
                    finish()
                }
            }
        }
    }.start(wait = true)
}
