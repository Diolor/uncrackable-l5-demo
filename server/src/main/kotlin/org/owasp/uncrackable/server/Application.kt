package org.owasp.uncrackable.server

import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.util.concurrent.CancellationException

private const val MAX_BODY = 40 * 1024
private val protocolJson = Json { ignoreUnknownKeys = false; explicitNulls = false }

/** Injectable routes; public deployment additionally requires distributed ingress limits. */
fun Application.crackme(service: AttestationService) {
    install(ContentNegotiation) { json(protocolJson) }
    install(StatusPages) {
        exception<Rejected> { call, cause -> call.respond(HttpStatusCode.Forbidden, ErrorResponse(cause.code)) }
        exception<Unavailable> { call, _ -> call.respond(HttpStatusCode.ServiceUnavailable, ErrorResponse("verification_unavailable")) }
        exception<Exception> { call, cause ->
            if (cause is CancellationException) throw cause
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal_error"))
        }
    }
    intercept(ApplicationCallPipeline.Plugins) {
        call.response.header(HttpHeaders.CacheControl, "no-store")
    }
    routing {
        get("/v1/health") { call.respond(HealthResponse()) }
        get("/v1/challenge") { call.respond(service.challenge()) }
        post("/v1/attest") {
            if (call.request.contentType().withoutParameters() != ContentType.Application.Json) {
                call.respond(HttpStatusCode.UnsupportedMediaType, ErrorResponse("invalid_request")); return@post
            }
            // Bound the read itself; Content-Length alone does not cover chunked requests.
            val input = call.receiveChannel()
            val bytes = ByteArray(MAX_BODY + 1)
            var count = 0
            while (count < bytes.size) {
                val read = input.readAvailable(bytes, count, bytes.size - count)
                if (read == -1) break
                count += read
            }
            if (count > MAX_BODY) {
                input.cancel()
                call.respond(HttpStatusCode.PayloadTooLarge, ErrorResponse("request_too_large")); return@post
            }
            val request = try { protocolJson.decodeFromString<AttestRequest>(bytes.decodeToString(0, count, true)) }
                catch (_: SerializationException) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid_request")); return@post
                } catch (_: CharacterCodingException) {
                    call.respond(HttpStatusCode.BadRequest, ErrorResponse("invalid_request")); return@post
                }
            val result = withContext(Dispatchers.IO) { service.attest(request) }
            call.respond(result)
        }
    }
}
