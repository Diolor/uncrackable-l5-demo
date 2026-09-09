package org.owasp.uncrackable.server

import com.google.cloud.firestore.FirestoreOptions
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import java.time.Clock

fun main() {
    val config = RuntimeConfig.load()
    val clock = Clock.systemUTC()
    val firestore = FirestoreOptions.newBuilder().setProjectId(config.projectId).build().service
    try {
        val service = AttestationService(
            Challenges(config.hmacKey, clock),
            AndroidVerifier(config.anchors, config.packageName, config.signer, clock,
                Revocations(clock, GoogleStatusFetcher())),
            FirestoreReplayStore(firestore), config.tier1, config.tier2,
        )
        embeddedServer(Netty, host = "0.0.0.0", port = config.port) {
            crackme(service)
        }.start(wait = true)
    } finally {
        firestore.close()
    }
}
