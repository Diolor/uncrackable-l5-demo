package org.owasp.uncrackable.server

/** Diagnostic only: fetch and parse the live status feed once and print the outcome. */
fun main() {
    val t0 = System.nanoTime()
    try {
        val d = GoogleStatusFetcher().fetch()
        println("fetched ${d.body.length} chars, snapshot ttl ${d.maxAgeSeconds}s, in ${(System.nanoTime() - t0) / 1_000_000} ms")
        println("parsed ${Revocations.parse(d.body).size} listed serials")
    } catch (e: Throwable) { println("FAILED after ${(System.nanoTime() - t0) / 1_000_000} ms"); e.printStackTrace() }
}
