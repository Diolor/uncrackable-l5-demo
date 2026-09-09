package org.owasp.mastg.uncrackable5

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The single screen: title, brief, one ATTEST button and a status line. The flag is never rendered
 * in any state; success only confirms a tier. The launch Intent is ignored entirely: no extras,
 * data URI or action is read.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var attest: Button
    private val main = Handler(Looper.getMainLooper())
    private var worker: ExecutorService? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        attest = findViewById(R.id.attest)
        attest.setOnClickListener { runAttempt() }
        status.setText(R.string.status_idle)
        validateStoredRecords()
    }

    override fun onDestroy() {
        worker?.shutdownNow()
        worker = null
        super.onDestroy()
    }

    private fun executor(): ExecutorService =
        worker ?: Executors.newSingleThreadExecutor().also { worker = it }

    private fun runAttempt() {
        attest.isEnabled = false
        status.setText(R.string.status_in_flight)
        val context = applicationContext
        executor().execute {
            val result = try {
                val outcome = Backend(BuildConfig.BASE_URL, Attestation(context)).attest()
                if (outcome is AttestOutcome.Accepted) {
                    // Processed in memory, then persisted encrypted. store() zeroes the plaintext.
                    runCatching { FlagStore(context).store(outcome.tier, outcome.flag) }
                }
                Status.forOutcome(outcome)
            } catch (e: Throwable) {
                if (e is InterruptedException) return@execute
                Status.forFailure(e)
            }
            main.post {
                if (isDestroyed) return@post
                status.setText(result)
                attest.isEnabled = true
            }
        }
    }

    /**
     * Later local access: decrypt any stored records in process to confirm they still authenticate,
     * discarding corrupt ones. Plaintext is zeroed immediately. This neither displays anything nor
     * counts as attestation.
     */
    private fun validateStoredRecords() {
        val context = applicationContext
        executor().execute {
            val store = FlagStore(context)
            for (tier in store.storedTiers()) {
                runCatching { store.read(tier) }.getOrNull()?.fill(0)
            }
        }
    }
}
