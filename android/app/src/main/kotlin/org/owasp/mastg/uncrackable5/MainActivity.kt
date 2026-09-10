package org.owasp.mastg.uncrackable5

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** The single screen. The flag is never rendered; the launch Intent is ignored entirely. */
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
                    try {
                        FlagStore(context).store(outcome.tier, outcome.flag)
                    } catch (_: Exception) {
                        throw FlagStorageException()
                    } finally {
                        outcome.flag.fill(0)
                    }
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
}
