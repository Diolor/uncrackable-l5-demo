# Temporary Render demo

This deployment uses a free Render web service and a free Postgres database in
Frankfurt. The database expires after 30 days. It is a device integration demo,
not the immutable release. Keep the workspace without a payment method to avoid
bandwidth overage billing. No Cloudflare or custom domain is configured yet.

The root Dockerfile builds only the server and launches `RenderDemoMainKt`.
The existing production `MainKt` remains the Firestore launcher. The demo accepts
only `org.owasp.mastg.uncrackable5.debug` with the configured debug signer and uses
the same verifier, live revocation feed, challenge authentication and flag policy.
It requires `DEMO_MODE=render-debug` and `DEMO-` prefixed synthetic flags.

Configure `CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_SIGNER_SHA256`,
`ATTESTATION_ROOTS`, and `DEMO_DATABASE_URL` as Render environment variables.
Never commit their secret values. Use the external Postgres URL: the adapter
requires TLS with hostname verification and the JVM's public trust store.
Restrict database external access to the service's outbound IP ranges and the
temporary validation workstation. Remove workstation access after testing.

Postgres stores challenge digests with a primary key and atomic insert-on-conflict.
Replay state survives web-service restarts. Database errors fail closed. A shared
global ceiling of 60 non-health requests per database minute bounds demo activity
without relying on forwarded IP headers. This is deliberately restrictive and
does not replace the production ingress-aware per-IP policy. Rows are retained
for the short demo; production lifecycle/cleanup is not implemented here.

Run `./gradlew -PserverOnly :server:test :server:installDist`. Set
`DEMO_DATABASE_URL` only for the optional live Postgres concurrency test; its absence
skips that test. The offline OnePlus fixture test is always included.

For device testing, warm `/v1/health` first (free services sleep), then build debug
with `-PcrackmeBaseUrl=https://<assigned-host>.onrender.com`. HTTPS debug requests
retain root pinning and platform trust checks. The release hostname and signer
are unchanged. Device acceptance, negative pinning tests, and durable replay
validation must be recorded separately; deployment alone proves none of these.

Implementation assistance: OpenAI Codex.
