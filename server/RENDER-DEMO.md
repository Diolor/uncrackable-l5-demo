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

## Recorded deployment and device validation — 2026-09-09

- Endpoint: <https://uncrackable-l5-demo.onrender.com>
- Private source: <https://github.com/Diolor/uncrackable-l5-demo>
- Render service: `srv-dagr5ouk1f9s73cmqj0g`, free, Frankfurt.
- Live deployment: `dep-dagr5pek1f9s73cmqkvg`, source `f9532bb`, live at 19:30:57 UTC.
- Postgres: `dpg-dagr1tepcuac73a9qs9g-a`, free, PostgreSQL 17; expires
  2026-10-09. External access is restricted to the service's observed shared
  outbound ranges `74.220.51.0/24` and `74.220.59.0/24`, explicitly approved
  for this demo. Workstation access has been removed.
- The presented TLS chain is `onrender.com` → GTS WE1 → cross-signed GTS Root R4.
  R4's SPKI matches the existing `sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=`
  pin. No pin or trust bypass was added.
- OnePlus 9 Pro (LE2123), Android 14, debug package and configured debug signer:
  ATTEST completed over the deployed HTTPS endpoint. At 19:31:18 UTC the backend
  logged `demo: evidence accepted tier=2`; the app displayed
  “Accepted — device and app fully verified.”
- The encrypted tier-2 record was replaced with a 90-byte record and survived
  an app force-stop/relaunch unchanged. No flag plaintext was displayed or logged.
- Live challenge issuance returned HTTP 200, a 76-character token, and
  `Cache-Control: no-store`. A malformed proof returned HTTP 403 with
  `attestation_invalid`. Health returned HTTP 200 (body `{}` with the current
  serializer's default-value omission).
- Before deployment: 29 server tests passed, including the live Postgres
  concurrent-insert/new-connection replay test; 8 Android unit tests passed.
  The container build reran offline server tests (live DB test skipped without
  credentials). Debug APK build and release Kotlin compilation passed.

This records a successful debug-device demo, not release-signing validation,
negative proxy/pinning tests, a captured-proof replay test against the hosted
endpoint, or a flag extraction solve. Cloudflare and custom-domain setup remain
the next phase. Auto-deploy is disabled; documentation commits do not redeploy.

## Prepared policy and release identity update

The updated source rejects unlocked or non-VERIFIED hardware boot evidence with
HTTP 403 `device_integrity`, without consuming the challenge or issuing either flag.
The legacy tier-one fallback is retired; successful responses retain tier 2.
The historical deployed debug test above predates this update.

The launcher now also supports `DEMO_MODE=render-release`, selecting the release
package with its separately configured signer digest. See
[release signing](../RELEASE-SIGNING.md) for local custody and the rollout procedure.
The keystore and passwords must never be sent to Render. A source/build check is
not evidence that the hosted service has been upgraded or a release device test passed.

## Mandatory boot gate deployed — 2026-09-09

- Deployment `dep-dagrj9142hec73epdq3g`, source `a16670e`, live at 19:59:30 UTC.
- The new hardware-enforced locked + VERIFIED requirement applies to every flag.
  Debug package/signer configuration remains active; release identity is prepared
  but has not been selected in the hosted environment.
- Container build completed successfully with server tests. After activation,
  HTTPS health and challenge returned HTTP 200; challenge was 76 characters with
  `Cache-Control: no-store`. Malformed attestation returned HTTP 403
  `attestation_invalid`, with no flag.
- Boot-state rejection is covered by the server regression suite. This deployment
  check is not a new physical-device or emulator attestation test.
