# UnCrackable L5 backend on Cloudflare Workers

TypeScript port of the Kotlin server in `../server/`, deployed at
`https://crackme.lorentzos.com` on the Workers Free plan. The wire protocol, error codes and
verification policy are unchanged; the verifier's behaviour is pinned to the Kotlin oracle by
`PARITY.md`. Design rationale is in `WORKERS_PLAN.md` (in `../server/`) and `../DESIGN.md`.

## Layout

```text
src/worker.ts        routes, body limits, challenge issue/verify, flag response
src/state.ts         single-instance Durable Object: replay table, request budget, revocation snapshot,
                     alarm-driven feed refresh (digest-gated: unchanged feeds rewrite no serial rows)
src/challenges.ts    challenge format byte-identical to Challenges.kt
src/revocations.ts   Google status feed parsing and snapshot lifetime rules
src/config.ts        startup validation (RuntimeConfig.kt equivalent), software-root rejection
src/verifier/        the attestation verifier port (see PARITY.md)
test/protocol.test.ts   workerd tests (vitest); test/parity/   oracle harness (Node)
spike/               phase 0 CPU measurement Worker, kept as the budget probe
```

## Commands

```bash
npm install
npm run typecheck
npm test                 # protocol tests inside workerd
npm run parity           # TypeScript vs Kotlin verdicts over ~8,400 cases (needs JDK 21)
npm run deploy           # wrangler deploy (custom domain and DO migration are in wrangler.jsonc)
```

Regenerate the synthetic parity corpus after changing Google's verifier or the fixtures:

```bash
PARITY_OUT=$PWD/test/parity/out/corpus.jsonl (cd .. && ./gradlew :server:runLocal -PlocalMain=org.owasp.uncrackable.server.ParityCorpusKt)
```

## Configuration

| Name | Kind | Value |
| --- | --- | --- |
| `CHALLENGE_HMAC_KEY` | secret | base64, at least 32 bytes; `wrangler secret put CHALLENGE_HMAC_KEY < keyfile` |
| `FLAG_TIER2` | secret | the flag; must equal the value served by the previous origin so published solves stay valid |
| `APP_PACKAGE` | var | `org.owasp.mastg.uncrackable5` (or `.debug` for a debug deployment) |
| `APP_SIGNER_SHA256` | var | from `../release/signer-sha256.txt` |
| `ATTESTATION_ROOTS` | bundled | `../server/roots/google-attestation-roots.pem`, imported at build time; an env override exists for tests only |

Secrets are never committed or echoed. The Worker refuses to serve when any value is missing
or malformed, and every response carries `Cache-Control: no-store`.

## Zone-side controls (owner, dashboard)

The wrangler OAuth token cannot edit WAF or notifications, so these are set once by hand:

1. **Rate limiting rule** (Security → WAF → Rate limiting rules, one rule is free):
   expression `http.host eq "crackme.lorentzos.com"`, 30 requests per 10 seconds per IP,
   action Block for 10 seconds. The Durable Object still enforces the global 60 per minute.
2. **Certificate Transparency Monitoring** (SSL/TLS → Edge Certificates): enable alerts.
   Universal SSL issues from Let's Encrypt or Google Trust Services, both pinned by the APK.
   If an alert shows a certificate from any other CA (a backup certificate deployed after a
   revocation event), toggle Universal SSL off and on to force reissue from LE/GTS. No APK
   change is needed; the outage lasts until reissue.
3. Keep the custom domain proxied (orange cloud); Workers custom domains require it.

Verify the served chain after any certificate change:

```bash
echo | openssl s_client -connect crackme.lorentzos.com:443 -servername crackme.lorentzos.com -showcerts 2>/dev/null | grep -E "^ [0-9] s:|^   i:"
```

The root must be ISRG Root X1/X2 or GTS Root R1–R4.

## Cutover checklist (Render → Workers)

1. `wrangler secret put FLAG_TIER2` with the value from the Render secret store.
2. Rebuild the APK with `crackmeReleaseBaseUrl=https://crackme.lorentzos.com` and the same
   signing key (`../scripts/release-signing.py`), refresh `../release/`.
3. Solve once on a real locked device against the new origin.
4. Keep Render alive until the new APK is published, then delete the Render service and
   database.
