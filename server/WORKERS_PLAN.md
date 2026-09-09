# Cloudflare Workers backend: viability and migration plan

Status: draft for discussion, 2026-09-09. Nothing in this document is implemented.

Goal: run the UnCrackable L5 backend at zero recurring cost with a platform-enforced
spending cap, on a hostname under a domain we control, with a TLS chain that the shipped
APK's six pinned roots accept for the next decade, and with every core invariant in
`CLAUDE.md` preserved. The Kotlin/Ktor server stays as the reference implementation and
test oracle until the port has proven parity.

## 1. Verdict

Viable, with two conditions that must be proven by a one-day spike before committing to
the rewrite (section 8):

1. Full attestation verification of a four-certificate chain plus the proof of possession
   fits inside the Workers Free CPU budget of 10 ms per request.
2. The Google revocation feed (178 KB, 1,744 entries today) can be refreshed and parsed
   inside the same budget on a Durable Object alarm.

Both are expected to pass with margin (estimates in section 6), but they are measured,
not assumed.

## 2. Facts verified against Cloudflare documentation (September 2026)

| Item | Free plan | Consequence for us |
| --- | --- | --- |
| Worker requests | 100,000 per day, then error 1027 | Route set to _fail closed_; a flood takes the demo down, never bills |
| CPU time | 10 ms per HTTP request and per cron/alarm invocation | The hard engineering constraint (section 6) |
| Memory | 128 MB | Irrelevant at our sizes |
| Durable Objects | SQLite-backed only; 100,000 requests/day, 13,000 GB-s/day, storage billed only on paid plan | One DO holds all state; free plan is never charged for storage |
| Subrequests | 50 external per invocation | We make at most one (the feed) |
| Cron Triggers | 5 per account | Not needed; a DO alarm refreshes the feed |
| Secrets, Workers Logs | Included | Secrets via `wrangler secret`; logs retained 7 days |
| Universal SSL CA | Let's Encrypt or Google Trust Services only; Cloudflare chooses, customer cannot | Both chain to pinned roots (ISRG Root X1; GTS Root R1-R4) |
| Backup certificates | Pre-issued from a _different_ CA, may be Sectigo or SSL.com; deployed only on revocation or key compromise; Free plan cannot opt out | Residual risk, section 7 |
| CAA records | Adding any CAA record makes Cloudflare silently add records for all four partner CAs | CAA cannot be used to exclude Sectigo/SSL.com |
| Custom Domain | Requires an active Cloudflare zone (full setup: nameservers moved) | The parent domain's DNS moves to Cloudflare Free |
| Billing | A Free account with no payment method cannot be charged | The cap is structural, not a budget alert |

Design consequence: the immutable origin baked into the APK becomes a subdomain of our own
domain, never `*.workers.dev`. If Cloudflare ever becomes unsuitable, the same hostname is
re-pointed at the Kotlin server on any host with a Let's Encrypt or GTS certificate and no
APK change is needed. The APK is bound to a hostname and six roots, not to a vendor.

## 3. Target architecture

```text
Android app ──TLS (pinned roots)──▶ Cloudflare edge ──▶ Worker (TypeScript)
                                                          │
                                   ┌──────────────────────┴───────────────────────┐
                                   │ Durable Object "state" (single instance,      │
                                   │ SQLite): used_challenges, request_budget,     │
                                   │ revocation snapshot + alarm                   │
                                   └──────────────────────────────────────────────┘
                                                          │ alarm every ≤300 s
                                                          ▼
                                   https://android.googleapis.com/attestation/status
```

One Worker, one Durable Object class with exactly one named instance. A single-instance DO
is single-threaded, so "consume challenge atomically" and "global 60 requests per minute"
become ordinary SQL statements with no race window, which is stronger than the current
Postgres `ON CONFLICT` pattern and needs no external database.

### 3.1 Worker (stateless request handling)

Wire protocol is unchanged so the current APK protocol code is reused verbatim:

- `GET /v1/health`, `GET /v1/challenge`, `POST /v1/attest`; JSON bodies exactly as in
  `Protocol.kt`; error codes unchanged (`attestation_invalid`, `challenge_expired`,
  `challenge_replayed`, `device_integrity`, `app_integrity`,
  `no_hardware_attestation`, `verification_unavailable`, `invalid_request`,
  `request_too_large`, `internal_error`).
- `Cache-Control: no-store` on every response; 40 KB body cap enforced by reading the body
  through a bounded stream, not by trusting `Content-Length`.
- Challenge format byte-identical to `Challenges.kt` (version byte, 8-byte epoch seconds,
  32-byte nonce, 16-byte truncated HMAC-SHA256; 57 bytes, 76 chars base64url). HMAC via
  WebCrypto with the key imported once per isolate from the `CHALLENGE_HMAC_KEY` secret.
  Constant-time tag comparison.
- The three-point freshness check in `AttestationService.attest` is kept in the same order:
  verify challenge, verify attestation, re-verify challenge, consume in DO, re-verify.

### 3.2 Durable Object `State`

```sql
CREATE TABLE IF NOT EXISTS used_challenges (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS request_budget (minute INTEGER PRIMARY KEY, requests INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revocation_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);   -- fetched_at, expires_at
CREATE TABLE IF NOT EXISTS revoked_serials (serial TEXT PRIMARY KEY);              -- lowercase hex, no leading zeros
```

RPC methods (each is one billed DO request; three per attest attempt, one per challenge):

- `allowRequest(nowMinute)` → boolean. Same semantics as `PostgresDemoStore.allowRequest`.
- `consume(id, expiresAt)` → boolean. `INSERT OR IGNORE` and check `changes() == 1`.
  Expired rows are purged opportunistically on each call (`DELETE WHERE expires_at < now`).
- `isRevoked(serials[])` → boolean, plus `snapshotExpiresAt`. The Worker calls this twice,
  before and after verification, exactly as `AndroidVerifier.rejectListed` does today.
  If the snapshot is expired or absent the DO returns `unavailable` and the Worker fails
  closed with `verification_unavailable` (invariant 6).
- `alarm()`: fetch the feed with a 3 s timeout, no redirects, 4 MiB cap, then apply the
  same `snapshotTtl(Cache-Control, Age)` rule as `Revocations.kt` (never more than 300 s,
  never past the origin's remaining `max-age`). Replace `revoked_serials` in one
  transaction; write `expires_at`; reschedule the alarm at `min(expires_at - 30 s, 300 s)`.
  A failed fetch leaves the old snapshot in place until it expires, then requests fail
  closed. Every listed serial is rejected regardless of status, as today.

Storage stays in the kilobytes. Daily DO request volume at 100 solves/day is under 1,000.

### 3.3 Attestation verifier port (the real work)

Google's Kotlin verifier (`third_party/android-keyattestation`, 3,039 lines including CLI
and printers) is replaced by a TypeScript module with the same _observable_ behaviour for
this protocol's configuration. Scope, mapped from what `AndroidVerifier.kt` actually uses:

1. **DER parsing and strict re-encoding check.** Each chain element must be a single DER
   certificate whose re-encoding equals the input (rejects PEM, trailing bytes, BER).
   Library: `@peculiar/asn1-schema` + `@peculiar/asn1-x509` (pure JS, WebCrypto-friendly).
2. **Path building and validation.** Two to six certificates, leaf first. If the last
   element is not self-signed, append the unique configured Google root whose subject
   matches its issuer and whose key verifies it. Validate issuer/subject chaining,
   signatures (RSA PKCS#1 v1.5 SHA-256/384 and ECDSA P-256/P-384 via WebCrypto),
   `BasicConstraints`, `KeyUsage keyCertSign` on CAs, and validity of every certificate
   including the leaf (upstream skips the leaf; our server adds it).
3. **Attestation extension** (OID `1.3.6.1.4.1.11129.2.1.17`) on the leaf only:
   `attestationVersion`, `attestationSecurityLevel`, `keymintVersion`,
   `keymintSecurityLevel`, `attestationChallenge`, `uniqueId`, `softwareEnforced`,
   `hardwareEnforced`. Strict parser: unknown tags rejected, as upstream does.
4. **Constraints, identical to `ConstraintConfig` in `AndroidVerifier.kt`:**
   - Security level matches certificate (TEE or StrongBox, and both levels agree).
   - App identity: `attestationApplicationId` has exactly one package,
     `org.owasp.mastg.uncrackable5`, and the signer set equals the single expected digest.
   - Device integrity: `rootOfTrust.deviceLocked == true` and
     `verifiedBootState == VERIFIED`, hardware-enforced.
   - Signing key: purposes `{SIGN}`, algorithm EC, key size 256, curve P-256, digests
     `{SHA-256}`, all hardware-enforced.
   - Challenge equals the server-issued challenge bytes.
5. **Chain-structure rules from upstream** that matter for real devices: the root must be
   one of the configured anchors; intermediates carry Google's provisioning structure;
   an attestation extension anywhere but the leaf is rejected. Every rule ported is
   pinned by a fixture-driven test (section 5).
6. **Revocation:** every certificate's serial (hex, no leading zeros) is checked against
   the snapshot before and after validation.
7. **Proof of possession:** leaf public key must be P-256 on the exact standard curve;
   `ECDSA(SHA-256)` over the challenge bytes; signature accepted in DER form as now.
   WebCrypto expects raw r||s, so DER is decoded with strict length and canonical checks.

Constraint violation to error-code mapping is unchanged. No log line ever includes chain
material, challenge, or flag (invariant 1).

Deliberately out of scope: Play Integrity, software-level attestation, and the upstream
`GoogleRevocationList` helper (which filters REVOKED only and is not used today).

### 3.4 Configuration and secrets

| Name | Kind | Source |
| --- | --- | --- |
| `CHALLENGE_HMAC_KEY` | secret | `wrangler secret put`; never in the repo |
| `FLAG_TIER2` | secret | same (tier 1 is unused by the protocol; drop `FLAG_TIER1`) |
| `APP_PACKAGE`, `APP_SIGNER_SHA256` | var | public values from `release/` |
| `ATTESTATION_ROOTS` | bundled | `server/roots/google-attestation-roots.pem` imported at build time |

Startup validation mirrors `RuntimeConfig.kt`: refuse to serve if any value is missing or
malformed. Secrets are never echoed in errors.

### 3.5 Abuse controls at zero cost

- Global 60 requests per minute in the DO (existing semantics).
- One free WAF rate-limiting rule on the zone in front of the Worker, keyed by IP, so a
  single flood does not burn the 100,000/day allowance in seconds.
- Route fail mode: closed. Over quota the client sees a TLS-valid Cloudflare error, never
  a bypass.

## 4. Repository layout after the port

```text
server/            Kotlin reference server (kept; CI still runs its tests)
server-worker/     TypeScript Worker + Durable Object
  src/verifier/    ASN.1, X.509 path, attestation extension, constraints, PoP
  src/worker.ts    routes, body limits, challenge issue/verify, flag response
  src/state.ts     Durable Object class
  test/            vitest under @cloudflare/vitest-pool-workers (runs in workerd)
  wrangler.jsonc   bindings, DO migration (new_sqlite_classes), route, limits
```

## 5. Test strategy: prove parity before cutover

1. **Fixture parity.** Every recorded chain in `fixtures/` is fed to both the Kotlin
   verifier and the TypeScript verifier; verdict and error code must match.
2. **Mutation parity.** A generator produces hundreds of variants from each fixture:
   truncated DER, trailing bytes, PEM wrapped, reordered chain, dropped intermediate,
   swapped root, expired leaf, wrong challenge, bad PoP, non-canonical DER signature,
   `deviceLocked=false`, `verifiedBootState=UNVERIFIED`, software security level, two
   packages in `attestationApplicationId`, wrong signer digest, extra unknown
   authorization tag, revoked serial. Both implementations must agree on every variant.
   Disagreements are investigated one by one; the Kotlin verdict is authoritative unless
   the upstream behaviour is shown to be a bug.
3. **Protocol tests** in workerd: replay rejected, expiry boundaries at 120 s, body cap,
   content-type, rate budget, revocation snapshot absent → 503, snapshot present → normal.
4. **CPU budget test** in CI: assert median CPU time per attest under 6 ms on the fixture
   chain using `performance.now()` inside the runtime, so a regression cannot ship silently.
5. **Real-device acceptance** on the current test device against the Worker at the new
   hostname, using a debug build pointed at it via `crackmeReleaseBaseUrl`.

## 6. Estimated CPU cost per attest (to be measured in the spike)

| Step | Estimate |
| --- | --- |
| JSON parse + base64 decode of four certificates (3.5 KB) | < 0.5 ms |
| DER parse of four certificates + re-encode check | 1 to 2 ms |
| Four signature verifications (WebCrypto, native) | ~1 ms |
| Attestation extension parse + constraints | < 0.5 ms |
| HMAC, SHA-256 id, ECDSA PoP verify | < 0.5 ms |
| Three DO round trips (network wait, not CPU) | 0 ms CPU |
| **Total** | **3 to 5 ms** against a 10 ms limit |

Revocation refresh on the alarm: streaming `JSON.parse` of 178 KB with 1,744 entries is
about 2 to 4 ms, then one SQLite transaction with a batched multi-row insert. If the feed
grows past roughly 1 MB in future years, the alarm switches to incremental parsing across
two invocations; that is a contained change.

### 6.1 Phase 0 measurement (2026-09-10, deployed to workers.dev, Free plan)

Spike code: `server-worker/spike/` (minimal DER walk, WebCrypto verification of all four
chain signatures including the root self-signature, plus the ECDSA proof of possession
over the recorded OnePlus 9 Pro fixture). CPU figures are `cpuTime` from `wrangler tail`,
which reports whole milliseconds.

| Route | What it does | CPU per request (ms) |
| --- | --- | --- |
| `/noop` | JSON response only | 0, 0, 0, 0, 0, 0 |
| `/parse` | parse 4 certs, import 4 keys (incl. RSA-4096, P-384) | 2, 2, 0, 1, 1 |
| `/attest` | parse + 4 signature verifications + PoP | 5, 3, 6, 3, 2, 2, 3, 6, 3, 6, 4, 3 (median 3, max 6) |
| `/attest?n=20` | 20 full verifications in one request | 30 (about 1.5 ms marginal per verification) |
| `/feed` | fetch + parse the live revocation feed (178,043 bytes, 1,746 entries) | 1, 3 |

Node 26 on the same code: 0.92 ms CPU per verification, verdicts correct, tampered PoP rejected.

Conclusions: a full attest costs a median 3 ms and a worst observed 6 ms against the
10 ms limit, leaving room for attestation-extension parsing, HMAC and the DO round
trips (which cost no CPU). The 30 ms request was not terminated, so enforcement has
slack beyond the documented figure, but the design still targets under 6 ms median.
Revocation-feed refresh in the DO alarm is well inside budget. **Phase 0 passes; the port proceeds.**

Side findings: the Free plan rejects `limits.cpu_ms` in `wrangler.jsonc`; the first
deploy auto-registered the account's workers.dev subdomain as `uncrackable-l5-spike`
(cosmetic, changeable in the dashboard, irrelevant once the custom domain is used);
the spike normalises serials as raw hex (`01`), while the Kotlin oracle uses
`BigInteger.toString(16)` (`1`). The port must match the oracle's form for the revocation lookup.

## 7. Risks and mitigations

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| Backup certificate from Sectigo or SSL.com deployed after a Cloudflare key-compromise event; every phone fails pinning | Low | Enable free Certificate Transparency Monitoring on the zone; on alert, toggle Universal SSL off and on to force reissue from LE/GTS; document the runbook. The outage is recoverable within an hour and needs no APK change. |
| Cloudflare changes Universal SSL CA set in the future | Low, slow-moving | Same runbook; worst case move the hostname to any host using LE/GTS (no APK change). |
| CPU limit exceeded on real chains | Low (measured, section 6.1) | Spike first (section 8); optimise DER parsing; the 10 ms limit has runtime slack for occasional overruns. |
| Port diverges from Google's verifier on a chain shape we have not recorded | Medium | Record more fixtures from different vendors before cutover; keep the Kotlin oracle in CI forever. |
| Free plan limits reduced | Low | Daily quota is 100 times what a crackme needs; re-hosting path exists. |
| Zone prerequisites | Verified 2026-09-10 | `lorentzos.com` is already a full-setup, active Free zone in the wrangler account (Cloudflare nameservers live, no CAA record, no existing `crackme` record). No nameserver move is needed. |

## 8. Phases

| Phase | Work | Exit criterion |
| --- | --- | --- |
| 0. Spike (done 2026-09-10) | Minimal Worker that parses the fixture chain, verifies four signatures and the PoP with WebCrypto, measures CPU; parse the live feed and measure | Passed: median 3 ms, max 6 ms per attest; feed 1 to 3 ms (section 6.1) |
| 1. Verifier port (done 2026-09-10) | `server-worker/src/verifier/` + `test/parity/` harness | 8,443 cases, zero unexplained disagreements; one documented reject-only divergence (`server-worker/PARITY.md`) |
| 2. Service glue (done 2026-09-10) | `worker.ts`, `state.ts`, `challenges.ts`, `revocations.ts`, `config.ts`, `wrangler.jsonc`, 13 workerd tests | Protocol suite green |
| 3. Zone and deploy (deployed 2026-09-10) | Live at `https://crackme.lorentzos.com`; served chain is GTS WE1 → GTS Root R4 (pinned). Secrets set: fresh `CHALLENGE_HMAC_KEY`, placeholder `FLAG_TIER2`. Open owner steps: WAF rate rule and CT monitoring (dashboard; token lacks the scope), real `FLAG_TIER2` | Real-device solve succeeds against the new hostname (pending device) |
| 4. APK re-release (blocked on keystore custody) | Gradle default already points at the new origin; rebuild with the same signing key, refresh `release/` | Published APK solves against the new origin |
| 5. Retire Render | Keep Render up until the new APK is published, then delete the service and database | Only one production origin remains |

## 9. Decisions (taken 2026-09-10)

1. Subdomain baked into the next APK: `https://crackme.lorentzos.com` (immutable once released).
2. Parent zone `lorentzos.com` is already on Cloudflare Free with full setup; nothing to move.
3. The Kotlin server stays as the test oracle for now; it may be deleted after cutover.

## 10. Inputs still needed from the owner before cutover

- `FLAG_TIER2`: the current value from the Render secret store, so already-published solves stay valid. Only the owner can read it; it is set with `wrangler secret put`, never committed.
- `CHALLENGE_HMAC_KEY`: a fresh random key is fine; challenges are short-lived and never cross the cutover.
- Signing keystore custody for phase 4 (`scripts/release-signing.py`), since the APK must be rebuilt with the same key.
- More recorded attestation fixtures if available; only `oneplus9pro-android14-tee-tier2.json` exists today.
