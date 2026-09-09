# Backend

## Run validation

Requires Java 21; the checksum-pinned Gradle wrapper downloads build dependencies.

```sh
./gradlew :server:test
```

Ktor's test host runs `/v1/challenge`, `/v1/attest` and `/v1/health` through the real
verifier adapter with synthetic signed chains, plus the recorded real-device chain in
[`fixtures/`](../fixtures/README.md). The tests require no credentials, device, live
status feed or production secret. Dependency versions are recorded in Gradle lockfiles.
The optional live Postgres concurrency test runs only when `DEMO_DATABASE_URL` is set.

## Enforced boundaries

- Canonical 57-byte HMAC-authenticated challenges expire at 120 seconds.
- Google's pinned Android verifier handles certificate chains and attestation parsing.
- The adapter requires hardware security, package/signer identity and P-256 signing properties.
- Revocation snapshots reject every listed serial, including SUSPENDED. A snapshot is
  reused for at most five minutes and never past the origin's remaining `max-age`
  (its `max-age` minus any CDN `Age`). Google serves the feed with a 24-hour `max-age`
  through a cache, so a copy that is hours old is still valid by the origin's policy.
  Missing, expired, malformed or unavailable status data prevents flag issuance with HTTP 503.
- Certificate time, challenge binding and proof of possession precede atomic replay
  consumption. Expiry is rechecked before and after the store operation.
- Every flag requires locked + Verified hardware boot evidence. Otherwise the server
  returns 403 `device_integrity`; there is no tier-one fallback.
- HTTP bodies are bounded during reading, responses are not cacheable, and errors
  exclude proof material and flags. Request and response bodies are never logged.

`crackme(service)` is the injectable application factory. Two launchers compose it:

| Launcher | Replay store | Used by |
| --- | --- | --- |
| `RenderDemoMainKt` | Postgres, insert-on-conflict | The hosted deployment, see [DEPLOYMENT.md](DEPLOYMENT.md) |
| `MainKt` | Firestore, create-if-absent | Cloud Run alternative, `server/Dockerfile` |

The only in-memory replay implementation is in test sources.

## Local device integration

`LocalMain.kt` (test sources only) runs the production verifier, revocation cache and
challenge code on loopback with an in-memory replay store, a random per-run HMAC key
and synthetic flags. It accepts the debug client's package and signer. The Google
attestation roots it loads by default are in [`roots/`](roots/README.md); verify their
fingerprints before use.

```sh
SIGNER=$(keytool -list -v -keystore ~/.android/debug.keystore -storepass android \
  | awk '/SHA256:/ {gsub(":","",$2); print tolower($2)}')
LOCAL_APP_SIGNER_SHA256=$SIGNER LOCAL_RECORD_DIR=fixtures/local ./gradlew :server:runLocal
adb reverse tcp:8080 tcp:8080
./gradlew :app:installDebug -PcrackmeBaseUrl=http://127.0.0.1:8080
```

`LOCAL_RECORD_DIR` writes every received `/v1/attest` body (chain, challenge, proof) as a
JSON file so real-device chains can be turned into committed test fixtures. Outcomes and
rejection codes are printed; proof material is not. The launcher is never part of the
runtime distribution or container.

## Configuration

Inject these as environment variables from the host's secret store. Never put secret
values in a Docker build argument, image, shell history or Git.

| Variable | Required format |
| --- | --- |
| `CHALLENGE_HMAC_KEY` | Standard Base64 encoding of at least 32 random bytes |
| `FLAG_TIER1`, `FLAG_TIER2` | Nonblank distinct flags; `FLAG_TIER1` is reserved and never issued |
| `APP_PACKAGE` | `org.owasp.mastg.uncrackable5` (Firestore launcher) |
| `DEMO_MODE` | `render-release` or `render-debug` (Render launcher; selects the package) |
| `APP_SIGNER_SHA256` | Exactly 64 hexadecimal characters, no separators |
| `ATTESTATION_ROOTS` | Explicit PEM bundle of self-signed CA certificates |
| `DEMO_DATABASE_URL` | Postgres URL over TLS (Render launcher) |
| `GOOGLE_CLOUD_PROJECT` | Firestore project ID (Firestore launcher) |
| `PORT` | Optional listen port |

No trust roots, signer or flag defaults exist. Operators must verify the provenance
of the configured Android attestation roots; PEM validation does not establish that
Google owns a root. Configuration errors name only the setting, never its value.

### Firestore launcher notes

Firestore uses the project's `(default)` database and `used_challenges` collection.
Each accepted proof calls document `create` with the SHA-256 challenge digest as ID
and a Timestamp `expireAt`. Only `ALREADY_EXISTS` means replay. A three-second wait
bounds the caller; every other error or uncertain result fails closed with 503.
A timed-out write can still commit, so clients must obtain a new challenge. TTL
cleanup never controls challenge validity. Configure Native-mode Firestore in the
service region, TTL on `expireAt`, deny-all client rules, and runtime IAM access to
data. The production launcher rejects `FIRESTORE_EMULATOR_HOST`.

## Known limitations

- Abuse limiting is a shared global request ceiling in the Render launcher, not an
  ingress-aware per-IP policy. It deliberately ignores forwarded headers, which are
  spoofable without a reviewed trusted-proxy boundary.
- Structured outcome logging, monitoring and budget alerting are host-level concerns not
  provided by this code.
- Firestore concurrent-create behaviour is covered by unit tests of the adapter's result
  mapping, not by tests against the live Google service.

## Trust and test limitations

The vendored verifier is pinned at `a48898a68337b920cbd368eab5824f696d7bbf3d`;
see [provenance](../third_party/android-keyattestation/UPSTREAM.md). It has Android-
specific chain validation, not arbitrary web PKI validation. Unknown authorization
tags are rejected (including legacy allApplications). The adapter adds leaf
validity checking and uses its own status loader because upstream filters REVOKED
only. Upstream source is unchanged; test factories are a separate test artifact.

Synthetic chains prove policy and protocol behaviour, not actual hardware identity.
Real-device compatibility and the live revocation fetch were demonstrated with a
OnePlus 9 Pro (Android 14, TEE, locked, verified boot): tier 2 accepted, replay and
tampered proofs rejected, encrypted record written. Never trust the test root in a
deployed service.
