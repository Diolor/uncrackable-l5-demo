# Backend runtime

## Run validation

Requires Java 21; the checksum-pinned Gradle wrapper downloads build dependencies.

```sh
./gradlew :server:test
```

Ktor's test host runs `/v1/challenge`, `/v1/attest` and `/v1/health` through the real
verifier adapter with synthetic signed chains. The tests require no Firebase
credentials, device, live status feed or production secret. Dependency versions
are recorded in Gradle lockfiles. Build downloads require network access once.

## Implemented boundaries

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
- Every flag requires locked + Verified hardware boot evidence. Otherwise return 403 `device_integrity`; never fall back to tier 1.
- HTTP bodies are bounded during reading, responses are not cacheable, and errors
  exclude proof material and flags. Logging of request/response bodies is not installed.

`crackme(service)` remains the injectable application factory. `MainKt` composes
Netty, explicit configuration, the Google HTTPS status fetcher and Firestore replay
storage. The only in-memory replay implementation is in test sources.

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

## Runtime and container

Build the distribution with Java 21:

```sh
./gradlew :server:test :server:installDist
docker build -f server/Dockerfile -t uncrackable-l5 .
```

The container copies only the distribution libraries and runs as a non-root user
on distroless Java 21. Resolve the base image to an approved immutable digest before
release. Container building requires Docker; Gradle validation alone does not test
container startup.

Cloud Run should inject numbered Secret Manager versions into these variables;
never put secret values in a Docker build argument, image, shell history or Git:

| Variable | Required format |
| --- | --- |
| `CHALLENGE_HMAC_KEY` | Standard Base64 encoding of at least 32 random bytes |
| `FLAG_TIER1`, `FLAG_TIER2` | Nonblank distinct flags |
| `APP_PACKAGE` | `org.owasp.mastg.uncrackable5` |
| `APP_SIGNER_SHA256` | Exactly 64 hexadecimal characters, no separators |
| `ATTESTATION_ROOTS` | Explicit PEM bundle of self-signed CA certificates |
| `GOOGLE_CLOUD_PROJECT` | Explicit Firestore project ID |
| `PORT` | Optional listen port, defaults to 8080 |

No trust roots, signer or flag defaults exist. Operators must verify the provenance
of the configured Android attestation roots; PEM validation does not establish that
Google owns a root. The production launcher rejects `FIRESTORE_EMULATOR_HOST`.
Configuration errors name only the setting, never its value. Application Default
Credentials use the attached dedicated runtime service account in Cloud Run.

Firestore uses the project's `(default)` database and `used_challenges` collection.
Each accepted proof calls document `create` with the SHA-256 challenge digest as ID
and a Timestamp `expireAt`. Only `ALREADY_EXISTS` means replay. A three-second wait
bounds the caller; every other error or uncertain result fails closed with 503.
A timed-out write can still commit, so clients must obtain a new challenge. TTL
cleanup never controls challenge validity. Configure Native-mode Firestore in the
service region, TTL on `expireAt`, deny-all client rules, and runtime IAM access to
data. IAM governs this server SDK; client security rules do not restrict it.

## Deployment gates

This runtime is **not ready for public exposure**. Still required:

- Ingress-aware distributed per-IP abuse limits, including a reviewed trusted-proxy
  boundary for Firebase Hosting and direct Cloud Run requests. Do not trust arbitrary
  forwarded headers or substitute an instance-local limiter.
- Cloud Run/Firebase deployment configuration, least-privilege secret access,
  structured verification outcome logging without proof/flag material, monitoring,
  budget alerts and an approved immutable container base digest.
- Emulator or isolated-project integration validation of Firestore concurrent creates,
  TTL field encoding and IAM failures. Unit tests cover adapter result mapping,
  timeouts and configuration rejection, not the live Google service.
- Physical-device fixtures and the release decisions in the plan.

No production resources or secrets are provisioned by the build.

## Trust and test limitations

The vendored verifier is pinned at `a48898a68337b920cbd368eab5824f696d7bbf3d`;
see [provenance](../third_party/android-keyattestation/UPSTREAM.md). It has Android-
specific chain validation, not arbitrary web PKI validation. Unknown authorization
tags are rejected (including legacy allApplications). The adapter adds leaf
validity checking and uses its own status loader because upstream filters REVOKED
only. Upstream source is unchanged; test factories are a separate test artifact.

Synthetic chains prove policy and protocol behavior, not actual hardware identity.
Real-device compatibility and the live revocation fetch were demonstrated on 2026-09-09
with a OnePlus 9 Pro (Android 14, TEE, locked, verified boot): tier 2 accepted, replay
and tampered proofs rejected, encrypted record written; see [`fixtures/`](../fixtures/README.md).
Firestore atomicity and Flag 1/2 extraction are not yet demonstrated. Never trust the
test root in a deployed service.

Next: distributed ingress limits and deployment configuration, followed by the
integration and device validation above. Resolve hostname, signer custody and
cloud ownership before production provisioning/publication.
