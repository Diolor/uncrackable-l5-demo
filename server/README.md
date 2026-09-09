# Local backend milestone

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
- Revocation snapshots reject every listed serial, including SUSPENDED. They expire
  within five minutes or the origin's shorter max-age, accounting for Age. Missing,
  expired, malformed or unavailable status data prevents flag issuance with HTTP 503.
- Certificate time, challenge binding and proof of possession precede atomic replay
  consumption. Expiry is rechecked before and after the store operation.
- Only locked + Verified hardware boot evidence earns tier 2.
- HTTP bodies are bounded during reading, responses are not cacheable, and errors
  exclude proof material and flags. Logging of request/response bodies is not installed.

`crackme(service)` is the application factory. There is deliberately no production
launcher in this milestone: production must supply an atomic distributed
`ReplayStore`, explicit trusted roots, package/signer, secret material and the
`GoogleStatusFetcher`. The only in-memory replay implementation is in test sources.
Do not expose this composition publicly before adding ingress limits and deployment
configuration; no global rate limiter or production HTTP engine is wired yet.

## Trust and test limitations

The vendored verifier is pinned at `a48898a68337b920cbd368eab5824f696d7bbf3d`;
see [provenance](../third_party/android-keyattestation/UPSTREAM.md). It has Android-
specific chain validation, not arbitrary web PKI validation. Unknown authorization
tags are rejected (including legacy allApplications). The adapter adds leaf
validity checking and uses its own status loader because upstream filters REVOKED
only. Upstream source is unchanged; test factories are a separate test artifact.

Synthetic chains prove policy and protocol behavior, not actual hardware identity.
No real-device compatibility, live revocation fetch, Firestore atomicity, Android
storage or Flag 1/2 extraction has been demonstrated yet. These need integration
validation. Never trust the test root in a deployed service.

Next: production ReplayStore/runtime composition and a minimal Android attestation
client with captured real-device fixtures. Resolve hostname, signer custody and
cloud ownership before production provisioning/publication.
