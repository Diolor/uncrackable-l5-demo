# Hosted deployment

The backend baked into the published APK is `https://uncrackable-l5-demo.onrender.com`,
a Render web service with a Render Postgres database. The presented TLS chain terminates
in GTS Root R4, one of the six roots pinned by the client. No pin or trust bypass exists
on either side.

## Container

The root `Dockerfile` builds only the server (`-PserverOnly`), runs the server tests, and
launches `RenderDemoMainKt` on distroless Java 21 as a non-root user:

```sh
./gradlew -PserverOnly :server:test :server:installDist
docker build -t uncrackable-l5 .
```

`server/Dockerfile` is the equivalent recipe for the Firestore launcher (`MainKt`) on
Cloud Run; it copies a distribution built beforehand with `./gradlew :server:installDist`.
Resolve the base image to an approved immutable digest before relying on either image.

## Render launcher behaviour

- `DEMO_MODE=render-release` accepts only `org.owasp.mastg.uncrackable5` with the digest
  in `release/signer-sha256.txt`. `render-debug` accepts only the `.debug` package with a
  developer debug signer. The two are never combined.
- The same verifier, live Google revocation feed, challenge authentication and boot
  policy apply as in every other launcher.
- Postgres stores challenge digests with a primary key and atomic insert-on-conflict, so
  replay state survives service restarts. Database errors fail closed with 503.
- A shared global ceiling of 60 non-health requests per minute bounds activity without
  relying on spoofable forwarded IP headers. Excess requests receive 429 `rate_limited`.
- Free Render services sleep when idle. Warm `/v1/health` first if the first attempt
  reports no connection.

## Environment

Set these as Render environment variables from the public values in
`release/render-release.env.example` plus the private secrets. Never commit secret values.

| Variable | Notes |
| --- | --- |
| `DEMO_MODE` | `render-release` |
| `APP_SIGNER_SHA256` | `release/signer-sha256.txt` |
| `CHALLENGE_HMAC_KEY` | Secret |
| `FLAG_TIER1`, `FLAG_TIER2` | Secret; only tier 2 is ever issued |
| `ATTESTATION_ROOTS` | `server/roots/google-attestation-roots.pem`, fingerprints verified |
| `DEMO_DATABASE_URL` | External Postgres URL; the adapter requires TLS with hostname verification |

Restrict database external access to the service's outbound IP ranges.

## Validation on a real device

Deployment alone proves nothing. After each backend change, record separately:

- physical-device acceptance with the release APK (`Accepted — device and app fully verified.`);
- rejection of the debug package in release mode (`app_integrity`);
- a malformed proof returning 403 `attestation_invalid` with no flag;
- challenge responses carrying `Cache-Control: no-store`;
- negative pinning tests through a user-CA and a system-CA proxy.
