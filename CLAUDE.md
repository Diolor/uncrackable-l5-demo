# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this is

**Android UnCrackable L5** — a network-backed crackme for the OWASP MASTG crackme
catalogue. Unlike every other Android crackme, the flag is **never present in the APK**.
It is issued over a pinned TLS channel by a backend that answers only a request carrying a
fresh, hardware-attested proof from an unmodified, correctly-signed build on a locked,
verified-boot device.

Design rationale and the reasoning behind each control live in [`DESIGN.md`](DESIGN.md).
Read it before changing behaviour — many things that look like bugs are deliberate and
load-bearing.

This crackme is the hands-on companion to MASTG PR
[OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953) (hardware-backed key
attestation best practice).

## Core invariants — do not break these

These properties are the crackme. A change that violates one silently ruins it.

1. **No flag values in the shipped APK.** No plaintext or encrypted flag payload is
   bundled in code, resources, assets or native libraries. The response model may declare
   `flag`; downloaded flags are processed at runtime and persisted with AES-GCM under a
   separate hardware-backed Android Keystore key. Keep flags out of UI and logs.
2. **TLS always fails closed.** No retry downgrade, permissive trust manager, disabled
   hostname verification or pin removal. Repeated attempts preserve every check.
3. **Strict backend verification.** No weak randomness, replay handling, certificate
   validation or revocation bypass. Consume a challenge atomically only after all
   verification succeeds and immediately before issuing the flag.
4. **Freshness is required.** Server-issued single-use challenge, bound to attestation and
   proof of possession. This is not continuous process integrity or a universal anti-relay proof.
5. **Anti-repackaging via `attestationApplicationId`.** Check the sole package and exact
   expected signer set under the documented platform and attestation trust assumptions.
6. **Revocation is mandatory.** Check the Google attestation status feed, reject every
   listed serial, and fail closed when no fresh valid snapshot is available.
7. **Every flag requires hardware-enforced locked + Verified boot.** No tier-one fallback.
8. **Flag extraction is open research.** No demonstrated bypass is required. Investigate
   attestation-to-use timing and post-attestation storage access without planting a weakness.
   Never advertise a proof of uncrackability.

## Immutable values (attested; cannot change after release)

- Package: `org.owasp.mastg.uncrackable5`, label `UnCrackable L5`, versionName `1.0`
- `minSdk = 28`, `targetSdk`/`compileSdk = 36`
- Signing key: **never rotate** (v3.1 rotation changes `attestationApplicationId`)
- Pinned roots: GTS Root R1–R4 + ISRG Root X1/X2 (roots only, OR-ed; never leaf/intermediate)
- Backend origin: `https://uncrackable-l5-demo.onrender.com`

## Layout

```text
Uncrackable/
  Mobile app/   Kotlin Android client (Gradle module :app)
  server/       Kotlin/Ktor backend (Gradle), DEPLOYMENT.md
  third_party/  Google's Android key attestation verifier, pinned revision
  fixtures/     recorded attestation chains for server tests
  release/      signed APK, public signing certificate, signer digest
  scripts/      release-signing.py (local key custody and signed build)
  DESIGN.md     design rationale
  README.md     brief, hard requirements, download, security assumptions
  SOLUTION.md   research status and what counts as a solve
```

Committed: pins, backend origin, package name, signer digest, public certificate.
**Never committed:** keystore, `CHALLENGE_HMAC_KEY`, flags, hosting credentials.

## Server secrets (host secret store, never in the image)

`CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_SIGNER_SHA256`,
`ATTESTATION_ROOTS` (PEM bundle), `DEMO_DATABASE_URL`. See `server/README.md`.

## Conventions

- Kotlin throughout (client and server). Server: Ktor 3.x / Java 21, distroless image.
- Client: OkHttp `CertificatePinner` (not a hand-rolled `X509TrustManager`) plus
  `network_security_config.xml` with `system`-only trust anchors, `cleartextTrafficPermitted=false`.
- Ship a **universal APK**, not an AAB, so the installed artefact is byte-identical to published.
- Server unit tests run against committed attestation-chain fixtures (no device needed).
- Markdown lint (shared MAS stack): `npx markdownlint-cli2 --config .markdownlint.jsonc`.

## Attribution for commits/PRs

- Commits end with: `Co-Authored-By: Claude <noreply@anthropic.com>`
- PR descriptions end with: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- Per OWASP MAS rules, **all PRs must disclose AI tool usage** — undisclosed use closes the PR.
