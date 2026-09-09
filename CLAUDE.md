# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## What this is

**Android UnCrackable L5** — a network-backed crackme for the OWASP MASTG crackme
catalogue. Unlike every existing Android crackme, the flag is **never present in the
APK**. It is issued over a pinned TLS channel by a backend that answers only a request
carrying a fresh, hardware-attested proof from an unmodified, correctly-signed build.

Full design rationale, decisions, and the intended solutions live in
[`UnCrackable-L5-Plan.md`](UnCrackable-L5-Plan.md). Read it before changing behaviour —
many things that look like bugs are deliberate and load-bearing.

This crackme is the hands-on companion to MASTG PR
[OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953) (`MASTG-BEST-0x01`
hardware-backed key attestation).

## Core invariants — do not break these

These properties are the crackme. A change that violates one silently ruins it.

1. **No flag values in the shipped APK.** No plaintext or encrypted flag payload is
   bundled in code, resources, assets or native libraries. The response model may declare
   `flag`; downloaded flags are processed at runtime and persisted. Keep flags out of UI
   and logs. Use AES-GCM storage with a separate persistent Android Keystore
   key; this does not prevent runtime extraction.
2. **TLS always fails closed.** No intentional retry downgrade, permissive trust manager,
   disabled hostname verification or pin removal. Repeated attempts preserve every check.
3. **Strict backend verification.** No deliberately weak randomness, replay handling,
   certificate validation or revocation bypass. Consume a challenge atomically only after
   all verification succeeds and immediately before issuing the flag.
4. **Freshness is required.** Server-issued single-use challenge, bound to attestation and
   proof of possession. This is not continuous process integrity or a universal anti-relay proof.
5. **Anti-repackaging via `attestationApplicationId`.** Check the sole package and exact
   expected signer set under the documented platform and attestation trust assumptions.
6. **Revocation is mandatory for both tiers.** Check the Google attestation status feed,
   reject every listed serial, and fail closed when no fresh valid snapshot is available.
7. **Flag 2 is open research.** No demonstrated bypass is required for release. Investigate
   attestation-to-use timing and post-attestation storage access without planting a weakness.
   Never advertise a proof of uncrackability or promise a leaked-keybox solution.

## Immutable-forever values (attested; cannot change after release)

- Package: `org.owasp.mastg.uncrackable5`, label `UnCrackable L5`, versionName `1.0`
- `minSdk = 28`, `targetSdk`/`compileSdk = 36`
- Signing key: **never rotate** (v3.1 rotation changes `attestationApplicationId`)
- Pinned roots: GTS Root R1–R4 + ISRG Root X1/X2 (roots only, OR-ed; never leaf/intermediate)
- Backend hostname (see release decisions below)

## Layout (target)

```
Uncrackable/
  app/          Kotlin Android client (Gradle)
  server/       Kotlin/Ktor backend (Gradle)
  infra/        gcloud deploy script or Terraform, firebase.json
  fixtures/     recorded attestation chains for server tests
  README.md     brief, hard requirements, flag SHA-256s, security assumptions and research status
  SOLUTION.md   the writeup required by the contributing terms
```

Git repository initialized.

- Source → `github.com/OWASP/mas-crackmes` at `Android/Level5/`. Committed: pins, backend
  URL, package name, signer digest. **Never committed:** keystore, `CHALLENGE_HMAC_KEY`, flags.
- Binary APK → `github.com/OWASP/mastg` at `Crackmes/Android/Level_05/`.

## Build order (why: the app is frozen last)

The APK is immutable once signed, and its pins can only be frozen once the live TLS chain
exists. Build in this order:

1. **Local server** (Ktor) with verification, revocation, challenge/replay handling and tests.
   Then add a minimal physical-device attestation client before production deployment.
2. **Deploy** to Cloud Run; wire Firebase Hosting `/v1/**` rewrite.
3. **Custom domain**: fix CAA records first (must allow `pki.goog` + `letsencrypt.org`),
   add domain in Firebase console, wait for managed cert. Confirm with
   `openssl s_client -connect <host>:443 -showcerts` that the live chain ends in a pinned root.
4. **Freeze the pin set**, then build, sign, and publish the APK.

## Firebase's actual role

Firebase Hosting is **only** a reverse proxy in front of Cloud Run (the `/v1/**` rewrite)
plus a static status `index.html`. It does **not** perform authentication. Auth is hardware
Key Attestation verified by the Ktor backend. Firebase App Check is deliberately **not** used
as a control (the app is not published on Play; direct attestation gives the required explicit policy).

Firebase project: `uncrackable-l5` (console.firebase.google.com/project/uncrackable-l5).

## Server secrets (Secret Manager, never in the image)

`CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_PACKAGE`, `APP_SIGNER_SHA256`,
`ATTESTATION_ROOTS` (PEM bundle). Use a dedicated runtime SA with `secretAccessor`, not the
default compute SA.

## Release decisions (not blockers for local implementation)

Tracked in the plan (section "Release decisions"): OWASP-controlled hostname vs.
personal `crackme.lorenzos.com`, GCP project/billing ownership transfer to OWASP, signing
keystore custody (≥2 custodians), MAS-team contact per
`docs/contributing/6_Add_a_Crackme.md`, and real MASTG ID allocation.

## Conventions

- Kotlin throughout (client and server). Server: Ktor 3.x / Java 21, distroless image.
- Client: OkHttp 4.12+, `CertificatePinner` (not a hand-rolled `X509TrustManager`) plus
  `network_security_config.xml` with `system`-only trust anchors, `cleartextTrafficPermitted=false`.
- Ship a **universal APK**, not an AAB, so the installed artefact is byte-identical to published.
- Server unit tests run against committed attestation-chain fixtures (no device needed).
- Markdown lint (shared MAS stack): `npx markdownlint-cli2 --config .markdownlint.jsonc`.

## Attribution for commits/PRs

- Commits end with: `Co-Authored-By: Claude <noreply@anthropic.com>`
- PR descriptions end with: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- Per OWASP MAS rules, **all PRs must disclose AI tool usage** — undisclosed use closes the PR.
