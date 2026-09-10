# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**Android UnCrackable L5**, a network-backed crackme for the OWASP MASTG catalogue. The flag
is never in the APK; a backend issues it over a pinned TLS channel only to a fresh,
hardware-attested proof from the genuine build on a locked, verified-boot device.
[`DESIGN.md`](DESIGN.md) explains each control; many things that look like bugs are
deliberate. Companion to [OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953).

## Invariants

1. **No flag values in the APK.** Downloaded flags are persisted AES-GCM encrypted under a
   hardware-backed Keystore key; never shown or logged.
2. **TLS fails closed.** No retry downgrade, permissive trust manager or pin removal.
3. **Strict verification.** No weak randomness, replay window, certificate or revocation
   bypass. Consume a challenge atomically only after every check passes.
4. **Freshness.** Server-issued single-use challenge bound to attestation and proof of
   possession.
5. **App identity** via `attestationApplicationId`: one package, exact signer.
6. **Revocation is mandatory.** Reject every listed serial; fail closed without a fresh feed.
7. **Every flag requires locked plus verified boot.** No lower tier.
8. **Extraction is open research.** Never advertise uncrackability, never plant a weakness.

## Immutable values (attested)

- Package `org.owasp.mastg.uncrackable5`, versionName `1.0`, `minSdk 28`, `targetSdk 36`.
- Signing key: never rotate. Digest in `release/signer-sha256.txt`.
- Pinned roots: GTS Root R1 to R4, ISRG Root X1/X2 (roots only, OR-ed).
- Backend origin `https://crackme.lorentzos.com` (Cloudflare Workers, `server/`).

## Layout

```text
android/    Kotlin Android client (Gradle project, module :app)
server/     Cloudflare Worker (TypeScript), verifier, tests, regression corpus
fixtures/   recorded attestation requests for the server tests
release/    signed APK, public certificate, signer digest, signing procedure
scripts/    release-signing.py (local key custody and signed build)
```

Never committed: keystore, `CHALLENGE_HMAC_KEY`, flags, hosting credentials, `.dev.vars`.
Any change under `server/src/verifier/` must keep `npm run corpus` green.

## Conventions

- Client: OkHttp `CertificatePinner` plus `network_security_config.xml` with system-only
  anchors and no cleartext. Ship a universal APK, not an AAB.
- Server tests run against synthetic chains and committed fixtures; no device needed.
- Markdown: `npx markdownlint-cli2 --config .markdownlint.jsonc`.
- Commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`; PR descriptions end
  with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. OWASP MAS
  requires disclosing AI tool usage in every PR.
