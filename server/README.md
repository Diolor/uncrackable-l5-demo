# Backend

Cloudflare Worker at `https://crackme.lorentzos.com` (Workers Free plan). One Worker handles
the protocol; one Durable Object holds the replay table, the global request budget and the
revocation snapshot.

```text
src/worker.ts        routes, body limits, challenge issue/verify, flag response
src/state.ts         Durable Object: replay table, request budget, revocation snapshot with alarm refresh
src/challenges.ts    challenge format: 1 | epochSeconds(8) | nonce(32) | HMAC-SHA256[0..16)
src/revocations.ts   Google attestation status feed parsing and snapshot lifetime
src/config.ts        startup validation; refuses to serve on missing or malformed values
src/verifier/        attestation verifier: strict DER, X.509 path building, KeyDescription, policy
roots/               Google's published attestation roots, bundled at build time
test/protocol.test.ts   end-to-end tests inside workerd (vitest)
test/corpus/            verifier regression corpus
```

## Commands

```sh
npm install
npm run typecheck
npm test            # protocol tests in workerd
npm run corpus      # verifier verdicts against the frozen corpus and recorded fixtures
npm run deploy      # custom domain and Durable Object migration are in wrangler.jsonc
```

## Configuration

| Name | Kind | Value |
| --- | --- | --- |
| `CHALLENGE_HMAC_KEY` | secret | base64, at least 32 bytes: `wrangler secret put CHALLENGE_HMAC_KEY < keyfile` |
| `FLAG_TIER2` | secret | the flag |
| `APP_PACKAGE` | var | `org.owasp.mastg.uncrackable5` (`.debug` for a debug deployment) |
| `APP_SIGNER_SHA256` | var | `../release/signer-sha256.txt` |
| `ATTESTATION_ROOTS` | env, tests only | PEM bundle overriding `roots/` |

Local development reads `.dev.vars` (ignored by Git). Every response carries
`Cache-Control: no-store`; the flag, challenge and chain are never logged.

## Zone controls set by hand

The wrangler token cannot edit these, so they are set once in the dashboard:

1. WAF rate limiting rule: `http.host eq "crackme.lorentzos.com"`, 10 requests per 10 seconds
   per IP, block for 10 seconds. The Durable Object still enforces 60 per minute globally.
2. Certificate Transparency monitoring alerts. Universal SSL issues from Let's Encrypt or
   Google Trust Services, both pinned by the APK. If an alert shows any other CA, toggle
   Universal SSL off and on to force reissue; the APK needs no change.
3. Keep the custom domain proxied.

```sh
echo | openssl s_client -connect crackme.lorentzos.com:443 -servername crackme.lorentzos.com -showcerts 2>/dev/null | grep -E "^ [0-9] s:|^   i:"
```

## Free-plan budgets

The Durable Object stores the revocation snapshot as one row (sorted serials joined by
newlines) because the free plan meters SQLite rows read and written per day. The feed has
about 1,700 serials; one row per serial cost thousands of writes per refresh and exhausted
the daily budget. An unchanged feed now rewrites one row every few minutes, and each
request reads one row. When the budget is exhausted the Worker fails closed with 503 until
the daily reset at 00:00 UTC.

## Verifier regression corpus

`src/verifier/` is a port of the verdict-deciding parts of Google's
[android-key-attestation](https://github.com/android/keyattestation) verifier. Its
behaviour was pinned once by running the reference verifier over the same cases; those
verdicts are frozen in `test/corpus/expected.tsv` and `npm run corpus` replays them
against the TypeScript port (no Kotlin is needed to run it):

- `test/corpus/corpus.jsonl`: 73 chains from Google's own test certificate factory.
- `test/corpus/cases.ts`: structural mutations built in TypeScript (malformed KeyDescription
  encodings, tag classes, RootOfTrust and AttestationApplicationId variants, chain shapes,
  distinguished-name canonicalisation, proof-of-possession encodings, serial forms, clock
  edges) plus single-byte corruptions of the synthetic leaf.
- Every recorded chain in `../fixtures/`: documented outcomes at capture time, and every
  single-byte corruption must be rejected cleanly.

Semantics pinned by cases that were not obvious from the reference:

- Two error classes in the extension parser: a failed attribute conversion nulls that
  attribute and a later constraint names it (`app_integrity` for a malformed
  `attestationApplicationId`); structural failures abort the parse (`attestation_invalid`).
- Explicit tagging only; duplicate tags, last wins. A critical attestation extension on the
  leaf counts as missing.
- Distinguished names compare like `X500Principal.equals`: RFC 2253 keyword attributes in
  PrintableString or UTF8String are normalised, everything else (including `serialNumber`
  and `title`) compares by exact DER bytes.
- TBS and outer signature algorithm identifiers must agree. The chain's root is never
  signature-checked, only matched against a configured anchor.
- Intermediate expiry is ignored on factory-provisioned chains and enforced on remotely
  provisioned ones; `notBefore` is always enforced; leaf validity is enforced by the server.
- Serials are unpadded lowercase hex. Base64 follows `java.util.Base64`.

One documented divergence: BER indefinite lengths inside the attestation extension are
accepted by BouncyCastle and rejected by this port (`kd-indefinite-length-ber`). KeyMint
emits DER, so no device is affected, and the divergence only ever rejects.
