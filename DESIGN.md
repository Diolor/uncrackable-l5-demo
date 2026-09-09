# Android UnCrackable L5 — Design

## Why this crackme exists

Every earlier Android crackme in the MAS catalogue is fully offline: the flag is inside the
APK and the challenge is pure reverse engineering. Nothing in the catalogue exercises the
two controls modern apps lean on to protect a secret that is provisioned only after server
verification: hardware-backed **device and app attestation**, and **TLS certificate
pinning**. This crackme turns the MASTG guidance on hardware-backed key attestation
([OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953)) into something a reader can
attack.

**Outcome:** a crackme whose flag is never present in the APK. It is issued over the
network by a backend that answers only a request carrying a fresh, hardware-attested proof
from an unmodified, correctly-signed build; and the app only talks to that backend over a
pinned channel. Solving it requires runtime instrumentation of the genuine binary.
Ordinary re-signing is rejected under the stated platform and attestation trust assumptions.

## Design rationale

### Key attestation, not Play Integrity or Firebase App Check

The APK is distributed from GitHub and not published on Play. An app never published on
Play cannot receive `PLAY_RECOGNIZED`, so Play Integrity would not give an explicit app
identity verdict. Direct Key Attestation verification gives explicit package/signer and
boot-state policies without a Play publication dependency and without any Firebase or GMS
SDK in the client.

Hardware Key Attestation yields both halves in one artefact: `attestationApplicationId`
carries app identity (package plus signing certificate SHA-256) and `rootOfTrust` carries
device state (`verifiedBootState`, `deviceLocked`). Firebase App Check is the
production-recommended alternative and is documented as such on the crackme page, but it
is not used as a control here.

### Freshness and the limits of attestation

A server-issued, expiring, single-use challenge is bound to both the attestation and the
proof of possession. No missing challenge, replay window or driveable exported attester is
planted. These controls resist stale proofs and straightforward relay attempts; they are
not a general proof that every relay or runtime compromise is impossible.

Attestation reports properties at key creation. It is not continuous monitoring of the app
process. The time between key creation, server verification, flag delivery and later local
decryption is a research surface. Checks are not weakened to make it exploitable.

### Security boundary and intended solutions

There is **no intentional client TLS defect**. Certificate validation, hostname
verification and pinning fail closed on every attempt, and repeated failures never weaken
these controls. The challenge is extracting a server-provisioned flag from the genuine app
at runtime.

The backend validates certificate trust, revocation, challenge freshness, key possession,
app identity and device state. There are no intentionally omitted security checks.

### Mandatory device gate

Every issued flag requires fresh trusted hardware attestation, live revocation checks,
matching package/signer, proof of possession, and hardware-enforced
`deviceLocked == true` AND `verifiedBootState == VERIFIED`. Unlocked, self-signed,
unverified, failed or missing hardware boot evidence releases no flag. Successful responses
carry `tier: 2`; `FLAG_TIER1` is a reserved configuration value that is never issued.

A stock locked device may receive the flag. Receiving it is not solving extraction. Boot
attestation describes key-creation state, not continuous runtime integrity.

## Client

**Identity (immutable, because it is attested):** package `org.owasp.mastg.uncrackable5`,
label `UnCrackable L5`, versionName `1.0`. `minSdk = 28` (StrongBox API without
reflection; reliable `attestationApplicationId` population), `targetSdk`/`compileSdk = 36`.
The signing key is never rotated: APK Signature Scheme v3.1 rotation changes what lands in
`attestationApplicationId`.

**Attestation key.** Per attempt, a throwaway EC P-256 signing key in `AndroidKeyStore`
under a random alias, deleted in a `finally` block:

```kotlin
KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameter(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(challenge)          // server-issued, per request
    .setKeyValidityEnd(Date(now + 5 * 60_000))
    .apply { if (strongBox) setIsStrongBoxBacked(true) }
    .build()
```

StrongBox first; on `StrongBoxUnavailableException` or a bare `ProviderException`
(several OEMs throw the latter, some only at `generateKeyPair()`), delete the partial alias
and retry without. StrongBox absence is not a failure; the server accepts
`TrustedEnvironment`.

The chain comes from `KeyStore.getCertificateChain(alias)`, each element Base64(DER). The
client also signs the challenge with the fresh key and sends it as proof of possession.

**Protocol.**

```text
GET  /v1/challenge  -> {"challenge":"<b64url 57B>","expiresIn":120}
POST /v1/attest     <- {"challenge":..,"chain":[..],"pop":..}
                    -> 200 {"tier":2, "flag":"..."}
                    -> 403 {"error":"device_integrity"}       // bootloader not locked and verified
                    -> 403 {"error":"app_integrity"           // signer digest mismatch
                                  | "no_hardware_attestation" // Software level / emulator
                                  | "challenge_expired"
                                  | "challenge_replayed"
                                  | "attestation_invalid"}    // chain / revocation / PoP / key props
                    -> 503 {"error":"verification_unavailable"} // status feed or replay store unavailable
GET  /v1/health     -> {"status":"ok"}
```

### Flag lifecycle and local storage

Neither flag value is embedded in the shipped APK, including resources, native libraries,
assets, or a bundled encrypted copy. The client response model declares a `flag` field and
handles downloaded flags; that is allowed.

After successful attestation, the client receives the flag in memory and persists it
locally. The UI shows only the accepted tier. Flags are never written to logs, clipboard,
analytics, HTTP caches or plaintext temporary files.

**Storage design.** Downloaded flags are encrypted with `AES/GCM/NoPadding` under a
persistent per-installation AES-256 key generated in `AndroidKeyStore`. This is a separate
key from the per-attempt attestation signing key, which is still deleted after each attempt.
The AES key must be hardware-backed on creation and on every load: on API 31+ only
StrongBox or Trusted Environment from `KeyInfo` is accepted, and on API 28–30
`isInsideSecureHardware` is required. Software or unknown levels are rejected without
encrypting or decrypting; rejected keys and their cached records are discarded. Failure to
inspect key metadata fails closed. A bundled or exported key is never substituted.
Storage failures show a secure-storage failure status instead of acceptance.

Every encryption uses a fresh provider-generated IV and a 128-bit authentication tag. A
record holds a version, IV and ciphertext/tag in app-private `noBackupFilesDir`, with the
tier and format version bound as authenticated additional data. One record per tier,
replaced atomically after successful encryption.

The shipped app never decrypts a record on its own; the only in-process plaintext exists
while an accepted response is being encrypted. `FlagStore.read` remains available for
research and tooling. Missing or invalidated keys and corrupt records cause the local record
to be discarded and require fresh online attestation; there is no plaintext fallback. A
cached record is a previously issued flag, not proof of current device integrity, and never
satisfies a new ATTEST operation.

Encryption protects stored bytes. Instrumentation in the authorised app process can still
observe plaintext or invoke the key. This is the intended extraction surface, not a promise
that a runtime secret is impossible to recover. Copying ciphertext alone does not reveal it.

References: [Android cryptography](https://developer.android.com/privacy-and-security/cryptography)
and [Android Keystore](https://developer.android.com/privacy-and-security/keystore).

### Pinning, two layers

- **OkHttp `CertificatePinner`**, not a hand-rolled `X509TrustManager`, which would replace
  path validation and silently accept expired certificates and wrong hostnames.
  `CertificatePinner` runs in addition to platform trust, pins against the verified chain
  (so pinning a root actually works), OR-s multiple pins, and is the pattern MASTG documents.
- **`res/xml/network_security_config.xml`** with `cleartextTrafficPermitted="false"` and
  `<trust-anchors>` containing `system` only. This defeats a naive proxy: installing a CA
  as a user certificate gets you nothing.

TLS failures always fail closed. The trust or pinning error is surfaced and the attempt
ends. Every attempt uses the same trust anchors, hostname checks and pins. No TLS failure
counter, permissive trust manager, disabled hostname verification or unpinned retry path
exists.

**Pin roots only, six of them:** GTS Root R1–R4 and ISRG Root X1/X2. Managed hosting
leaves rotate on the order of weeks and intermediates rotate unannounced, so leaf or
intermediate pins guarantee a break and add nothing, since pins are OR-ed. The set covers
Google Trust Services and Let's Encrypt issuance and keeps a Cloudflare-proxied emergency
mode viable. Earliest expiry is ISRG X1 in 2035; GTS roots run to 2036. Each pin is
computed from the CA's own published PEM, never scraped from a live connection:

```bash
openssl x509 -in GTS_Root_R1.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Refresh policy: none. The APK is immutable; a pin change means a new APK and invalidated
writeups.

**HTTP client:** OkHttp with `ConnectionSpec.RESTRICTED_TLS`, 15 s call timeout,
`retryOnConnectionFailure = false`, `followRedirects = false` (a redirect could escape the
pinned host), no cookie jar, no cache, no logging interceptor in any build type.

### UI, one screen with diagnostic states

One `MainActivity`, no fragments, no navigation. A title, a short brief, one `ATTEST`
button, and a status line. The flag is never rendered in any state; success only confirms
a tier.

The status line is deliberately instructive rather than opaque: each failure names the
control that rejected the attempt. This is a teaching artefact, so the oracle is the point.
In a production app this granularity would be a finding.

| State | Message | Source |
| --- | --- | --- |
| Idle | `Connect to the internet to obtain the flag.` | client |
| In flight | `Attesting…` | client |
| No connectivity, DNS or timeout | `No connection to the server.` | client |
| Pinning / trust failure (MITM) | `Signing authority cannot be trusted.` | client |
| Re-signed or repackaged APK | `App signature is not verified.` | server `app_integrity` |
| No hardware attestation (emulator) | `This device has no hardware-backed attestation.` | server `no_hardware_attestation` |
| Stale or replayed challenge | `Attestation expired. Try again.` | server `challenge_expired` / `challenge_replayed` |
| Malformed chain, bad PoP, wrong key properties | `Attestation could not be verified.` | server `attestation_invalid` |
| Verification service unavailable | `Attestation service is unavailable. Try again later.` | server `verification_unavailable` |
| Boot policy rejected | `Device bootloader is not locked and verified.` | server `device_integrity` |
| Secure storage failed | `The flag could not be stored securely. Try again.` | client |
| Accepted, tier 2 | `Accepted — device and app fully verified.` | server `tier:2` |

Client-side exception mapping for the MITM state, which makes it detectable before any
request reaches the server:

- `SSLPeerUnverifiedException`: OkHttp `CertificatePinner` rejected a chain that the
  platform trusted (a system-installed CA on a rooted device).
- `SSLHandshakeException` / `CertificateException`: the framework trust manager rejected
  the chain (an unknown or user-installed CA).

Both map to `Signing authority cannot be trusted.` Everything else network-shaped
(`UnknownHostException`, `ConnectException`, `SocketTimeoutException`) maps to
`No connection to the server.`

No clipboard writes, no share intent, no diagnostic detail beyond the strings above.
`MainActivity` ignores its own `Intent` entirely.

**Manifest and build (reduced attestation surface):** `allowBackup="false"`, empty
`dataExtractionRules`, `usesCleartextTraffic="false"`, single `INTERNET` permission, no
`<service>`, `<receiver>` or `<provider>`, no AndroidX, Firebase or GMS SDKs. Exactly one
`<intent-filter>` (MAIN/LAUNCHER) with no schemes, `autoVerify` or `<data>`. No `<queries>`,
`sharedUserId` or `android:process`. `debuggable` and `testOnly` absent. Release settings:
`isMinifyEnabled = true`, `dependenciesInfo { includeInApk = false }`, R8
`-assumenosideeffects` on `android.util.Log`. The published artefact is a universal APK, not
an AAB, so the installed artefact is byte-identical to the published one. Obfuscation stays
light; L4 already covers that, and L5's difficulty is the protocol.

## Server

Kotlin/Ktor on Java 21. [`github.com/android/keyattestation`](https://github.com/android/keyattestation)
is JVM-only and is the verifier MASTG recommends over a custom implementation, so the
backend is a JVM service rather than a Worker that would need hand-rolled X.509 path
building and ASN.1 parsing.

All configuration comes from the environment, never baked into the image:
`CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_PACKAGE`, `APP_SIGNER_SHA256`,
`ATTESTATION_ROOTS` (PEM bundle). Keeping the roots in configuration means adding a new
Google root is a configuration change, not a rebuild.

**Challenge issuance is stateless**; single use is enforced at consumption.
`payload = ver(1) || tsSeconds(8) || nonce(32)`;
`challenge = payload || HMAC-SHA256(K, payload)[0..15]`, 57 bytes in total (under 64;
some KeyMint implementations reject larger challenges). `/v1/challenge` is
unauthenticated, so issuance must not write to storage or a `curl` loop could exhaust it.
One replay-store row is written per accepted `/v1/attest`, keyed by
`hex(SHA-256(challenge))`, create-if-absent. "Already exists" is the replay signal,
atomically, with no transaction. Expiry is enforced by the application, never by row
deletion timing.

**Verification pipeline** (no flag before all checks and atomic consumption):

1. Bound total request size, chain count and certificate sizes; reject malformed input.
2. Authenticate the canonical 57-byte challenge; reject future timestamps and age ≥ 120 s.
3. Validate the chain with the official Android verifier and explicitly configured trusted
   roots. Validate certificate times against the server clock, including the leaf
   (upstream omits that check). Use the verifier's chain structure validation and reject
   appended certificates.
4. Check every certificate against Google's HTTPS attestation status feed. Reject any
   listed serial, including REVOKED and SUSPENDED. Cache a successful snapshot for at most
   five minutes or the origin's remaining `max-age`, whichever is shorter. No snapshot,
   an expired snapshot or a malformed response means 503 and no flag. A refresh failure
   never extends freshness.
5. Require the attested challenge to exactly equal the authenticated server challenge.
6. Require both attestation and key security levels to be hardware backed (TEE or StrongBox).
7. Check exactly one package entry and exactly the configured signer digest set; reject
   shared-UID co-packages, missing identity and unexpected signers.
8. Require a hardware-enforced generated EC P-256 signing key, SIGN-only purpose and
   SHA-256 digest; reject `allApplications` in either authorization list.
9. Verify proof of possession over the challenge with the attested public key.
10. Require hardware-enforced locked + Verified boot; otherwise reject with `device_integrity`.
11. Recheck expiry after verification, then atomically consume the challenge immediately
    before flag issuance. Concurrent valid submissions yield one winner. Invalid proofs do
    not consume a challenge. A store failure means 503. A lost response requires a new
    challenge, not a replay of the old request.

The pinned verifier's strict parser is used as is. It rejects unknown authorization tags,
including legacy `allApplications`; there is no permissive fallback. New KeyMint tags
require a reviewed dependency update and compatibility tests. Server trust roots and
verifier code are not frozen with the APK.

**Errors are deliberately diagnostic.** Each rejection returns the machine-readable
`error` code listed above, which the app maps to the status strings in the UI table. An
opaque 403 would leave a solver unable to tell a repackaging failure from a boot-state
failure, which is exactly the distinction the crackme exists to teach. Consequences
accepted: no uniform-latency floor and no per-response reference ID.

Still enforced: the flag, the challenge and the chain are never logged; abuse limits return
a generic 429; verification stage and outcome are logged for the maintainer without proof
material.

## Release and placement

- The release keystore is RSA-4096 with a 30-year validity, generated offline. Signing-key
  rotation must never be used. See [RELEASE-SIGNING.md](RELEASE-SIGNING.md).
- `apksigner verify --print-certs` gives the "Signer #1 certificate SHA-256 digest", which
  is exactly the value of `APP_SIGNER_SHA256`. Publishing it is fine; it is derivable from
  the APK.
- The published APK's SHA-256 is recorded in the README. The build is verifiable in
  practice but does not promise bit-for-bit reproducibility.
- Source is intended for `github.com/OWASP/mas-crackmes` under `Android/Level5/`, and the
  binary for `github.com/OWASP/mastg` under `Crackmes/Android/Level_05/`. Committed:
  pins, backend origin, package name, signer digest. Never committed: keystore,
  `CHALLENGE_HMAC_KEY`, flags.
- The website entry follows the existing crackme page pattern, with an installation note
  stating the hard requirements: internet access and a GMS-certified device with hardware
  attestation and a locked, verified bootloader.

## Verification checklist

1. **Server tests** with signed synthetic chains under test-only roots plus recorded
   real-device chains: a genuine `TrustedEnvironment` chain, a `Software`/emulator chain
   (must fail hardware policy), a repackaged-app chain (must fail app identity), a replayed
   nonce, an expired challenge, a tampered HMAC, and unlocked or non-verified boot states.
2. **Local end-to-end**: run the server locally, point a debug variant at it, confirm the
   full round trip on a physical GMS device. An emulator must fail hardware policy.
3. **Pinning**: a proxy with a user CA must fail platform trust; a system-trusted proxy CA
   must still fail certificate pinning. Repeated failures must show no downgrade.
4. **Manifest audit**: `aapt dump badging` and a manifest diff on the release APK confirm
   zero exported components beyond `MainActivity`, no intent filters beyond MAIN/LAUNCHER,
   `allowBackup=false`, `debuggable` absent.
5. **Flag lifecycle**: inspect the shipped APK for embedded flag values. After attestation,
   verify encrypted records survive process restart, IVs differ across writes, tampering
   fails authentication, and missing keys require re-attestation. Inspect app files, logs,
   caches and backup configuration for plaintext leakage.
6. **Device policy and extraction research**: document locked verified device acceptance,
   unlocked or non-verified rejection, revoked or suspended credential rejection, and
   timing/storage experiments. Test status-feed outage, concurrent replay, invalid PoP
   without nonce consumption, and expiry during verification.

There is no offline flag issuance or weakened attestation mode. A fresh ATTEST action
requires the backend. Previously downloaded encrypted records may persist; they neither
mint new flags nor establish current device integrity. Flag SHA-256 digests should be published
for solver self-verification, and plaintext flags published when the service is
retired.
