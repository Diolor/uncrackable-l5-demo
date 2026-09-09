# Android UnCrackable L5 — Attestation & Pinning Crackme

## Context

The MAS crackme catalogue (`docs/crackmes/`) has not gained a challenge since the tab was created, and every existing Android crackme is **fully offline**: the flag is inside the APK and the challenge is pure reverse engineering. Nothing in the catalogue exercises the two controls modern apps lean on to protect a secret that is provisioned only after server verification — hardware-backed **device and app attestation**, and **TLS certificate pinning**.

This crackme is the hands-on companion to the author's own in-flight MASTG work, [OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953) (local branch `android-attestation`), which introduces `MASTG-BEST-0x01` "Use Hardware-Backed Key Attestation for Device and App Integrity", the rewritten `MASTG-KNOW-0044/0119/0120`, and `MASTG-TEST-0x01/0x05`. It turns that doctrine into something a reader can attack.

**Outcome:** a crackme whose flag is never present in the APK. It is issued over the network by a backend that answers only a request carrying a fresh, hardware-attested proof from an unmodified, correctly-signed build; and the app only talks to that backend over a pinned channel. Solving it requires runtime instrumentation of the genuine binary — ordinary re-signing is rejected under the stated platform and attestation trust assumptions.

---

## Design rationale (decided with the user)

### Key Attestation, not Play Integrity / Firebase App Check

The APK is distributed from GitHub and not published on Play. Firebase App Check supports outside-Play distribution, but an app never published on Play cannot receive `PLAY_RECOGNIZED`. We choose direct Key Attestation verification for explicit package/signer and boot-state policies, without a Play publication dependency. See [Firebase distribution settings](https://firebase.google.com/docs/app-check/android/play-integrity-provider).

**Hardware Key Attestation uses Android Keystore APIs**: the client needs no Firebase SDK or Play publication, but a supported device must provide a chain to our configured trusted roots. It yields both halves in one artefact — `attestationApplicationId` carries app identity (package + signing cert SHA-256), `rootOfTrust` carries device state (`verifiedBootState`, `deviceLocked`). Firebase App Check is documented on the crackme page as the *production-recommended* alternative, cross-referencing PR #3954's App Check knowledge page, but is not used as a control.

### Freshness and limits of attestation

Use a server-issued, expiring, single-use nonce and bind it to both attestation and proof
of possession. Do not plant a missing challenge, replay window, or driveable exported
attester. These controls resist stale proofs and straightforward relay attempts; they
are not a general proof that every relay or runtime compromise is impossible.

Attestation reports properties at key creation. It is not continuous monitoring of the
app process. The time between key creation, server verification, flag delivery and later
local decryption is a research surface; do not intentionally weaken checks to make it exploitable.

### Security boundary and intended solutions

There is **no intentional client TLS defect**. Certificate validation, hostname verification,
and pinning fail closed on every attempt. Repeated failures never weaken these controls.
The challenge is extracting a server-provisioned flag from the genuine app at runtime.

The backend validates certificate trust, revocation, challenge freshness, key possession,
app identity and device state. There are no intentionally omitted security checks.

### Mandatory device gate and legacy tiers

Every issued flag requires fresh trusted hardware attestation, live revocation checks,
matching package/signer, proof of possession, and hardware-enforced
`deviceLocked == true` AND `verifiedBootState == VERIFIED`.
Unlocked, self-signed, unverified, failed or missing hardware boot evidence releases no flag.
The weaker tier-one fallback is retired. Successful responses retain `tier:2` for
protocol compatibility; `FLAG_TIER1` remains a reserved configuration value and is never issued.
There is currently no separate tier-one success criterion.

A stock locked device may receive the flag. Receiving it is not solving extraction.
No release extraction bypass is demonstrated. Boot attestation describes key-creation
state, not continuous runtime integrity; do not claim that all runtime compromise is impossible.

---

## Release decisions (do not block local backend implementation)

1. **Hostname.** `crackme.lorenzos.com` is a personal domain pinned into an immutable APK. If it lapses, every published APK breaks permanently — and the name could be re-registered by a third party who can obtain a certificate from an already-pinned public root. **Strongly prefer an OWASP-controlled hostname.** If the personal domain is kept: register it for the maximum term, enable registrar lock, and commit a documented handover.
2. **Cloud project ownership.** Same class of risk. Transfer the GCP project and billing to an OWASP-controlled account with ≥2 Owners before launch; a lapsed card silently kills the crackme.
3. **Signing keystore custody.** If the release key is lost the crackme is unfixable forever, because the signer digest is attested. Two custodians minimum, in the OWASP secret store.
4. **MAS team contact.** `docs/contributing/6_Add_a_Crackme.md` requires contacting the team *before* submitting, with a writeup and a feature list.
5. **IDs.** `MASTG-BEST-0x01` / `MASTG-KNOW-0119` / `MASTG-KNOW-0120` are placeholders in PR #3953 pending ID allocation; the crackme page's cross-references must be updated once real IDs land.

### Implementation readiness and scope

No unresolved product decision blocks the first local backend milestone. Use isolated test
keys, synthetic flags and injected clocks/trust sources. Do not choose a production hostname,
release signer, actual flag values, billing owner or cloud credentials implicitly. The five
items above block publication and production provisioning, not local implementation.

First milestone: Java 21/Kotlin Gradle server, attestation verifier adapter, strict policy,
challenge issuance, atomic replay-store contract and Ktor endpoints with automated tests.
Use synthetic chains rooted only in test trust anchors; label them as synthetic and never
allow test anchors in the runtime configuration by default. Integrate the official Android
verifier at a pinned revision rather than writing an ASN.1 or certificate path verifier.

Follow with a minimal physical-device client and genuine recorded-chain tests, then Firebase
integration and deployment. Device tests validate compatibility; extraction remains
research and need not produce an exploit.

---

## Client — Kotlin Android app

**Identity (immutable forever, because it is attested):** package `org.owasp.mastg.uncrackable5`, label `UnCrackable L5`, versionName `1.0`. `minSdk = 28` (StrongBox API without reflection; reliable `attestationApplicationId` population), `targetSdk`/`compileSdk = 36`.

**Attestation key.** Per attempt, a throwaway EC P-256 signing key in `AndroidKeyStore` under a random alias, deleted in a `finally` block:

```kotlin
KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameter(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(challenge)          // server-issued, per request
    .setKeyValidityEnd(Date(now + 5 * 60_000))
    .apply { if (strongBox) setIsStrongBoxBacked(true) }
    .build()
```

StrongBox first; on `StrongBoxUnavailableException` **or** bare `ProviderException` (several OEMs throw the latter, some only at `generateKeyPair()`), delete the partial alias and retry without. StrongBox absence is not a failure — the server accepts `TrustedEnvironment`.

Chain via `KeyStore.getInstance("AndroidKeyStore").getCertificateChain(alias)`, each element Base64(DER). Also sign the challenge with the fresh key and send it as a proof-of-possession.

**Protocol.**

```
GET  /v1/challenge  -> {"challenge":"<b64url 57B>","expiresIn":120}
POST /v1/attest     <- {"challenge":..,"chain":[..],"pop":..}
                    -> 200 {"tier":2, "flag":"..."}
                    -> 403 {"error":"device_integrity"} // bootloader not locked and verified
                    -> 403 {"error":"app_integrity"        // signer digest mismatch
                                  | "no_hardware_attestation"  // Software level / emulator
                                  | "challenge_expired"
                                  | "challenge_replayed"
                                  | "attestation_invalid"}    // chain / revocation / PoP / key props
                    -> 503 {"error":"verification_unavailable"} // status feed or replay store unavailable
GET  /v1/health     -> {"status":"ok"}
```

### Flag lifecycle and local storage

**Confirmed invariant:** neither flag value is embedded in the shipped APK, including
resources, native libraries, assets, or a bundled encrypted copy. A `flag` JSON field name
and code that handles downloaded flags are allowed. The client response model declares
`flag`; it no longer discards the field with `ignoreUnknownKeys`.

After successful attestation, the client receives and processes the flag in memory and
persists it locally. The UI continues to show only the accepted tier; flags must not be
written to logs, clipboard, analytics, HTTP caches, or plaintext temporary files.

**Storage design:** encrypt downloaded flags with
`AES/GCM/NoPadding`, using a persistent per-installation AES-256 key generated in
`AndroidKeyStore`. This is a separate key from the per-attempt attestation signing key,
which is still deleted after each attempt. Require hardware-backed storage for both new
and existing AES keys: accept only StrongBox or Trusted Environment from `KeyInfo` on
API 31+, and require `isInsideSecureHardware` on API 28–30. Reject software or unknown
levels without encrypting or decrypting; discard rejected keys and their cached records.
Failure to inspect key metadata fails closed. Never substitute a bundled/exported key.
Storage failures show a secure-storage failure status instead of acceptance.
Verify the actual AES key security level and rejection behavior on physical devices.
Use a new provider-generated IV for every encryption under the same key and a 128-bit
authentication tag. Store a version, IV, and ciphertext/tag in app-private
`noBackupFilesDir`; bind the tier and format version as authenticated additional data.
Keep one record per earned tier and replace it atomically after successful encryption.

On later access, decrypt only in process and retain plaintext briefly. Missing or invalidated
keys and corrupt records cause the local record to be discarded and require fresh online
attestation; never fall back to plaintext storage. A cached record is a previously issued
flag, not proof of current device integrity, and must not satisfy a new ATTEST operation.

Encryption protects stored bytes; instrumentation in the authorized app process can still
observe plaintext or invoke the key. This is an intended extraction surface, not a promise
that a runtime secret is impossible to recover. Copying ciphertext alone should not reveal
it. Validate the storage behavior on real hardware before freezing the client.

References: [Android cryptography](https://developer.android.com/privacy-and-security/cryptography)
and [Android Keystore](https://developer.android.com/privacy-and-security/keystore).

**Pinning — two layers, correctly built:**

- **OkHttp `CertificatePinner`** — not a hand-rolled `X509TrustManager`, which would replace path validation and silently accept expired certs and wrong hostnames. `CertificatePinner` runs *in addition to* platform trust, pins against the verified chain (so pinning a root actually works), OR-s multiple pins, and is the pattern MASTG documents.
- **`res/xml/network_security_config.xml`** with `cleartextTrafficPermitted="false"` and `<trust-anchors>` containing `system` only (no `user`). This is what defeats a naive proxy: installing a CA as a user certificate gets you nothing.

### TLS failures always fail closed

Surface the existing trust/pinning error and end the attempt. A user may start another
attempt, but every attempt uses the same trust anchors, hostname checks and certificate
pins. No TLS failure counter, permissive trust manager, disabled hostname verification,
or unpinned retry path is permitted.

**Pin roots only, six of them:** GTS Root R1–R4 and ISRG Root X1/X2. Firebase Hosting's managed leaf rotates on the order of weeks and the GTS intermediates rotate unannounced, so leaf/intermediate pins guarantee a break and add nothing (pins are OR-ed). Covers the observed Let's Encrypt→GTS transition on Firebase Hosting custom domains, and keeps a Cloudflare-proxied emergency mode viable. Earliest expiry ISRG X1 2035-06; GTS to 2036. Compute each from the CA's own published PEM, never scraped from the live connection:

```bash
openssl x509 -in GTS_Root_R1.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Refresh policy: **none**. The APK is immutable; a pin change means a new APK and invalidated writeups.

**HTTP client:** OkHttp 4.12+, `ConnectionSpec.RESTRICTED_TLS`, 15 s call timeout, `retryOnConnectionFailure = false`, `followRedirects = false` (a redirect could escape the pinned host), no cookie jar, no cache, no logging interceptor in any build type.

### UI — one screen, diagnostic states

One `MainActivity`, no fragments, no navigation. A title, a short brief, one `ATTEST` button, and a status line. **The flag is never rendered in any state** — success only ever confirms a tier.

The status line is deliberately **instructive rather than opaque**: each failure names the control that rejected the attempt. This is a teaching artefact, so the oracle is the point — it tells a solver why they are stuck and makes repackaging dead-end visibly instead of mysteriously. (In a production app this granularity would be a finding; the writeup should say so explicitly.)

| State | Message | Source |
|---|---|---|
| Idle (default) | `Connect to the internet to obtain the flag.` | client |
| In flight | `Attesting…` | client |
| No connectivity, DNS or timeout | `No connection to the server.` | client |
| **Pinning / trust failure — MITM** | `Signing authority cannot be trusted.` | client |
| **Re-signed or repackaged APK** | `App signature is not verified.` | server `app_integrity` |
| No hardware attestation (emulator, `Software` level) | `This device has no hardware-backed attestation.` | server `no_hardware_attestation` |
| Stale or replayed challenge | `Attestation expired. Try again.` | server `challenge_expired` / `challenge_replayed` |
| Malformed chain, bad PoP, wrong key properties | `Attestation could not be verified.` | server `attestation_invalid` |
| Boot policy rejected | `Device bootloader is not locked and verified.` | server `device_integrity` |
| **Accepted, tier 2** | `Accepted — device and app fully verified.` | server `tier:2` |

Client-side exception mapping for the MITM state — this is what makes it detectable before any request reaches the server:

- `SSLPeerUnverifiedException` — OkHttp `CertificatePinner` rejected a chain that the platform trusted (a *system*-installed CA on a rooted device).
- `SSLHandshakeException` / `CertificateException` — the framework's `NetworkSecurityTrustManager` rejected the chain (an unknown or *user*-installed CA).

Both map to `Signing authority cannot be trusted.` Everything else network-shaped (`UnknownHostException`, `ConnectException`, `SocketTimeoutException`) maps to `No connection to the server.`

No clipboard writes, no share intent, no diagnostic detail beyond the strings above (no HTTP status, no exception text, no `ref`). `MainActivity` **ignores its own `Intent` entirely** — no extras, data URI, or action is read.

**Manifest / build (reduce exposed attestation surfaces):** `allowBackup="false"`, empty `dataExtractionRules`, `usesCleartextTraffic="false"`, single `INTERNET` permission, no `<service>`/`<receiver>`/`<provider>` (explicitly `tools:node="remove"` the merged `androidx.startup.InitializationProvider` and `ProfileInstallReceiver`, or better, don't depend on them; add zero Firebase/GMS SDKs). Exactly one `<intent-filter>` (MAIN/LAUNCHER) — no schemes, no `autoVerify`, no `<data>`. No `<queries>`, no `sharedUserId`, no `android:process`. `debuggable`/`testOnly` absent. Release APK is the challenge; a separate debug build is allowed for local integration tests only. Release settings: `isMinifyEnabled = true`, `dependenciesInfo { includeInApk = false }`, R8 `-assumenosideeffects` on `android.util.Log`. Ship a **universal APK**, not an AAB, so the installed artefact is byte-identical to the published one. Obfuscation stays light — L4 already covers that; L5's difficulty is the protocol.

---

## Server — Kotlin/Ktor on Cloud Run

Chosen for the JVM: [`github.com/android/keyattestation`](https://github.com/android/keyattestation) is JVM-only, and `MASTG-BEST-0x01` explicitly says to prefer it over a custom verifier. A Cloudflare Worker would mean hand-rolling several hundred lines of security-critical X.509 path building and ASN.1 parsing; Cloud Functions gen2 is Cloud Run with an imposed runtime-deprecation treadmill.

Ktor 3.x on Java 21, distroless image. All config from Secret Manager, never baked into the image: `CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_PACKAGE`, `APP_SIGNER_SHA256`, `ATTESTATION_ROOTS` (PEM bundle — keeping the roots in config means adding Google's new root that began signing 2026-02-01 is a secret-version bump, not a rebuild).

**Challenge issuance is stateless**, single-use is enforced at consumption. `payload = ver(1) || tsSeconds(8) || nonce(32)`; `challenge = payload || HMAC-SHA256(K, payload)[0..15]` → 57 bytes (stay under 64; some KeyMint implementations reject larger challenges). This matters: `/v1/challenge` is unauthenticated, so a Firestore write per issuance would let a `curl` loop burn the free write quota. One Firestore document is written per accepted `/attest`, `docId = hex(SHA-256(challenge))`, create-if-absent — `ALREADY_EXISTS` *is* the replay signal, atomically, with no transaction. `expireAt` + a TTL policy cleans up old records; TTL deletion is asynchronous and billable. Expiry is enforced by the application, never by deletion timing.

**Verification pipeline** (no flag before all required checks and atomic consumption):

1. Bound total request size, chain count and certificate sizes; reject malformed input.
2. Authenticate the canonical 57-byte challenge, reject future timestamps and age >= 120 s.
3. Validate the chain using the official Android verifier and explicitly configured trusted
   roots. Validate certificate times against the server clock, explicitly including the leaf
   (upstream omits that check). Use the verifier's chain structure validation and reject
   appended certificates; do not search an arbitrary chain for a convenient extension.
4. Check every certificate against Google's HTTPS attestation status feed. Reject any listed
   serial, including REVOKED and SUSPENDED. Cache a successful snapshot for at most five
   minutes (or a shorter origin max-age); refresh with a bounded timeout. No snapshot, expired
   snapshot or malformed response means 503 and no flag. A refresh failure must not extend
   freshness. JCA CRL/OCSP settings are not a substitute for this separate status feed.
5. Require the attested challenge to exactly equal the authenticated server challenge.
6. Require both attestation and key security levels to be hardware backed (TEE or StrongBox).
7. Check exactly one package entry and exactly the configured signer digest set; reject
   shared-UID co-packages, missing identity and unexpected signers.
8. Require hardware-enforced generated EC P-256 signing key, SIGN-only purpose and SHA-256
   digest; reject `allApplications` in either authorization list.
9. Verify proof of possession over the challenge with the attested public key.
10. Require hardware-enforced locked + Verified boot for every flag; otherwise reject with `device_integrity`. Success retains tier 2.
11. Recheck expiry after verification, then atomically consume the challenge immediately
    before flag issuance. Concurrent valid submissions yield one winner. Invalid proofs do
    not consume a challenge. Store failure means 503; never use a per-instance production
    replay cache. A lost response requires a new challenge, not replaying the old request.

Use the pinned verifier's strict parser. It currently rejects unknown authorization tags, including legacy `allApplications`; do not add a permissive parser fallback. New KeyMint tags require a reviewed server dependency update and compatibility tests. Do not freeze server trust roots or verifier code with the APK.

**Errors are deliberately diagnostic.** Each rejection returns the machine-readable `error` code listed in the protocol above, which the app maps to the status strings in the UI table. This is a reversal of the usual rule and is intentional for a teaching artefact: an opaque `403` would leave a solver unable to tell a repackaging failure from a boot-state failure, which is exactly the distinction the crackme exists to teach. Consequences accepted: the uniform-latency floor is dropped (there is nothing left to hide by timing), and the `ref` UUID is no longer needed in responses.

Still enforced: never log the flag, the challenge, or the chain; per-IP token bucket → generic `429`; the full verification stage and outcome go to Cloud Logging for the maintainer.

---

## Infrastructure

GCP project with `run`, `artifactregistry`, `firestore`, `secretmanager`, `cloudbuild`, `firebasehosting`. Firestore **Native mode** in the same region as Cloud Run (`us-central1`), collection `used_challenges`, TTL on `expireAt`, security rules deny all client access. Dedicated runtime service account with `secretAccessor` (not the default compute SA).

```bash
gcloud run deploy crackme-l5 --region us-central1 --allow-unauthenticated \
  --min-instances=0 --max-instances=3 --concurrency=40 --cpu=1 --memory=512Mi \
  --timeout=15s --cpu-boost --set-secrets=...
```

`max-instances=3` limits scaling but is not a hard spending cap. Budget alerts are notifications, not automatic shutdown.

Firebase Hosting rewrite `{"source":"/v1/**","run":{"serviceId":"crackme-l5","region":"us-central1"}}`, plus a static `index.html` at `/` with the brief and a live status widget — this stays up even if Cloud Run is entirely broken. Custom domain added in the Firebase console (TXT verification, then two A records) entered in Cloudflare **DNS-only / grey cloud**. **Fix CAA records first** — if the apex has a CAA that omits `pki.goog` and `letsencrypt.org`, managed certificate issuance stalls silently for days; this is the most common setup failure here. After issuance, confirm with `openssl s_client -connect <host>:443 -showcerts` that the live chain terminates in a pinned root, *then* freeze the pin set and build the APK.

**Cost: usage-based, not guaranteed free.** Cloud Run requires billing/Blaze. Account for Firestore TTL deletes, builds, storage, logging, secrets and traffic as well as requests. Budget alerts at $1 / $5 / $20 to at least two addresses.

---

## Build, release and placement

- Keystore `uncrackable-l5.jks`, RSA-4096, `-validity 10950` (30 y), generated offline, two custodians. **Signing-key rotation (v3.1) must never be used** — rotation changes what lands in `attestationApplicationId`. Record this as a hard constraint in the repo README.
- `apksigner verify --print-certs` → "Signer #1 certificate SHA-256 digest" is exactly the value for `APP_SIGNER_SHA256`. Publishing it is fine; it is derivable from the APK.
- Ship a `Dockerfile` pinning JDK/Gradle/AGP/build-tools plus `./gradlew assembleRelease`, and publish the released APK's SHA-256. Verifiable in practice; don't over-promise bit-for-bit reproducibility.
- **Local development root: `/Users/dionysislorentzos/Development/Projects/OWASP/Uncrackable`** (Git repository initialized; implementation starts with the server). Layout, which doubles as the eventual upstream layout:

  ```
  Uncrackable/
    Mobile app/          Kotlin Android client (Gradle)
    server/       Kotlin/Ktor backend (Gradle)
    infra/        gcloud deploy script or Terraform, firebase.json
    fixtures/     recorded attestation chains for the server tests
    README.md     brief, hard requirements, flag SHA-256s, security assumptions and research status
    SOLUTION.md   the writeup required by the contributing terms
  ```

- **Source published to** `github.com/OWASP/mas-crackmes` at `Android/Level5/` — the contents of the directory above. Committed: pins, backend URL, package name, signer digest. Never committed: keystore, `CHALLENGE_HMAC_KEY`, flags.
- **Binary** → `github.com/OWASP/mastg` at `Crackmes/Android/Level_05/UnCrackable-Level5.apk`.
- **Website**, following the existing pattern exactly (no front matter, `##` heading, `mas-chip` download link, `??? info "Installation"`, `??? danger "SPOILER (Solutions)"`, italic gray credit):
  - `docs/crackmes/Android.md` — new `## Android UnCrackable L5` section inserted before `## MASTG Hacking Playground`, with numbered flag objectives in the L4 style, and an Installation note stating the hard requirements: **internet access** and a **GMS-certified device with hardware attestation** (a stock AVD has no real attestation keybox and cannot work).
  - `docs/crackmes/index.md` — a `mas-app-row` block linking to `#android-uncrackable-l5`. New files under `docs/crackmes/` are picked up automatically by the awesome-pages `flat` glob at `mkdocs.yml:216-218`, but these are edits to existing files.
  - Optionally a `MASTG-APP-00XX.md` reference-app entry in `mastg/apps/android/` (`title`, `platform`, `package`, `source`, `weaknesses: [MASWE-0054, MASWE-0056]`) per `mastg/.github/instructions/mastg-apps.instructions.md` — use a placeholder ID in the PR.

---

## Solution status (`SOLUTION.md`)

See [SOLUTION.md](SOLUTION.md). The former unlocked-device tier-one Frida route is
retired by the mandatory boot gate. No release extraction bypass is demonstrated.
Research must preserve all checks and demonstrate actual plaintext extraction; runtime
compromise or later storage access are hypotheses, not completed solutions.

---

## Verification

1. **Server tests** start with signed synthetic chains under test-only roots. Add recorded real-device chains as integration fixtures before release: a genuine `TrustedEnvironment` chain, a StrongBox chain, a `Software`/emulator chain (must fail hardware policy), a repackaged-app chain (must fail app identity), a replayed nonce (must fail atomic consumption), an expired challenge, a tampered HMAC, and a chain whose `verifiedBootState` is `Unverified` (must reject without issuing any flag).
2. **Local end-to-end**: run the Ktor server locally, point a debug variant at it, confirm the full round trip on a physical GMS device. An emulator must be verified to fail hardware policy — that is a test, not a bug.
3. **Pinning proved**: a proxy with a user CA must fail platform trust; a system-trusted proxy CA must still fail certificate pinning. Repeat failures beyond two attempts and confirm there is no downgrade. With a runtime pinning bypass, a system-trusted proxy CA may succeed; a user-only CA still needs a trust bypass.
4. **Anti-relay audit**: `aapt dump badging` and a manifest diff on the release APK to confirm zero exported components beyond `MainActivity`, no intent filters beyond MAIN/LAUNCHER, `allowBackup=false`, `debuggable` absent.
5. **Flag lifecycle**: inspect the shipped APK for embedded flag values or bundled encrypted flags; the `flag` JSON key is allowed. After attestation, verify encrypted records survive process restart and decrypt correctly, IVs differ across writes, tampering fails authentication, and missing keys require re-attestation. Inspect app files, logs, caches and backup configuration for plaintext leakage. Record runtime extraction experiments at the response or crypto boundary without claiming a demonstrated bypass.
6. **Device policy and extraction research:** document locked verified device acceptance, unlocked/non-verified rejection, rejection of revoked/suspended credentials, and timing/storage experiments. No successful Flag 2 bypass is required. Test status-feed outage/staleness, concurrent replay, invalid PoP without nonce consumption, and expiry during verification.
7. **Live monitoring**: a GitHub Actions cron in `mas-crackmes` doing a daily synthetic round trip (`/challenge` → malformed `/attest` → expect 403) that **opens an issue on failure**, so the community learns of an outage before the maintainer does.
8. **Website build**: `mkdocs serve` in `mas-website` (with the sibling `mastg` checkout present, since `docs/hooks/combine-repos.py` runs at `on_pre_build`), then `npx markdownlint-cli2 --config .markdownlint.jsonc`.

**No offline flag issuance or weakened attestation mode.** A fresh ATTEST action requires
the backend. Previously downloaded encrypted records may persist and be accessed locally;
they neither mint new flags nor establish current device integrity. Ship no embedded flag
or offline derivation mechanism. Publish flag SHA-256 digests for solver self-verification
and document a sunset plan for publishing plaintext flags when the service is retired.

## Implementation status

The first local backend milestone is implemented in `server/`: challenge authentication,
strict Android verifier adapter, bounded revocation cache, atomic replay-store interface,
and Ktor route composition. Tests use signed synthetic chains and a test-only in-memory
replay store. The pinned upstream source and license are in `third_party/`.

The Android client in `Mobile app/` implements the plan's client section: per-attempt attested
P-256 key with StrongBox-then-TEE fallback, root-only `CertificatePinner` over
`RESTRICTED_TLS` with a system-anchor `network_security_config`, bounded protocol client
with the documented error-to-status mapping, AES-256-GCM flag records under a persistent
Keystore key (tier bound as AAD, atomic replace in `noBackupFilesDir`), and the one-screen
UI. The release manifest was audited: single `INTERNET` permission, one exported activity
with only MAIN/LAUNCHER, `allowBackup=false`, no `debuggable`. Physical-device validation was
completed on 2026-09-09 (OnePlus 9 Pro, Android 14, TEE, locked, verified boot: tier 2
accepted; replay, tampered proof and foreign-challenge requests rejected; the first
revocation fetch exposed and fixed a CDN `Age` handling bug that failed closed on a
valid feed). The accepted chain is recorded in `fixtures/`. Not yet done on the client:
the signing keystore and the final hostname (currently the plan's placeholder in
`Mobile app/build.gradle.kts`).

The production runtime foundation now includes a Firestore create-if-absent replay
adapter, strict environment configuration for injected secrets, a Netty entry point
and a non-root distroless container recipe. This is not ready for public deployment:
ingress-aware distributed abuse limits, deployment setup, structured outcome logging,
Firestore integration validation and physical-device client validation/recorded
fixtures remain. No production flags, signing keys, trust configuration or cloud
resources have been created. See `server/README.md` for the runnable local test milestone.

## Release signing preparation

The user authorized local release-key creation. See [RELEASE-SIGNING.md](RELEASE-SIGNING.md).
Only the public certificate SHA-256 digest is backend configuration. Private signing
material stays with custodians, outside Git and hosting. Two-custodian backup and final
hostname decisions still precede publication.
