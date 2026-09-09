# Android UnCrackable L5 — Attestation & Pinning Crackme

## Context

The MAS crackme catalogue (`docs/crackmes/`) has not gained a challenge since the tab was created, and every existing Android crackme is **fully offline**: the flag is inside the APK and the challenge is pure reverse engineering. Nothing in the catalogue exercises the two controls modern apps lean on to protect a secret that is provisioned only after server verification — hardware-backed **device and app attestation**, and **TLS certificate pinning**.

This crackme is the hands-on companion to the author's own in-flight MASTG work, [OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953) (local branch `android-attestation`), which introduces `MASTG-BEST-0x01` "Use Hardware-Backed Key Attestation for Device and App Integrity", the rewritten `MASTG-KNOW-0044/0119/0120`, and `MASTG-TEST-0x01/0x05`. It turns that doctrine into something a reader can attack.

**Outcome:** a crackme whose flag is never present in the APK. It is issued over the network by a backend that answers only a request carrying a fresh, hardware-attested proof from an unmodified, correctly-signed build; and the app only talks to that backend over a pinned channel. Solving it requires runtime instrumentation of the genuine binary — repackaging is impossible by construction.

---

## Design rationale (decided with the user)

### Key Attestation, not Play Integrity / Firebase App Check

The APK is sideloaded from GitHub. A sideloaded app can never receive `PLAY_RECOGNIZED`, so a Firebase App Check (Play Integrity provider) gate would reject every legitimate solver unless configured to allow unrecognised versions — which removes the anti-repackaging property the challenge depends on. It would also bind the crackme to a Play Console app record.

**Hardware Key Attestation is pure AOSP**: no GMS, no Play Console, no publishing, and it yields both halves in one artefact — `attestationApplicationId` carries app identity (package + signing cert SHA-256), `rootOfTrust` carries device state (`verifiedBootState`, `deviceLocked`). Firebase App Check is documented on the crackme page as the *production-recommended* alternative, cross-referencing PR #3954's App Check knowledge page, but is not used as a control.

### Freshness is kept — the relay stays closed

The user considered and **rejected** making a missing/hardcoded `setAttestationChallenge` the intended flaw. The app uses a proper server-issued single-use nonce throughout. Consequence, and the reason it matters: a two-device relay (clean phone + rooted phone) does **not** work, because

- injecting the server's current nonce into the genuine app on a clean device needs instrumentation, which needs root;
- a self-built or re-signed attester is rejected — `attestationApplicationId` is populated by the OS with the signing certificate digest;
- MITM to feed the clean device a nonce fails on pinning, and a transparent TCP relay reveals nothing.

This holds **only if the app exposes no driveable surface** — see the manifest constraints below.

### Security boundary and intended solutions

There is **no intentional client TLS defect**. Certificate validation, hostname verification,
and pinning fail closed on every attempt. Repeated failures never weaken these controls.
The challenge is extracting a server-provisioned flag from the genuine app at runtime.

The backend validates challenges, key possession, app identity and device state. Its one
explicit, intentional attestation weakness remains the omission of revocation checking,
which supports the proposed advanced Flag 2 route. Do not describe the backend as fully
correct while retaining that omission.

### Two flags

| | Gate | Intended solve |
|---|---|---|
| **Flag 1** | Fresh challenge, hardware attestation, matching package and original signer, proof of possession | Instrument the genuine app on a rooted device; observe the response or the local encryption/decryption boundary. |
| **Flag 2** | Flag 1 checks plus `deviceLocked == true` and `verifiedBootState == Verified` | Proposed advanced route: compromised trusted attestation credentials with the intentionally omitted revocation check, plus runtime extraction. Must be validated end to end before release. |

A stock locked device can receive Flag 2, but a proxy and repeated TLS failures alone
cannot extract it. Encrypted persistence does not provide an automatic stock-device solve.
Ordinary repackaging is rejected through the attested package and signing certificate;
that guarantee assumes trustworthy attestation credentials and the platform supplying app identity.

The backend deliberately does not query `https://android.googleapis.com/attestation/status`.
Document this omission in README, SOLUTION and the website. Availability of suitable test
credentials and the actual feasibility of the Flag 2 route are release dependencies, not
assumed guarantees. Revocation checking also cannot prove the absence of every compromise.

---

## Decide before the APK ships (blocking)

1. **Hostname.** `crackme.lorenzos.com` is a personal domain pinned into an immutable APK. If it lapses, every published APK breaks permanently — and the name could be re-registered by a third party who can obtain a certificate from an already-pinned public root. **Strongly prefer an OWASP-controlled hostname.** If the personal domain is kept: register it for the maximum term, enable registrar lock, and commit a documented handover.
2. **Cloud project ownership.** Same class of risk. Transfer the GCP project and billing to an OWASP-controlled account with ≥2 Owners before launch; a lapsed card silently kills the crackme.
3. **Signing keystore custody.** If the release key is lost the crackme is unfixable forever, because the signer digest is attested. Two custodians minimum, in the OWASP secret store.
4. **MAS team contact.** `docs/contributing/6_Add_a_Crackme.md` requires contacting the team *before* submitting, with a writeup and a feature list.
5. **IDs.** `MASTG-BEST-0x01` / `MASTG-KNOW-0119` / `MASTG-KNOW-0120` are placeholders in PR #3953 pending ID allocation; the crackme page's cross-references must be updated once real IDs land.

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
                    -> 200 {"tier":1, "flag":"...", "reason":"device_integrity"}
                    -> 403 {"error":"app_integrity"        // signer digest mismatch
                                  | "no_hardware_attestation"  // Software level / emulator
                                  | "challenge_expired"
                                  | "challenge_replayed"
                                  | "attestation_invalid"}    // chain / PoP / key props
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

**Recommended storage design (proposed default):** encrypt downloaded flags with
`AES/GCM/NoPadding`, using a persistent per-installation AES-256 key generated in
`AndroidKeyStore`. This is a separate key from the per-attempt attestation signing key,
which is still deleted after each attempt. Prefer hardware-backed storage and verify
its security level on supported test devices; never substitute a bundled/exported key.
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
it. Validate the proposed storage behavior on real hardware before freezing the client.

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
| **Accepted, tier 1** | `Accepted — this device does not have a verified bootloader.` | server `tier:1` |
| **Accepted, tier 2** | `Accepted — device and app fully verified.` | server `tier:2` |

Client-side exception mapping for the MITM state — this is what makes it detectable before any request reaches the server:

- `SSLPeerUnverifiedException` — OkHttp `CertificatePinner` rejected a chain that the platform trusted (a *system*-installed CA on a rooted device).
- `SSLHandshakeException` / `CertificateException` — the framework's `NetworkSecurityTrustManager` rejected the chain (an unknown or *user*-installed CA).

Both map to `Signing authority cannot be trusted.` Everything else network-shaped (`UnknownHostException`, `ConnectException`, `SocketTimeoutException`) maps to `No connection to the server.`

No clipboard writes, no share intent, no diagnostic detail beyond the strings above (no HTTP status, no exception text, no `ref`). `MainActivity` **ignores its own `Intent` entirely** — no extras, data URI, or action is read.

**Manifest / build (this is what closes the relay):** `allowBackup="false"`, empty `dataExtractionRules`, `usesCleartextTraffic="false"`, single `INTERNET` permission, no `<service>`/`<receiver>`/`<provider>` (explicitly `tools:node="remove"` the merged `androidx.startup.InitializationProvider` and `ProfileInstallReceiver`, or better, don't depend on them; add zero Firebase/GMS SDKs). Exactly one `<intent-filter>` (MAIN/LAUNCHER) — no schemes, no `autoVerify`, no `<data>`. No `<queries>`, no `sharedUserId`, no `android:process`. `debuggable`/`testOnly` absent. Release-only build type, `isMinifyEnabled = true`, `dependenciesInfo { includeInApk = false }`, R8 `-assumenosideeffects` on `android.util.Log`. Ship a **universal APK**, not an AAB, so the installed artefact is byte-identical to the published one. Obfuscation stays light — L4 already covers that; L5's difficulty is the protocol.

---

## Server — Kotlin/Ktor on Cloud Run

Chosen for the JVM: [`github.com/android/keyattestation`](https://github.com/android/keyattestation) is JVM-only, and `MASTG-BEST-0x01` explicitly says to prefer it over a custom verifier. A Cloudflare Worker would mean hand-rolling several hundred lines of security-critical X.509 path building and ASN.1 parsing; Cloud Functions gen2 is Cloud Run with an imposed runtime-deprecation treadmill.

Ktor 3.x on Java 21, distroless image. All config from Secret Manager, never baked into the image: `CHALLENGE_HMAC_KEY`, `FLAG_TIER1`, `FLAG_TIER2`, `APP_PACKAGE`, `APP_SIGNER_SHA256`, `ATTESTATION_ROOTS` (PEM bundle — keeping the roots in config means adding Google's new root that began signing 2026-02-01 is a secret-version bump, not a rebuild).

**Challenge issuance is stateless**, single-use is enforced at consumption. `payload = ver(1) || tsSeconds(8) || nonce(32)`; `challenge = payload || HMAC-SHA256(K, payload)[0..15]` → 57 bytes (stay under 64; some KeyMint implementations reject larger challenges). This matters: `/v1/challenge` is unauthenticated, so a Firestore write per issuance would let a `curl` loop burn the free write quota. One Firestore document is written per `/attest`, `docId = hex(SHA-256(challenge))`, create-if-absent — `ALREADY_EXISTS` *is* the replay signal, atomically, with no transaction. `expireAt` + a TTL policy self-prunes at no cost.

**Verification pipeline** (cheapest and most-forgeable last):

1. Body sanity — chain 2–6 elements, each < 4 KB, valid DER.
2. Challenge HMAC recomputed, constant-time compare; reject if older than 120 s or future-dated.
3. `CertPathValidator("PKIX")` to a trust anchor in `ATTESTATION_ROOTS`, `isRevocationEnabled = false` (this PKI has no CRL/OCSP endpoints), ±24 h skew. Tolerate a device omitting the self-signed root.
4. Parse `KeyDescription` from leaf extension **OID 1.3.6.1.4.1.11129.2.1.17**.
5. `attestationChallenge` **exactly equals** the issued challenge — this is what binds the key to this session.
6. **Consume the nonce** (create-if-absent) — after the crypto, so garbage can't burn a nonce; before issuing a flag.
7. `attestationSecurityLevel ∈ {TrustedEnvironment, StrongBox}` and `keymasterSecurityLevel` agrees. Reject `Software`.
8. `attestationApplicationId` (tag 709, in `softwareEnforced`): **exactly one** `packageInfos` entry with `packageName == APP_PACKAGE` (exactly one, so a `sharedUserId` co-package cannot ride along), and `signatureDigests` contains `APP_SIGNER_SHA256`. **This is the anti-repackaging control.**
9. Key-property sanity from `hardwareEnforced`: purpose SIGN only, algorithm EC, digest SHA-256, `origin == GENERATED`, tag 600 `allApplications` absent.
10. Verify the PoP signature against the leaf public key. → **Flag 1**.
11. **Flag 2 only:** `rootOfTrust` (tag 704, must be in `hardwareEnforced`) with `deviceLocked == true` **and** `verifiedBootState == Verified`. Deliberately do *not* constrain `verifiedBootKey` to a known OEM set — that would exclude legitimate devices and make the intended solve unreachable.

Parse leniently (ignore unknown tags, no upper bound on `attestationVersion`) so future KeyMint revisions don't break the crackme.

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

`max-instances=3` is a cost circuit-breaker, not a performance setting.

Firebase Hosting rewrite `{"source":"/v1/**","run":{"serviceId":"crackme-l5","region":"us-central1"}}`, plus a static `index.html` at `/` with the brief and a live status widget — this stays up even if Cloud Run is entirely broken. Custom domain added in the Firebase console (TXT verification, then two A records) entered in Cloudflare **DNS-only / grey cloud**. **Fix CAA records first** — if the apex has a CAA that omits `pki.goog` and `letsencrypt.org`, managed certificate issuance stalls silently for days; this is the most common setup failure here. After issuance, confirm with `openssl s_client -connect <host>:443 -showcerts` that the live chain terminates in a pinned root, *then* freeze the pin set and build the APK.

**Cost: $0.00 steady state.** A few thousand attempts a month is a fraction of a percent of the Cloud Run and Firestore free tiers. Budget alerts at $1 / $5 / $20 to at least two addresses.

---

## Build, release and placement

- Keystore `uncrackable-l5.jks`, RSA-4096, `-validity 10950` (30 y), generated offline, two custodians. **Signing-key rotation (v3.1) must never be used** — rotation changes what lands in `attestationApplicationId`. Record this as a hard constraint in the repo README.
- `apksigner verify --print-certs` → "Signer #1 certificate SHA-256 digest" is exactly the value for `APP_SIGNER_SHA256`. Publishing it is fine; it is derivable from the APK.
- Ship a `Dockerfile` pinning JDK/Gradle/AGP/build-tools plus `./gradlew assembleRelease`, and publish the released APK's SHA-256. Verifiable in practice; don't over-promise bit-for-bit reproducibility.
- **Local development root: `/Users/dionysislorentzos/Development/Projects/OWASP/Uncrackable`** (currently empty and not a git repo — `git init` it first). Layout, which doubles as the eventual upstream layout:

  ```
  Uncrackable/
    app/          Kotlin Android client (Gradle)
    server/       Kotlin/Ktor backend (Gradle)
    infra/        gcloud deploy script or Terraform, firebase.json
    fixtures/     recorded attestation chains for the server tests
    README.md     brief, hard requirements, flag SHA-256s, intentional-omission notes
    SOLUTION.md   the writeup required by the contributing terms
  ```

- **Source published to** `github.com/OWASP/mas-crackmes` at `Android/Level5/` — the contents of the directory above. Committed: pins, backend URL, package name, signer digest. Never committed: keystore, `CHALLENGE_HMAC_KEY`, flags.
- **Binary** → `github.com/OWASP/mastg` at `Crackmes/Android/Level_05/UnCrackable-Level5.apk`.
- **Website**, following the existing pattern exactly (no front matter, `##` heading, `mas-chip` download link, `??? info "Installation"`, `??? danger "SPOILER (Solutions)"`, italic gray credit):
  - `docs/crackmes/Android.md` — new `## Android UnCrackable L5` section inserted before `## MASTG Hacking Playground`, with numbered flag objectives in the L4 style, and an Installation note stating the hard requirements: **internet access** and a **GMS-certified device with hardware attestation** (a stock AVD has no real attestation keybox and cannot work).
  - `docs/crackmes/index.md` — a `mas-app-row` block linking to `#android-uncrackable-l5`. New files under `docs/crackmes/` are picked up automatically by the awesome-pages `flat` glob at `mkdocs.yml:216-218`, but these are edits to existing files.
  - Optionally a `MASTG-APP-00XX.md` reference-app entry in `mastg/apps/android/` (`title`, `platform`, `package`, `source`, `weaknesses: [MASWE-0054, MASWE-0056]`) per `mastg/.github/instructions/mastg-apps.instructions.md` — use a placeholder ID in the PR.

---

## How it is solved (`SOLUTION.md`)

Pinning is implemented without a deliberate bypass. Flags arrive in a server response and are processed and stored by the genuine app after attestation. Runtime extraction can target network plaintext or local encryption/decryption. The advanced tier additionally depends on the explicitly omitted attestation revocation check and must be demonstrated before release.

### Recon (shared)

- Static: decompile with jadx. There are no embedded flag values. The `flag` response field and storage code reveal the provisioning and persistence flow. Recover the endpoint (`crackme.lorenzos.com/v1/...`), the challenge→attest→flag protocol, the OkHttp `CertificatePinner`, and the `network_security_config` system trust anchors. Distinguish certificate pinning from platform trust validation.
- Dynamic: a stock AVD is useless — it has no real attestation keybox, so it fails server-side at step 7. You need a **physical GMS-certified device**, and for anything involving Frida, a **rooted** one (Magisk).

### Flag 1 — read the response on a rooted device

The server for Flag 1 does not care about boot state, so a rooted device passes steps 1–10 as long as the app is unmodified and the traffic reaches the server intact. The network controls are certificate pinning plus platform trust validation. Two runtime routes:

- **Observe network plaintext.** Instrument the genuine app after TLS decryption, or
  bypass certificate pinning and ensure the proxy certificate also passes platform trust.
  A user CA is excluded by the configured trust anchors. A system-trusted proxy CA can
  satisfy platform trust, but cannot satisfy the configured pins without a runtime bypass.
- **Observe flag processing or storage.** Instrument parsing or the encryption/decryption
  boundary. The app legitimately handles plaintext before encryption and after decryption;
  extraction does not require exporting the Android Keystore key.

For Flag 1, the real device attests the genuine app for a fresh server challenge. The
solver observes the delivered flag in that process; copying its encrypted file alone
is not sufficient.

### Flag 2 — forge a clean boot state (keybox tier)

Flag 2 additionally demands `deviceLocked == true` and `verifiedBootState == Verified` in the **hardware-enforced** `rootOfTrust` — on a device that, to run Frida, is rooted and boot-unlocked. You cannot patch the values after the fact: they are signed inside the attestation chain by the device's attestation key.

The intended solve is the exact weakness `MASTG-BEST-0x01` documents and the server deliberately leaves open by **not checking revocation**:

- Use a leaked/extracted attestation **keybox** (a `keybox.xml` circulating in the community) together with a Keystore-hooking layer — **TrickyStore** (Magisk/Zygisk module) is the canonical tool. It intercepts `getCertificateChain`/attestation at the Keystore HAL and re-signs the leaf with the leaked attestation key, emitting a `rootOfTrust` that claims `Verified` + `deviceLocked` while the device is neither.
- Because the leaked keybox chains to a genuine Google attestation root, it passes path validation (step 3); because the server never consults `android.googleapis.com/attestation/status`, the revoked keybox is accepted at step 11. Flag 2 issued.
- If the chosen keybox is self-generated (chains to a non-Google root), it fails at step 3, not step 11 — the solver needs a genuine leaked one. A stock locked device can also pass, but obtaining its plaintext requires a separate demonstrated extraction capability. Neither repeated TLS failures nor the existence of an encrypted local file provides that capability.

**Takeaway:** attestation depends on the trustworthiness of its signing credentials.
Skipping revocation can admit known-compromised credentials. This proposed route needs
an end-to-end demonstration; enabling revocation would close the known-revoked-credential
route, not prove that all other extraction or attestation attacks are impossible.

---

## Verification

1. **Server unit tests** against recorded chains, committed as fixtures: a genuine `TrustedEnvironment` chain, a StrongBox chain, a `Software`/emulator chain (must fail step 7), a repackaged-app chain (must fail step 8), a replayed nonce (must fail step 6), an expired challenge, a tampered HMAC, and a chain whose `verifiedBootState` is `Unverified` (Flag 1 only, no Flag 2).
2. **Local end-to-end**: run the Ktor server locally, point a debug variant at it, confirm the full round trip on a physical GMS device. An emulator must be verified to *fail* at step 7 — that is a test, not a bug.
3. **Pinning proved**: a proxy with a user CA must fail platform trust; a system-trusted proxy CA must still fail certificate pinning. Repeat failures beyond two attempts and confirm there is no downgrade. With a runtime pinning bypass, a system-trusted proxy CA may succeed; a user-only CA still needs a trust bypass.
4. **Anti-relay audit**: `aapt dump badging` and a manifest diff on the release APK to confirm zero exported components beyond `MainActivity`, no intent filters beyond MAIN/LAUNCHER, `allowBackup=false`, `debuggable` absent.
5. **Flag lifecycle**: inspect the shipped APK for embedded flag values or bundled encrypted flags; the `flag` JSON key is allowed. After attestation, verify encrypted records survive process restart and decrypt correctly, IVs differ across writes, tampering fails authentication, and missing keys require re-attestation. Inspect app files, logs, caches and backup configuration for plaintext leakage. Demonstrate runtime extraction at the response or crypto boundary.
6. **Both intended solves walked end to end** and written up in `SOLUTION.md`: Flag 1 via root + Frida on the unmodified APK; Flag 2 via a keybox-forged `rootOfTrust`.
7. **Live monitoring**: a GitHub Actions cron in `mas-crackmes` doing a daily synthetic round trip (`/challenge` → malformed `/attest` → expect 403) that **opens an issue on failure**, so the community learns of an outage before the maintainer does.
8. **Website build**: `mkdocs serve` in `mas-website` (with the sibling `mastg` checkout present, since `docs/hooks/combine-repos.py` runs at `on_pre_build`), then `npx markdownlint-cli2 --config .markdownlint.jsonc`.

**No offline flag issuance or weakened attestation mode.** A fresh ATTEST action requires
the backend. Previously downloaded encrypted records may persist and be accessed locally;
they neither mint new flags nor establish current device integrity. Ship no embedded flag
or offline derivation mechanism. Publish flag SHA-256 digests for solver self-verification
and document a sunset plan for publishing plaintext flags when the service is retired.
