# Design

## Why this crackme exists

Every earlier Android crackme in the MAS catalogue is offline: the flag is in the APK and
the challenge is reverse engineering. None exercises the two controls modern apps use to
protect a secret that is provisioned only after server verification: hardware-backed
**key attestation** and **TLS pinning**. L5 turns the MASTG guidance on hardware-backed key
attestation ([OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953)) into something a
reader can attack. Solving it requires runtime instrumentation of the genuine binary on a
device that still reports verified boot; re-signing is rejected.

## Choices

**Key attestation, not Play Integrity or App Check.** The APK is distributed from GitHub,
never Play, so Play Integrity cannot give an app identity verdict. Key attestation carries
both halves in one artefact: `attestationApplicationId` (package plus signer digest) and
`rootOfTrust` (`verifiedBootState`, `deviceLocked`), with no Firebase or GMS SDK in the client.

**Freshness.** A server-issued, expiring, single-use challenge is bound to both the
attestation and the proof of possession. Attestation reports properties at key creation, not
continuous process integrity. The window between key creation, verification, flag delivery
and later local use is the research surface; no check is weakened to make it exploitable.

**No intentional TLS defect.** Certificate validation, hostname verification and pinning
fail closed on every attempt and never degrade after failures.

**Mandatory device gate.** Every flag requires hardware-enforced `deviceLocked == true` and
`verifiedBootState == VERIFIED`, a remotely provisioned attestation key, and a security patch
from the last twelve months. Responses carry `tier: 2`; there is no lower tier.

**Remotely provisioned keys only.** A factory keybox is a long-lived attestation key injected
at manufacture. Keyboxes leak, and a leaked one lets a rooted device sign an attestation that
claims any boot state, patch level and app identity until Google lists its serial in the
status feed. Remote Key Provisioning (RKP, mandatory for devices launching with Android 13)
gives each device short-lived attestation certificates from Google's servers for keys that
never leave its secure hardware. The server accepts only chains whose top intermediate is
Google's RKP CA (`CN=Droid CA2, O=Google LLC`), the test Google's verifier uses for
`ProvisioningMethod.REMOTELY_PROVISIONED`. Devices without RKP cannot receive a flag.
Revocation still applies to every certificate in an RKP chain.

**Recent patch.** The hardware-enforced OS, vendor and boot patch levels must each be at most
twelve calendar months old, the bar Play Integrity's strong verdict uses, and at most one
month ahead, since vendors sometimes ship the next bulletin early. A missing, malformed or
software-enforced-only value fails. Like the boot state, it is what the device reported when
the key was created.

**Diagnostic errors.** Each rejection names the control that fired. An opaque 403 would
leave a solver unable to tell repackaging from boot state, which is what L5 exists to teach.

## Client

**Identity is attested, so it is immutable:** package `org.owasp.mastg.uncrackable5`,
versionName `1.0`, `minSdk 28` (StrongBox API, reliable `attestationApplicationId`),
`targetSdk`/`compileSdk 36`. The signing key is never rotated: APK signature scheme v3.1
rotation changes what lands in `attestationApplicationId`.

**Attestation key.** Per attempt, a throwaway EC P-256 key in `AndroidKeyStore` under a
random alias with the server challenge as `setAttestationChallenge`, StrongBox first, TEE on
`StrongBoxUnavailableException` or a bare `ProviderException`, deleted in `finally`. The
chain comes from `getCertificateChain`; the same key signs the challenge as proof of possession.

**Flag storage.** Downloaded flags are encrypted with AES-256-GCM under a persistent AES key
in `AndroidKeyStore`, separate from the attestation key. The key must be hardware-backed on
creation and on every load (StrongBox or TEE on API 31+, `isInsideSecureHardware` on 28 to
30); anything else is discarded together with its records. Each record is
`version || tier || ivLength || iv || ciphertext || tag`, with `version || tier` as
authenticated data, written atomically to `noBackupFilesDir`. The shipped UI never decrypts;
plaintext exists in process only while an accepted response is being encrypted. A stored
record never satisfies a new attempt. Instrumentation of the authorised process can still
observe plaintext or drive the key; that is the intended surface.

**Pinning, two layers.** OkHttp `CertificatePinner` (runs after platform validation, so a
root pin actually works, and OR-s pins) plus `network_security_config.xml` with system
anchors only and no cleartext. Six root pins: GTS Root R1 to R4 and ISRG Root X1/X2,
computed from the CAs' published PEMs. Leaves and intermediates rotate unannounced, so
pinning them would only guarantee a break. Earliest root expiry is 2035. No refresh policy:
the APK is immutable and a pin change means a new APK.

**HTTP client.** `ConnectionSpec.RESTRICTED_TLS`, 15 s call timeout, no retry, no
redirects, no cookies, no cache, no logging in any build type, bounded response bodies.

**UI.** One activity, one button, one status line; the flag is never rendered.

| Status | Source |
| --- | --- |
| `Connect to the internet to obtain the flag.` | idle |
| `Attesting…` | in flight |
| `No connection to the server.` | DNS, connect, timeout |
| `Signing authority cannot be trusted.` | `SSLPeerUnverifiedException` (pin), `SSLHandshakeException` or `CertificateException` (trust) |
| `App signature is not verified.` | `app_integrity` |
| `This device has no hardware-backed attestation.` | `no_hardware_attestation` |
| `Device attestation key is not remotely provisioned by Google.` | `no_remote_provisioning` |
| `Device security update is older than twelve months.` | `security_patch_outdated` |
| `Attestation expired. Try again.` | `challenge_expired`, `challenge_replayed` |
| `Attestation could not be verified.` | `attestation_invalid`, protocol violation, local key failure |
| `Attestation service is unavailable. Try again later.` | 429 or 503 |
| `Device bootloader is not locked and verified.` | `device_integrity` |
| `The flag could not be stored securely. Try again.` | storage failure |
| `Accepted — device and app fully verified.` | `tier: 2` |

**Manifest and build.** `allowBackup="false"`, empty extraction rules, only `INTERNET`,
one exported activity with only MAIN/LAUNCHER, no services, receivers, providers, AndroidX,
Firebase or GMS. Release: minified, `dependenciesInfo` off, `Log` calls stripped by R8,
shipped as a universal APK so the installed bytes equal the published bytes. Obfuscation
stays light; L4 covers that, L5 is about the protocol.

## Server

A single Cloudflare Worker plus one Durable Object (`server/`). The attestation verifier is
a TypeScript port of Google's [android-key-attestation](https://github.com/android/keyattestation)
verifier, pinned to that library's verdicts by a frozen corpus (`server/README.md`).

**Challenge** `= ver(1) || tsSeconds(8) || nonce(32) || HMAC-SHA256(K, ·)[0..16)`, 57 bytes
(some KeyMint implementations reject challenges of 64 bytes or more). Issuance is stateless,
so an unauthenticated `curl` loop cannot exhaust storage. Consumption inserts
`SHA-256(challenge)` create-if-absent; "already exists" is the replay signal.

**Verification order.** Bound request size and chain shape; authenticate the challenge and
reject age of 120 s or more; validate the chain against the configured Google roots, including
leaf validity; reject any serial in Google's status feed (`REVOKED` and `SUSPENDED` alike),
failing closed when no snapshot fresher than five minutes exists; require the attested
challenge to equal the server challenge; require hardware attestation and key security
levels; require exactly one package entry with exactly the configured signer; require a
hardware-enforced generated P-256 SIGN-only key with SHA-256; require locked plus verified
boot; verify the proof of possession; then, on an otherwise valid attestation, require an
RKP-issued chain and current patch levels; recheck expiry; consume atomically; issue the flag.
Invalid proofs never consume a challenge. A store failure is a 503.

**Diagnostic errors are deliberate.** Accepted consequences: no uniform latency floor and no
per-response reference id. The flag, challenge and chain are never logged.

## Release

RSA-4096 signing key, 30-year validity, generated and kept offline (`release/README.md`).
`apksigner verify --print-certs` gives the signer digest the backend expects; it is derivable
from the APK, so publishing it is fine. The build is verifiable but not bit-for-bit
reproducible. Intended homes: source under `github.com/OWASP/mas-crackmes` `Android/Level5/`,
binary under `github.com/OWASP/mastg` `Crackmes/Android/Level_05/`. Publish flag digests for
self-verification, and the plaintext flags when the service is retired.
