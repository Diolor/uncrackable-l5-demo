# Android UnCrackable L5

A network-backed Android crackme for the OWASP MASTG crackme catalogue. Unlike the
earlier Android levels, **the flag is not inside the APK**. It is issued by a backend,
over a pinned TLS channel, only to a request that carries a fresh hardware-attested proof
from the genuine, correctly-signed build running on a locked device with verified boot.
The client encrypts the received flag with a hardware-backed Android Keystore key. The
challenge is to extract the plaintext flag.

This crackme is the hands-on companion to the MASTG best practice on hardware-backed key
attestation ([OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953)).

## Download

| Artefact | Value |
| --- | --- |
| APK | [`release/UnCrackable-Level5.apk`](release/UnCrackable-Level5.apk) |
| APK SHA-256 | `a2ab837e8a57bcd79726610b9de75dec7f1a5bd6cf701e372da1dfd6af911aaa` |
| Package | `org.owasp.mastg.uncrackable5`, versionName `1.0`, minSdk 28, targetSdk 36 |
| Signer certificate SHA-256 | [`release/signer-sha256.txt`](release/signer-sha256.txt) |
| Backend | `https://uncrackable-l5-demo.onrender.com` |

Install with `adb install release/UnCrackable-Level5.apk`. Verify the download with
`sha256sum` and the signer with `apksigner verify --print-certs`.

## Hard requirements

- **Internet access.** There is no offline mode and no embedded flag.
- **A GMS-certified physical device with hardware key attestation** (TEE or StrongBox).
  A stock emulator has no attestation keybox and is rejected as `no_hardware_attestation`.
- **A locked bootloader with verified boot.** Unlocked, unverified or software-only boot
  evidence never releases a flag. Receiving the flag on a stock device is a compatibility
  check, not a solve.

## How it works

```text
GET  /v1/challenge -> {"challenge":"<b64url 57B>","expiresIn":120}
POST /v1/attest    <- {"challenge":..,"chain":[..],"pop":..}
                   -> 200 {"tier":2,"flag":".."}
                   -> 403 {"error":"device_integrity" | "app_integrity" |
                            "no_hardware_attestation" | "challenge_expired" |
                            "challenge_replayed" | "attestation_invalid"}
                   -> 503 {"error":"verification_unavailable"}
GET  /v1/health    -> {"status":"ok"}
```

1. The app fetches a single-use, HMAC-authenticated challenge.
2. It generates a throwaway EC P-256 key in `AndroidKeyStore` attested against that
   challenge (StrongBox first, TEE fallback), signs the challenge with it, and sends the
   certificate chain plus the proof of possession.
3. The backend validates the chain against Google's attestation roots, checks every
   certificate against Google's attestation status feed, requires hardware security
   levels, the exact package and signer, key properties, a locked and verified boot state,
   and the proof of possession. Only then does it consume the challenge atomically and
   return the flag.
4. The app encrypts the flag with AES-256-GCM under a persistent hardware-backed Keystore
   key and stores only the ciphertext. The UI never displays the flag; it only confirms
   acceptance.

The status line is deliberately diagnostic. Each failure names the control that rejected
the attempt, so a solver can tell a pinning failure from a repackaging failure from a boot
policy failure. In a production app that granularity would be a finding.

## Security assumptions

- Certificate validation, hostname verification and root pinning fail closed on every
  attempt. There is no retry downgrade, permissive trust manager or user-CA trust.
- The backend has no intentionally omitted or weakened check. Challenges are single-use,
  expire after 120 seconds, and are bound to both the attestation and the proof of
  possession.
- App identity is enforced through `attestationApplicationId`: exactly one package and
  exactly the expected signer. Re-signing the APK is rejected under normal platform and
  attestation trust assumptions.
- Revocation is mandatory. Any serial listed in Google's status feed, including
  `SUSPENDED`, is rejected, and the backend fails closed when no fresh snapshot is
  available.
- Attestation describes the state at key creation. It is not continuous process
  integrity, and it is not a universal anti-relay proof. Runtime instrumentation of the
  genuine process on a device that still reports verified boot is the open research
  surface. See [SOLUTION.md](SOLUTION.md).

## Repository layout

| Path | Contents |
| --- | --- |
| [`Mobile app/`](<Mobile app/README.md>) | Kotlin Android client (Gradle module `:app`) |
| [`server/`](server/README.md) | Kotlin/Ktor backend, verifier adapter, revocation cache, tests |
| [`server/DEPLOYMENT.md`](server/DEPLOYMENT.md) | Container build and the hosted deployment |
| [`third_party/android-keyattestation/`](third_party/android-keyattestation/UPSTREAM.md) | Google's Android key attestation verifier, pinned revision |
| [`fixtures/`](fixtures/README.md) | Recorded real-device attestation requests used by server tests |
| [`release/`](release/) | Signed APK, public signing certificate and signer digest |
| [`scripts/release-signing.py`](scripts/release-signing.py) | Local release-key custody and signed build helper |
| [`DESIGN.md`](DESIGN.md) | Design rationale and the reasoning behind each control |
| [`RELEASE-SIGNING.md`](RELEASE-SIGNING.md) | Signing-key custody and release build procedure |
| [`SOLUTION.md`](SOLUTION.md) | Research status and what counts as a solve |

## Build and test

Requires Java 21 for the server and the Android SDK (compileSdk 36) for the client.

```sh
./gradlew :server:test :app:testDebugUnitTest
```

Server tests run the real verifier against synthetic signed chains and the recorded
OnePlus 9 Pro chain in `fixtures/`; no device, credentials or live service are needed.
The Android unit tests cover the challenge format, flag record encoding and status mapping.
Android Keystore behaviour is validated on physical hardware, not in JVM tests.

To build the client see [`Mobile app/README.md`](<Mobile app/README.md>). Release
signing requires the private keystore, which is never committed.

## What is and is not committed

Committed: root pins, backend origin, package name, public signing certificate and its
digest, Google attestation roots, recorded attestation fixtures.

Never committed: the signing keystore and its passwords, `CHALLENGE_HMAC_KEY`, flag values,
hosting credentials.

## Contributing

Follow the [OWASP MAS contributing guide](https://mas.owasp.org/contributing/). Markdown is
linted with the shared MAS configuration:

```sh
npx markdownlint-cli2 --config .markdownlint.jsonc
```

Do not weaken the verifier, the pinning or the boot policy to make a solution possible.
Read [DESIGN.md](DESIGN.md) before changing behaviour; several things that look like
bugs are deliberate.

AI-assisted development disclosure: parts of this repository were written with Claude Code
and OpenAI Codex. All PRs must disclose AI tool usage per OWASP MAS rules.
