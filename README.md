# Android UnCrackable L5

**Can you get the flag?**

A network-backed Android crackme for the OWASP MASTG crackme catalogue. Unlike the
earlier Android levels, **the flag is not inside the APK**. A backend issues it, over a
pinned TLS channel, only to a request carrying a fresh hardware-attested proof from the
genuine, correctly-signed build running on a locked device with verified boot. The client
stores the flag encrypted under a hardware-backed Android Keystore key. Extract the
plaintext flag.

Companion to the MASTG best practice on hardware-backed key attestation
([OWASP/mastg#3953](https://github.com/OWASP/mastg/pull/3953)).

## Download

| | |
| --- | --- |
| APK | [`release/UnCrackable-Level5.apk`](release/UnCrackable-Level5.apk) |
| APK SHA-256 | `3629bf9521c689eac32001a45f515237d84ad27a85aef935ea784acb3de7ae75` |
| Package | `org.owasp.mastg.uncrackable5`, versionName `1.0`, minSdk 28, targetSdk 36 |
| Signer SHA-256 | [`release/signer-sha256.txt`](release/signer-sha256.txt) |
| Backend | `https://crackme.lorentzos.com` |

```sh
adb install release/UnCrackable-Level5.apk
```

## Requirements

- Internet access. There is no offline mode.
- A GMS-certified physical device with hardware key attestation (TEE or StrongBox). An
  emulator has no attestation keybox and is rejected.
- A locked bootloader with verified boot. Receiving the flag on a stock device is a
  compatibility check, not a solve.

## Protocol

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
   challenge, signs the challenge with it, and sends the certificate chain plus the
   proof of possession.
3. The backend validates the chain against Google's attestation roots and status feed,
   requires hardware security levels, the exact package and signer, key properties, a
   locked and verified boot state, and the proof of possession. Only then does it consume
   the challenge and return the flag.
4. The app encrypts the flag with AES-256-GCM under a persistent hardware-backed Keystore
   key and stores only the ciphertext. The UI only confirms acceptance.

Each failure names the control that rejected the attempt, so a solver can tell a
pinning failure from a repackaging failure from a boot-policy failure. In a production
app that granularity would be a finding.

## Security assumptions

- TLS fails closed on every attempt: system trust anchors only, root-only pinning, no
  retry downgrade.
- The backend omits no check. Challenges are single-use, expire after 120 seconds and
  are bound to both the attestation and the proof of possession.
- App identity is `attestationApplicationId`: exactly one package and exactly the
  expected signer.
- Any serial in Google's attestation status feed is rejected, and the backend fails
  closed without a fresh snapshot.
- Attestation describes the state at key creation, not continuous process integrity.
  Runtime instrumentation of the genuine process on a device that still reports
  verified boot is the open research surface. See [SOLUTION.md](SOLUTION.md).

## Repository

| Path | Contents |
| --- | --- |
| [`android/`](android/app/README.md) | Kotlin Android client (Gradle project, module `:app`) |
| [`server/`](server/README.md) | Cloudflare Workers backend (TypeScript) with the attestation verifier |
| [`fixtures/`](fixtures/README.md) | Recorded device attestation requests used by the server tests |
| [`release/`](release/README.md) | Signed APK, public signing certificate, signing procedure |
| [`scripts/release-signing.py`](scripts/release-signing.py) | Local key custody and signed build |
| [`DESIGN.md`](DESIGN.md) | Why each control is the way it is |
| [`SOLUTION.md`](SOLUTION.md) | What counts as a solve |

Committed: root pins, backend origin, package name, public signing certificate and its
digest, Google attestation roots, recorded fixtures. Never committed: the signing
keystore, `CHALLENGE_HMAC_KEY`, flag values, hosting credentials.

## Build and test

```sh
(cd android && ./gradlew :app:testDebugUnitTest :app:assembleRelease)   # Android SDK 36
cd server && npm install && npm test && npm run corpus   # Node 22+
npx markdownlint-cli2 --config .markdownlint.jsonc
```

## Contributing

Follow the [OWASP MAS contributing guide](https://mas.owasp.org/contributing/). Do not
weaken the verifier, the pinning or the boot policy to make a solution possible; read
[DESIGN.md](DESIGN.md) first, several things that look like bugs are deliberate.

Parts of this repository were written with Claude Code and OpenAI Codex. All PRs must
disclose AI tool usage per OWASP MAS rules.
