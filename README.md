# Android UnCrackable L5

A planned network-backed Android crackme. Flags are provisioned after server-side
hardware attestation; no flag payload is embedded in the shipped APK. TLS always
fails closed. Downloaded flags will be encrypted locally with Android Keystore.

Flag 1 targets runtime extraction. Flag 2 is an open research challenge with no
known demonstrated bypass under the documented assumptions. Revocation checking
is required for both tiers. There is no planted TLS downgrade or revocation hole.

Read [the design plan](UnCrackable-L5-Plan.md) and [repository guidance](AGENTS.md).

## Current implementation

The [backend runtime](server/README.md) has a Ktor application composition,
challenge protocol, Android attestation adapter, revocation cache and tests.
Run with Java 21:

```sh
./gradlew :server:test
```

The [Android client](<Mobile app/README.md>) implements attestation key generation, the pinned
OkHttp protocol client, AES-GCM Keystore persistence of downloaded flags and the
single-screen UI. On 2026-09-09 a debug build completed the full round trip against the
local backend on a physical OnePlus 9 Pro (Android 14, TEE, locked bootloader): tier 2
accepted, replayed and tampered proofs rejected, flag stored encrypted, no plaintext in
files or logs. The recorded chain is in `fixtures/`. The backend now includes a Firestore replay adapter, strict runtime
configuration, Netty launcher and container recipe. Distributed ingress limits,
deployment setup and live integration validation remain. No Firebase resources were changed.
Tests contain synthetic values, not challenge flags. Test certificate generators
are excluded from the runtime artifact.

Publication requires resolving the release decisions in the plan. A successful
Flag 2 exploit is not a release requirement; real-device validation is.
