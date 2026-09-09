# Android UnCrackable L5

A planned network-backed Android crackme. Flags are provisioned after server-side
hardware attestation; no flag payload is embedded in the shipped APK. TLS always
fails closed. Downloaded flags will be encrypted locally with Android Keystore.

Flag 1 targets runtime extraction. Flag 2 is an open research challenge with no
known demonstrated bypass under the documented assumptions. Revocation checking
is required for both tiers. There is no planted TLS downgrade or revocation hole.

Read [the design plan](UnCrackable-L5-Plan.md) and [repository guidance](AGENTS.md).

## Current implementation

The [local backend milestone](server/README.md) has a Ktor application composition,
challenge protocol, Android attestation adapter, revocation cache and tests.
Run with Java 21:

```sh
./gradlew :server:test
```

The [Android client](app/README.md) implements attestation key generation, the pinned
OkHttp protocol client, AES-GCM Keystore persistence of downloaded flags and the
single-screen UI; it builds and passes unit tests but has not yet been validated on a
physical device. The Firestore adapter, production runtime and deployment are not
implemented yet. No Firebase resources were changed.
Tests contain synthetic values, not challenge flags. Test certificate generators
are excluded from the runtime artifact.

Publication requires resolving the release decisions in the plan. A successful
Flag 2 exploit is not a release requirement; real-device validation is.
