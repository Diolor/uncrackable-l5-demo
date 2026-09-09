# Android client

Kotlin, no AndroidX, no Firebase/GMS SDKs. One activity, one button, one status line.
The flag is never rendered, logged, copied or shared; success only confirms a tier.

Persistent AES keys must be hardware-backed on creation and on every load. API 31+
accepts only StrongBox or TEE; API 28–30 requires `KeyInfo.isInsideSecureHardware`.
Rejected keys and their records are discarded, and metadata failures prevent key use.
Storage failure is reported instead of acceptance. JVM tests do not exercise Android
Keystore; this policy is validated on physical devices.

| File | Role |
| --- | --- |
| `Attestation.kt` | Per-attempt EC P-256 key in AndroidKeyStore attested against the server challenge (StrongBox first, TEE fallback), chain export, proof of possession, key deleted in `finally`. |
| `Backend.kt` | The only HTTP client: OkHttp with `RESTRICTED_TLS`, root-only `CertificatePinner`, no redirects, no retry, no cache, bounded bodies. `/v1/challenge` → `/v1/attest`. |
| `Pins.kt` | SPKI SHA-256 pins for GTS Root R1–R4 and ISRG Root X1/X2, computed from the PEMs in `pins/`. |
| `FlagStore.kt` / `FlagRecord.kt` | AES-256-GCM encryption of downloaded flags under a persistent hardware-backed Keystore key, tier bound as AAD, atomic replace in `noBackupFilesDir`, corrupt or unkeyed records discarded. The shipped UI never calls `read`. |
| `Status.kt` | Maps every outcome and exception to exactly one of the documented status strings. |
| `res/xml/network_security_config.xml` | System trust anchors only, no cleartext. |

## Build

Run these commands from the repository root. The Android project lives in
`Mobile app/` and has the Gradle module name `:app`; the backend lives in `server/`.

```sh
./gradlew :app:testDebugUnitTest :app:assembleRelease
```

The release build bakes in `https://crackme.lorentzos.com` as the backend origin (the
published 1.0 APK was built against `https://uncrackable-l5-demo.onrender.com`) (override with `-PcrackmeReleaseBaseUrl=https://...`). The release APK is unsigned
unless `UNCRACKABLE_KEYSTORE`, `UNCRACKABLE_KEYSTORE_PASSWORD`, `UNCRACKABLE_KEY_ALIAS`
and `UNCRACKABLE_KEY_PASSWORD` are set; see [RELEASE-SIGNING.md](../RELEASE-SIGNING.md).
The keystore is never committed and the signing key must never be rotated, because the
signer digest is attested.

## Local integration (debug build only)

The debug build has application id `org.owasp.mastg.uncrackable5.debug`, takes its
backend URL from a Gradle property, and its `network_security_config` overlay permits
cleartext to loopback / `10.0.2.2` / `*.local` so a local Ktor server can be used:

```sh
adb reverse tcp:8080 tcp:8080   # physical device over USB
./gradlew :app:installDebug -PcrackmeBaseUrl=http://127.0.0.1:8080
```

Only a debug build with an `http://` base URL adds `ConnectionSpec.CLEARTEXT` to the OkHttp
client; release builds are `RESTRICTED_TLS` only and cannot dial plaintext at all. See
`server/README.md` ("Local device integration") for the matching local backend launcher.

`CertificatePinner` does not apply to plaintext connections, so a debug build against a
local HTTP server exercises attestation and storage but not pinning. Pinning is verified
against the deployed TLS endpoint. A debug build attests its own package name and debug
signer, so the local server must be configured with those values. A standard emulator
must not receive a flag; record its observed failure rather than assuming an exact error
code, since local key generation or certificate trust may fail first.

## Verifying the pins

```sh
for f in "Mobile app"/pins/*.pem; do
  openssl x509 -in "$f" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
done
```

The output must match `Pins.ROOT_SPKI_SHA256` in order R1, R2, R3, R4, X1, X2.
