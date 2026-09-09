# Android client

Kotlin, no AndroidX, no Firebase/GMS SDKs. One activity, one button, one status line.
The flag is never rendered, logged, copied or shared; success only confirms a tier.

| File | Role |
|---|---|
| `Attestation.kt` | Per-attempt EC P-256 key in AndroidKeyStore attested against the server challenge (StrongBox first, TEE fallback), chain export, proof of possession, key deleted in `finally`. |
| `Backend.kt` | The only HTTP client: OkHttp with `RESTRICTED_TLS`, root-only `CertificatePinner`, no redirects, no retry, no cache, bounded bodies. `/v1/challenge` → `/v1/attest`. |
| `Pins.kt` | SPKI SHA-256 pins for GTS Root R1–R4 and ISRG Root X1/X2, computed from the PEMs in `pins/`. |
| `FlagStore.kt` / `FlagRecord.kt` | AES-256-GCM encryption of downloaded flags under a persistent Keystore key, tier bound as AAD, atomic replace in `noBackupFilesDir`, corrupt or unkeyed records discarded. |
| `Status.kt` | Maps every outcome and exception to exactly one of the documented status strings. |
| `res/xml/network_security_config.xml` | System trust anchors only, no cleartext. |

## Build

```sh
./gradlew :app:testDebugUnitTest :app:assembleRelease
```

The release APK is unsigned unless `UNCRACKABLE_KEYSTORE`, `UNCRACKABLE_KEYSTORE_PASSWORD`,
`UNCRACKABLE_KEY_ALIAS` and `UNCRACKABLE_KEY_PASSWORD` are set. The keystore is never
committed and the signing key must never be rotated (the signer digest is attested).

## Local integration (debug build only)

The debug build has application id `org.owasp.mastg.uncrackable5.debug`, takes its
backend URL from a Gradle property, and its `network_security_config` overlay permits
cleartext to loopback / `10.0.2.2` / `*.local` so a local Ktor server can be used:

```sh
./gradlew :app:installDebug -PcrackmeBaseUrl=http://10.0.2.2:8080
```

`CertificatePinner` does not apply to plaintext connections, so a debug build against a
local HTTP server exercises attestation and storage but not pinning. Pinning is verified
against the deployed TLS endpoint with the release build. A debug build attests its own
package name and debug signer, so the local server must be configured with those values.
An emulator has no real attestation keybox and must be rejected with
`no_hardware_attestation`; a physical GMS-certified device is required for acceptance.

## Verifying the pins

```sh
for f in app/pins/*.pem; do
  openssl x509 -in "$f" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
done
```

The output must match `Pins.ROOT_SPKI_SHA256` in order R1, R2, R3, R4, X1, X2.
