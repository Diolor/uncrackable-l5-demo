# Android client

Kotlin, no AndroidX, no Firebase or GMS. One activity, one button, one status line. The
flag is never rendered, logged, copied or shared; success only confirms a tier.

| File | Role |
| --- | --- |
| `Attestation.kt` | Per-attempt EC P-256 key in AndroidKeyStore attested against the server challenge (StrongBox first, TEE fallback), chain export, proof of possession, key deleted in `finally` |
| `Backend.kt` | The only HTTP client: OkHttp with `RESTRICTED_TLS`, root-only `CertificatePinner`, no redirects, retry or cache, bounded bodies |
| `Pins.kt` | SPKI SHA-256 pins for GTS Root R1 to R4 and ISRG Root X1/X2, computed from `pins/` |
| `FlagStore.kt`, `FlagRecord.kt` | AES-256-GCM records under a persistent hardware-backed Keystore key, tier bound as AAD, atomic replace in `noBackupFilesDir` |
| `Status.kt` | Maps every outcome and exception to one status string |
| `res/xml/network_security_config.xml` | System trust anchors only, no cleartext |

## Build

```sh
./gradlew :app:testDebugUnitTest :app:assembleRelease
```

The release build bakes in `https://crackme.lorentzos.com` (override with
`-PcrackmeReleaseBaseUrl=https://...`) and is signed only when the `UNCRACKABLE_KEYSTORE*`
variables are set; see [`release/README.md`](../release/README.md). JVM tests cover the
challenge format, record encoding and status mapping; Keystore behaviour is validated on
physical devices.

## Local integration (debug build)

The debug build has application id `org.owasp.mastg.uncrackable5.debug`, takes its
backend URL from a Gradle property, and permits cleartext to loopback so a local Worker
can be used. It attests its own package and signer, so the local Worker needs
`APP_PACKAGE=org.owasp.mastg.uncrackable5.debug` and the debug signer digest in
`server/.dev.vars`.

```sh
./gradlew :app:installDebug -PcrackmeBaseUrl=http://127.0.0.1:8787
adb reverse tcp:8787 tcp:8787
(cd server && npx wrangler dev)
```

Pinning does not apply to plaintext, so this exercises attestation and storage but not
pinning; verify pinning against the deployed origin.

## Verifying the pins

```sh
for f in android/app/pins/*.pem; do
  openssl x509 -in "$f" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
done
```

The output must match `Pins.ROOT_SPKI_SHA256` in order R1, R2, R3, R4, X1, X2.
