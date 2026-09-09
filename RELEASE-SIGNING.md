# Release signing

The private signing key signs APKs locally. The backend receives only the SHA-256
fingerprint of the DER signing certificate (`APP_SIGNER_SHA256`), paired with
`APP_PACKAGE=org.owasp.mastg.uncrackable5`. This is different from a TLS SPKI pin.
Never upload the keystore or its passwords to the hosting provider or commit them to Git.
See [Android app signing](https://developer.android.com/studio/publish/app-signing).

The signing key is attested inside `attestationApplicationId`, so it must **never be
rotated or regenerated**. Losing it makes the crackme unfixable. Keep encrypted backups
with at least two named custodians and test recovery.

## Public material in `release/`

| File | Contents |
| --- | --- |
| `UnCrackable-Level5.apk` | The published, signed release APK (SHA-256 in the README) |
| `signing-certificate.pem` | Public signing certificate |
| `signer-sha256.txt` | SHA-256 of the DER certificate; the value of `APP_SIGNER_SHA256` |
| `render-release.env.example` | Public identity variables for the hosted backend |

## Local custody and build

`scripts/release-signing.py create` creates one RSA-4096 JKS key, valid for 30 years,
in `~/.android/uncrackable-l5-release/` (directory 0700, files 0600). It refuses an
existing directory. `signing.json` in that directory contains the local build
credentials; treat the entire directory as private. The public certificate and SHA-256
fingerprint are exported into `release/` and may be committed.

`python3 scripts/release-signing.py build` signs a non-debuggable, optimized release APK
for the backend origin configured in `Mobile app/build.gradle.kts`. The helper passes
passwords through environment variables, never command-line arguments. The output is
`Mobile app/build/outputs/apk/release/app-release.apk`.

Verify a build before publishing it:

```sh
apksigner verify --print-certs "Mobile app/build/outputs/apk/release/app-release.apk"
aapt dump badging "Mobile app/build/outputs/apk/release/app-release.apk" | grep -E "^package|debuggable|uses-permission"
shasum -a 256 "Mobile app/build/outputs/apk/release/app-release.apk"
```

Expect exactly one signer whose certificate digest equals `release/signer-sha256.txt`, a
valid APK v2 signature, package `org.owasp.mastg.uncrackable5` with SDK 28–36, no
`debuggable` flag and only the `INTERNET` permission.

## Backend identity

The hosted launcher supports `DEMO_MODE=render-release`, which accepts only the release
package with the digest from `release/signer-sha256.txt`, and `render-debug`, which
accepts only the debug package with a developer debug signer. Never allow both signers
as a convenience fallback. `FLAG_TIER1` is reserved and never issued.

When switching the backend to release mode, deploy the server first, then install the
release APK and verify physical-device acceptance and rejection of the debug package.
