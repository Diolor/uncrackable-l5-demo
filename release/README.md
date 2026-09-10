# Release

| File | Contents |
| --- | --- |
| `UnCrackable-Level5.apk` | The published, signed release APK (SHA-256 in the top-level README) |
| `signing-certificate.pem` | Public signing certificate |
| `signer-sha256.txt` | SHA-256 of the DER certificate; the backend's `APP_SIGNER_SHA256` |

## Signing key

The signing key is attested inside `attestationApplicationId`, so it must **never be
rotated or regenerated**; losing it makes the crackme unfixable. Keep encrypted backups
with at least two custodians and test recovery. Never commit the keystore or its
passwords, and never upload them to a hosting provider.

`scripts/release-signing.py create` generates one RSA-4096 JKS key, valid 30 years, in
`~/.android/uncrackable-l5-release/` (directory 0700) together with `signing.json` holding
the build credentials, and exports the public certificate and digest into this directory.
It refuses to overwrite an existing key.

## Signed build

```sh
python3 scripts/release-signing.py build
```

Builds `app/build/outputs/apk/release/app-release.apk` for the origin configured in
`app/build.gradle.kts`, passing passwords through the environment only. Verify before
publishing:

```sh
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
aapt dump badging app/build/outputs/apk/release/app-release.apk | grep -E "^package|debuggable|uses-permission"
shasum -a 256 app/build/outputs/apk/release/app-release.apk
```

Expect one signer whose digest equals `signer-sha256.txt`, package
`org.owasp.mastg.uncrackable5` with SDK 28 to 36, no `debuggable` flag and only the
`INTERNET` permission. Then copy the APK here, update the SHA-256 in the README and
confirm acceptance on a locked physical device.
