# Release signing

The private signing key signs APKs locally. The backend receives only the SHA-256
fingerprint of the DER signing certificate (`APP_SIGNER_SHA256`), paired with
`APP_PACKAGE=org.owasp.mastg.uncrackable5`. This is different from a TLS SPKI pin.
Never upload the keystore or its passwords to Render or commit them to Git.
See [Android app signing](https://developer.android.com/studio/publish/app-signing).

## Local custody and build

`scripts/release-signing.py create` creates one RSA-4096 JKS key, valid for 30 years,
in `~/.android/uncrackable-l5-release/` (directory 0700, files 0600). It refuses an
existing directory. `signing.json` in that directory contains the local build
credentials; treat the entire directory as private. Public certificate and SHA-256
fingerprint are exported into `release/` and may be committed.

Run `python3 scripts/release-signing.py build` to sign a non-debuggable, optimized
release APK for `https://uncrackable-l5-demo.onrender.com`. The helper passes passwords
through environment variables, never command-line arguments. The output is
`Mobile app/build/outputs/apk/release/app-release.apk`.

This is a demo candidate, not the frozen public release. Arrange encrypted backups
with at least two named custodians and test recovery before publication. One local
copy does not satisfy that requirement. Do not regenerate or rotate the signing key.
Resolve the final hostname and rebuild before freezing the published APK.

## Backend rollout

The Render launcher supports `DEMO_MODE=render-release`, which accepts only the
release package, and `render-debug`, which accepts only the debug package. Set
`APP_SIGNER_SHA256` to `release/signer-sha256.txt` for release mode. The public values are ready in `release/render-release.env.example`. Never allow both
signers as a convenience fallback. Keep the existing DEMO-prefixed flags and HMAC
secret; neither belongs in the APK. `FLAG_TIER1` is reserved and never issued.

Deploy the updated server before switching its environment to release mode. Then
install the release APK and verify physical-device acceptance and debug-package
rejection. Old debug-device evidence does not establish a release end-to-end pass.

## Local validation (2026-09-09)

- Backend: 32 tests passed; the optional live Postgres integration test was skipped.
  Includes all unlocked/non-VERIFIED boot combinations, software-only boot evidence,
  legacy tier-one refusal, HTTP rejection without a flag, and the recorded OnePlus chain.
- Android: 9 unit tests passed. Optimized release APK assembled successfully.
- `apksigner verify`: one RSA-4096 signer, valid APK v2 signature. Certificate SHA-256
  matches `release/signer-sha256.txt`. `aapt dump badging`: release package, SDK 28–36,
  no debuggable flag. The APK contains the temporary Render HTTPS origin.
- APK SHA-256: `df1ca2106abb1da3096906d111441b07122ae45917df68ada30eb00125271aee`.

These changes are prepared locally. The hosted demo has not been redeployed or
switched to the release identity by this change. A physical release-device round
trip and rejection of the debug package remain rollout checks.

Implementation assistance: OpenAI Codex.
