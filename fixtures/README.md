# Recorded attestation requests

Real `/v1/attest` request bodies (challenge, certificate chain, proof of possession)
recorded by the local integration launcher (`server/README.md`, "Local device
integration"). Nothing here is secret: the chain is the device's public attestation
certificate chain and the challenge was issued under a throwaway per-run HMAC key, so
these bodies cannot be replayed against any deployed backend.

| File | Device | Result |
| --- | --- | --- |
| `oneplus9pro-android14-tee-tier2.json` | OnePlus 9 Pro (LE2123), Android 14, locked bootloader, verified boot green, no StrongBox; debug build `org.owasp.mastg.uncrackable5.debug` signed with the developer's debug key | Accepted, tier 2, 2026-09-09 |

The `local/` subdirectory is the launcher's live recording directory and is ignored by Git.

`./gradlew :server:test` runs `RecordedAttestationTest` against the committed OnePlus
request through the production verifier, including chain validation, attestation
parsing, challenge matching and proof of possession. It asserts tier 2 for the debug
identity and `app_integrity` for the release package. The test uses the committed
Google roots, the capture-time clock (the leaf has a five-minute lifetime), and an
injected empty revocation snapshot. It needs no device or live service and catches
verifier updates that break this chain's structure. It does not authenticate the old
challenge's HMAC, exercise replay consumption, establish current revocation status,
or validate a release-signed build.
