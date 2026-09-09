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
