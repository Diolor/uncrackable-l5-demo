# Recorded attestation requests

Real `/v1/attest` request bodies recorded from a physical device against a local Worker,
with the metadata `npm run parity` needs to replay them:

```json
{ "meta": { "device", "packageName", "signerSha256", "recordedAt" },
  "request": { "challenge", "chain", "pop" } }
```

Nothing here is secret or replayable: the chain is the device's attestation certificate
chain, whose intermediate certificates are shared by a production batch of devices, the
leaf carries no device identifiers, and the challenge was issued under a throwaway per-run
HMAC key. Record fixtures with a throwaway debug signing key, never a personal one.

| File | Device | Outcome |
| --- | --- | --- |
| `oneplus9pro-android14-tee-tier2.json` | OnePlus 9 Pro (LE2123), Android 14, TEE, locked, verified boot; debug package | Accepted, tier 2 |

To record a new fixture, run the debug build against `wrangler dev` (see
[`app/README.md`](../app/README.md)) behind a small proxy that writes each `/v1/attest`
body to disk, then add the `meta` block.
