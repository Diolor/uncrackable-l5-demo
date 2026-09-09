# Solution status

No release-build flag extraction has been demonstrated. The former tier-one route
using an unlocked rooted device is no longer a valid solution: every flag requires
hardware-enforced locked and VERIFIED boot, with all certificate, revocation, app
identity, freshness, possession and replay checks passing.

A stock device receiving and encrypting the flag is a compatibility test, not a solve.
Debug builds permit debugging and are not evidence of release resistance.

Runtime compromise on a device that still reports verified boot, or access to a
previously issued flag, remains research. Attestation records key-creation state and
cannot prove continuous process integrity. Unlocking may wipe both app data and keys.
A solve must demonstrate plaintext extraction and record device/OS, boot states,
timing, key survival and server verdict. Neither a hypothesis nor copied ciphertext
establishes a bypass. Do not weaken the verifier to make a solution possible.
