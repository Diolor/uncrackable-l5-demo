# Upstream provenance

Source: https://github.com/android/keyattestation
Revision: a48898a68337b920cbd368eab5824f696d7bbf3d
License: Apache-2.0 (see LICENSE). Kotlin sources are unchanged.

Integration changes: custom Gradle build; testing helpers moved to test fixtures;
VerifierCli.kt excluded from compilation (no embedded roots or upstream CLI).
The server supplies explicit trust anchors and a bounded, fail-closed status feed.
The upstream status helper filters REVOKED only; it is not used by our server.
Upstream rejects unknown authorization tags (including legacy allApplications),
and validates a specific Android chain structure. New-device compatibility needs tests.
