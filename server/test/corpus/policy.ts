// Cases for the server policy that runs after the reference verifier: remotely provisioned
// attestation keys only, and OS, vendor and boot patch levels at most twelve months old.
// The reference never had this policy, so these verdicts live only in policy.tsv.
import { buildChain, toCase, keyDescription, hwList, swList, rootOfTrust, bool, ctx, int, enumerated, name, NOW } from "./synthetic.ts";
import type { Case, ChainOpts } from "./synthetic.ts";
import type { Bytes } from "./der-writer.ts";

const DAY = 86_400_000;

/** hardwareEnforced list with all three patch levels; null removes one. NOW is 2025-01-01. */
function patched(os: Bytes | null = int(202409), vendor: Bytes | null = int(20240905), boot: Bytes | null = int(20240905), overrides: Record<number, Bytes | null> = {}): Bytes {
  const extra: Bytes[] = [];
  if (vendor) extra.push(ctx(718, vendor));
  if (boot) extra.push(ctx(719, boot));
  return hwList({ 706: os, ...overrides }, extra);
}

export async function policyCases(): Promise<Case[]> {
  const out: Case[] = [];
  const keys = (await buildChain({ remote: true })).keys;
  const add = async (id: string, opts: ChainOpts, extra: Parameters<typeof toCase>[2] = {}) => {
    const built = await buildChain({ remote: true, ...opts }, keys);
    out.push(await toCase(id, built, extra));
  };
  const strongBox = { attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) };

  // --- Provisioning method ---
  await add("policy-rkp-current", { kd: keyDescription({ hw: patched() }) });
  await add("policy-rkp-strongbox-current", { remoteLevel: "StrongBox", kd: keyDescription({ ...strongBox, hw: patched() }) });
  await add("policy-factory-current", { remote: false, kd: keyDescription({ hw: patched() }) });
  await add("policy-factory-strongbox-current", { remote: false, intermediateSubject: name(["serialNumber", "e18c4f2ca699739a"], ["title", "StrongBox"]), kd: keyDescription({ ...strongBox, hw: patched() }) });
  await add("policy-unknown-provisioning-current", { remote: false, intermediateSubject: name(["cn", "Droid CA2"], ["o", "Google"]), kd: keyDescription({ hw: patched() }) });
  await add("policy-factory-outdated", { remote: false, kd: keyDescription({ hw: patched(int(202301)) }) });
  await add("policy-rkp-revoked-intermediate", { kd: keyDescription({ hw: patched() }) }, { serials: ["1234567891"] });

  // --- Patch level window: [2024-01, 2025-02] at NOW ---
  await add("policy-patch-oldest-month", { kd: keyDescription({ hw: patched(int(202401), int(20240101), int(20240101)) }) });
  await add("policy-patch-os-13-months", { kd: keyDescription({ hw: patched(int(202312)) }) });
  await add("policy-patch-vendor-13-months", { kd: keyDescription({ hw: patched(undefined, int(20231231)) }) });
  await add("policy-patch-boot-13-months", { kd: keyDescription({ hw: patched(undefined, undefined, int(20231201)) }) });
  await add("policy-patch-os-missing", { kd: keyDescription({ hw: patched(null) }) });
  await add("policy-patch-vendor-missing", { kd: keyDescription({ hw: patched(undefined, null) }) });
  await add("policy-patch-boot-missing", { kd: keyDescription({ hw: patched(undefined, undefined, null) }) });
  await add("policy-patch-software-enforced-only", { kd: keyDescription({ hw: patched(null, null, null), sw: swList({}, [ctx(706, int(202409)), ctx(718, int(20240905)), ctx(719, int(20240905))]) }) });
  await add("policy-patch-next-month", { kd: keyDescription({ hw: patched(int(202502), int(20250201), int(20250201)) }) });
  await add("policy-patch-two-months-ahead", { kd: keyDescription({ hw: patched(int(202503)) }) });
  await add("policy-patch-yyyymm-vendor-boot", { kd: keyDescription({ hw: patched(undefined, int(202409), int(202409)) }) });
  await add("policy-patch-yyyymmdd-os", { kd: keyDescription({ hw: patched(int(20240905)) }) });
  await add("policy-patch-month-13", { kd: keyDescription({ hw: patched(int(202413)) }) });
  await add("policy-patch-month-00", { kd: keyDescription({ hw: patched(int(202400)) }) });
  await add("policy-patch-7-digits", { kd: keyDescription({ hw: patched(undefined, int(2024095)) }) });
  await add("policy-patch-short", { kd: keyDescription({ hw: patched(int(2024)) }) });
  await add("policy-patch-negative", { kd: keyDescription({ hw: patched(int(-202409)) }) });
  await add("policy-patch-zero", { kd: keyDescription({ hw: patched(int(0)) }) });

  // --- Clock: the same 2024-09 patch before and after it ages out ---
  const sept = Date.parse("2025-09-30T23:59:59Z");
  const oct = Date.parse("2025-10-01T00:00:00Z");
  await add("policy-patch-last-current-second", { nowMs: sept, kd: keyDescription({ hw: patched() }) }, { now: sept });
  await add("policy-patch-first-outdated-second", { nowMs: oct, kd: keyDescription({ hw: patched() }) }, { now: oct });

  // --- Policy runs after every reference check ---
  await add("policy-unlocked-outdated", { kd: keyDescription({ hw: patched(int(202301), undefined, undefined, { 704: rootOfTrust({ locked: bool(false) }) }) }) });
  await add("policy-factory-bad-pop", { remote: false, kd: keyDescription({ hw: patched() }) }, { pop: new Uint8Array(70) });
  await add("policy-rkp-leaf-expired", { leafNotAfter: NOW - DAY, kd: keyDescription({ hw: patched(int(202301)) }) });
  return out;
}
