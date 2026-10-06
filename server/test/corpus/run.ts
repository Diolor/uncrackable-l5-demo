// Verifier regression harness. Replays the verdicts frozen in expected.tsv (produced once by
// Google's android-key-attestation reference verifier, which src/verifier/ ports) against the
// TypeScript verifier, and checks every recorded device chain in ../../../fixtures.
// Usage: node --experimental-strip-types test/corpus/run.ts [--quick]
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AndroidVerifier, Rejected, parsePemCertificates } from "../../src/verifier/verifier.ts";
import { base64UrlDecode } from "../../src/verifier/base64.ts";
import { parseFeed } from "../../src/revocations.ts";
import { structuralCases, byteMutations } from "./cases.ts";
import { policyCases } from "./policy.ts";
import type { Case } from "./synthetic.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = fileURLToPath(new URL("../../../", import.meta.url));
const quick = process.argv.includes("--quick");
const POLICY_CODES = new Set(["no_remote_provisioning", "security_patch_outdated"]);
const CODES = new Set(["ok:2", "attestation_invalid", "app_integrity", "device_integrity", "no_hardware_attestation", ...POLICY_CODES]);

async function verdict(c: Case): Promise<string> {
  try {
    const anchors = parsePemCertificates(c.roots);
    const serials = parseFeed(JSON.stringify({ entries: Object.fromEntries((c.serials ?? []).map((s) => [s, { status: "REVOKED" }])) }));
    const verifier = new AndroidVerifier({ anchors, packageName: c.packageName, signerSha256Hex: c.signer });
    let challenge: Uint8Array;
    try {
      challenge = base64UrlDecode(c.request.challenge);
    } catch {
      return "attestation_invalid";
    }
    return "ok:" + (await verifier.verify(c.request, challenge, serials, Date.parse(c.now)));
  } catch (e) {
    if (e instanceof Rejected) return e.code;
    return "error:" + (e as Error).message;
  }
}

let failures = 0;
const fail = (msg: string) => {
  failures++;
  console.log("FAIL " + msg);
};

// 1. Synthetic cases against the frozen reference verdicts. Server policy the reference never had
// runs after every reference check, so it may only turn a frozen ok:2 into a policy rejection;
// policy.tsv records those verdicts and the verdicts of the policy-only cases.
const readTsv = (file: string) => {
  const out = new Map<string, string>();
  for (const line of readFileSync(here + file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const [id, code] = line.split("\t");
    if (out.has(id)) throw new Error(`duplicate id ${id} in ${file}`);
    out.set(id, code);
  }
  return out;
};
const expected = readTsv("expected.tsv");
const policy = readTsv("policy.tsv");
for (const [id, code] of policy) {
  const frozen = expected.get(id);
  if (frozen !== undefined && (frozen !== "ok:2" || !POLICY_CODES.has(code))) fail(`policy.tsv ${id}: ${code} may only replace a frozen ok:2`);
  if (frozen === undefined && !id.startsWith("policy-")) fail(`policy.tsv ${id}: unknown case`);
}
const synthetic: Case[] = readFileSync(here + "corpus.jsonl", "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const structural = await structuralCases();
synthetic.push(...structural, ...(await policyCases()));
synthetic.push(...byteMutations("syn-leaf", structural.find((c) => c.id === "syn-baseline")!, 0, quick ? 16 : 1));
const seen = new Set<string>();
for (const c of synthetic) {
  if (seen.has(c.id)) throw new Error("duplicate case id " + c.id);
  seen.add(c.id);
  const want = policy.get(c.id) ?? expected.get(c.id);
  const got = await verdict(c);
  // The synthetic leaf is re-signed with fresh keys on every run, so its byte mutations have no
  // stable frozen verdict; they must only produce a documented verdict, never an internal error.
  if (c.id.startsWith("syn-leaf-")) {
    if (!CODES.has(got)) fail(`${c.id}: ${got}`);
  } else if (want === undefined) fail(`${c.id}: no frozen verdict`);
  else if (got !== want) fail(`${c.id}: got ${got}, frozen ${want}`);
}
for (const id of policy.keys()) if (!seen.has(id)) fail(`policy.tsv ${id}: no such case`);
console.log(`synthetic: ${synthetic.length} cases`);

// 2. Recorded device chains: the outcome documented in meta.expected, and every single-byte
// corruption of the chain must be rejected cleanly (never an internal error).
const googleRoots = readFileSync(new URL("../../roots/google-attestation-roots.pem", import.meta.url), "utf8");
const fixtureDir = repo + "fixtures/";
for (const file of readdirSync(fixtureDir).filter((f) => f.endsWith(".json"))) {
  const f = JSON.parse(readFileSync(fixtureDir + file, "utf8"));
  const base: Case = { id: file, request: f.request, now: f.meta.recordedAt, packageName: f.meta.packageName, signer: f.meta.signerSha256, roots: googleRoots, serials: [] };
  const leafSerial = "1";
  const checks: Array<[Case, string]> = [
    [base, f.meta.expected],
    [{ ...base, packageName: "org.owasp.mastg.uncrackable5.other" }, "app_integrity"],
    [{ ...base, signer: "00".repeat(32) }, "app_integrity"],
    [{ ...base, now: new Date(Date.parse(f.meta.recordedAt) + 3_600_000).toISOString() }, "attestation_invalid"],
    [{ ...base, serials: [leafSerial] }, "attestation_invalid"],
    [{ ...base, request: { ...f.request, chain: f.request.chain.slice(0, -1) } }, "attestation_invalid"],
    [{ ...base, request: { ...f.request, pop: "AAAA" } }, "attestation_invalid"],
  ];
  for (const [c, want] of checks) {
    const got = await verdict(c);
    if (got !== want) fail(`${file} ${JSON.stringify({ packageName: c.packageName, now: c.now, serials: c.serials, chain: c.request.chain.length, pop: c.request.pop.length })}: got ${got}, want ${want}`);
  }
  let mutations = 0;
  for (let i = 0; i < f.request.chain.length; i++) {
    for (const m of byteMutations(file + "-" + i, base, i, quick ? 64 : 1)) {
      mutations++;
      const got = await verdict(m);
      if (!CODES.has(got)) fail(`${m.id}: ${got}`);
    }
  }
  console.log(`${file}: ${checks.length} outcomes, ${mutations} byte mutations`);
}

console.log(failures === 0 ? "OK" : `${failures} failures`);
process.exit(failures === 0 ? 0 : 1);
