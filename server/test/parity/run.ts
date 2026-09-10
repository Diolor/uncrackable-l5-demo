// Verifier regression harness. Compares TypeScript verdicts with the verdicts the Kotlin reference
// implementation (Google's android-key-attestation verifier) produced for the same cases, frozen in
// expected.tsv, and checks every recorded device chain in ../../../fixtures.
// Usage: node --experimental-strip-types test/parity/run.ts [--quick]
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AndroidVerifier, Rejected, parsePemCertificates } from "../../src/verifier/verifier.ts";
import { base64UrlDecode } from "../../src/verifier/base64.ts";
import { parseFeed } from "../../src/revocations.ts";
import { structuralCases, byteMutations } from "./cases.ts";
import type { Case } from "./synthetic.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = fileURLToPath(new URL("../../../", import.meta.url));
const quick = process.argv.includes("--quick");
const CODES = new Set(["ok:2", "attestation_invalid", "app_integrity", "device_integrity", "no_hardware_attestation"]);

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

// 1. Synthetic cases against the frozen Kotlin verdicts.
const expected = new Map<string, string>();
for (const line of readFileSync(here + "expected.tsv", "utf8").split("\n")) {
  if (!line.trim()) continue;
  const [id, code] = line.split("\t");
  expected.set(id, code);
}
const synthetic: Case[] = readFileSync(here + "corpus.jsonl", "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const structural = await structuralCases();
synthetic.push(...structural);
synthetic.push(...byteMutations("syn-leaf", structural.find((c) => c.id === "syn-baseline")!, 0, quick ? 16 : 1));
const seen = new Set<string>();
for (const c of synthetic) {
  if (seen.has(c.id)) throw new Error("duplicate case id " + c.id);
  seen.add(c.id);
  const want = expected.get(c.id);
  const got = await verdict(c);
  // The synthetic leaf is re-signed with fresh keys on every run, so its byte mutations have no
  // stable frozen verdict; they must only produce a documented verdict, never an internal error.
  if (c.id.startsWith("syn-leaf-")) {
    if (!CODES.has(got)) fail(`${c.id}: ${got}`);
  } else if (want === undefined) fail(`${c.id}: no frozen verdict`);
  else if (got !== want) fail(`${c.id}: typescript=${got} kotlin=${want}`);
}
console.log(`synthetic: ${synthetic.length} cases`);

// 2. Recorded device chains: documented outcomes at capture time, and every single-byte
// corruption of the chain must be rejected cleanly (never an internal error).
const googleRoots = readFileSync(new URL("../../roots/google-attestation-roots.pem", import.meta.url), "utf8");
const fixtureDir = repo + "fixtures/";
for (const file of readdirSync(fixtureDir).filter((f) => f.endsWith(".json"))) {
  const f = JSON.parse(readFileSync(fixtureDir + file, "utf8"));
  const base: Case = { id: file, request: f.request, now: f.meta.recordedAt, packageName: f.meta.packageName, signer: f.meta.signerSha256, roots: googleRoots, serials: [] };
  const leafSerial = "1";
  const checks: Array<[Case, string]> = [
    [base, "ok:2"],
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
