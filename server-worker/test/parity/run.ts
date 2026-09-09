// Parity harness: runs the TypeScript verifier and the Kotlin oracle over the same cases and diffs verdicts.
// Usage: node --experimental-strip-types test/parity/run.ts [--quick]
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { AndroidVerifier, Rejected, parsePemCertificates } from "../../src/verifier/verifier.ts";
import { base64UrlDecode } from "../../src/verifier/base64.ts";
import { parseFeed } from "../../src/revocations.ts";
import { structuralCases, byteMutations } from "./cases.ts";
import type { Case } from "./synthetic.ts";

const here = fileURLToPath(new URL(".", import.meta.url));
const repo = fileURLToPath(new URL("../../../", import.meta.url));
const outDir = here + "out/";
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const quick = process.argv.includes("--quick");

// 1. Cases
const cases: Case[] = [];
const corpusPath = outDir + "corpus.jsonl";
if (existsSync(corpusPath)) {
  for (const line of readFileSync(corpusPath, "utf8").split("\n")) if (line.trim()) cases.push(JSON.parse(line));
} else console.warn("corpus.jsonl missing; run the Kotlin ParityCorpus generator first");

const fixture = JSON.parse(readFileSync(repo + "fixtures/oneplus9pro-android14-tee-tier2.json", "utf8"));
const googleRoots = readFileSync(repo + "server/roots/google-attestation-roots.pem", "utf8");
const recorded: Case = {
  id: "recorded-oneplus-debug", request: fixture, now: "2026-09-09T18:52:11Z",
  packageName: "org.owasp.mastg.uncrackable5.debug", signer: "5bb26e313b60dcb38bf264e8e152111fc76ed51e12ec77d1073be3323beb53be", roots: googleRoots, serials: [],
};
cases.push(recorded, { ...recorded, id: "recorded-oneplus-release", packageName: "org.owasp.mastg.uncrackable5" });
cases.push({ ...recorded, id: "recorded-oneplus-expired", now: "2026-09-09T19:00:00Z" });
cases.push({ ...recorded, id: "recorded-oneplus-revoked-root", serials: ["d50ff25ba3f2d6b3"] });
cases.push({ ...recorded, id: "recorded-oneplus-revoked-leaf", serials: ["1"] });
cases.push({ ...recorded, id: "recorded-oneplus-no-root", request: { ...fixture, chain: fixture.chain.slice(0, 3) } });
cases.push({ ...recorded, id: "recorded-oneplus-no-root-no-anchors-match", request: { ...fixture, chain: fixture.chain.slice(0, 3) }, roots: googleRoots.split("-----END CERTIFICATE-----")[1] + "-----END CERTIFICATE-----" });
cases.push(...byteMutations("recorded-leaf", recorded, 0, quick ? 16 : 1));
cases.push(...byteMutations("recorded-attestation", recorded, 1, quick ? 32 : 1));
cases.push(...byteMutations("recorded-intermediate", recorded, 2, quick ? 64 : 1));
cases.push(...byteMutations("recorded-root", recorded, 3, quick ? 64 : 1));
const structural = await structuralCases();
cases.push(...structural);
const synBase = structural.find((c) => c.id === "syn-baseline")!;
cases.push(...byteMutations("syn-leaf", synBase, 0, quick ? 16 : 1));

const ids = new Set<string>();
for (const c of cases) {
  if (ids.has(c.id)) throw new Error("duplicate case id " + c.id);
  ids.add(c.id);
}
const allPath = outDir + "all.jsonl";
writeFileSync(allPath, cases.map((c) => JSON.stringify(c)).join("\n") + "\n");
console.log(`cases: ${cases.length}`);

// 2. TypeScript verdicts
async function tsVerdict(c: Case): Promise<string> {
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
const t0 = performance.now();
const ts = new Map<string, string>();
for (const c of cases) ts.set(c.id, await tsVerdict(c));
console.log(`typescript verdicts: ${(performance.now() - t0).toFixed(0)} ms`);

// 3. Kotlin oracle
const ktPath = outDir + "kotlin.jsonl";
const t1 = performance.now();
const gradle = spawnSync("./gradlew", [":server:runLocal", "-PlocalMain=org.owasp.uncrackable.server.ParityOracleKt", "--offline", "-q"], {
  cwd: repo, env: { ...process.env, PARITY_IN: allPath, PARITY_OUT: ktPath }, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
});
if (gradle.status !== 0) {
  console.error(gradle.stdout, gradle.stderr);
  process.exit(2);
}
console.log(`kotlin oracle: ${(performance.now() - t1).toFixed(0)} ms`);
const kt = new Map<string, string>();
for (const line of readFileSync(ktPath, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const v = JSON.parse(line);
  kt.set(v.id, v.code);
}

// 4. Compare
/** Documented, deliberate divergences (see PARITY.md): the port is stricter than BouncyCastle here. */
const EXPECTED_DIVERGENCE: Record<string, { typescript: string; kotlin: string }> = {
  "kd-indefinite-length-ber": { typescript: "attestation_invalid", kotlin: "ok:2" },
};
let mismatches = 0;
const histogram = new Map<string, number>();
for (const c of cases) {
  const a = ts.get(c.id)!;
  const b = kt.get(c.id) ?? "<missing>";
  histogram.set(b, (histogram.get(b) ?? 0) + 1);
  const expected = EXPECTED_DIVERGENCE[c.id];
  if (expected) {
    if (a !== expected.typescript || b !== expected.kotlin) {
      mismatches++;
      console.log(`UNEXPECTED ${c.id}: typescript=${a} kotlin=${b} (documented divergence expected ${JSON.stringify(expected)})`);
    }
    continue;
  }
  if (a !== b) {
    mismatches++;
    console.log(`MISMATCH ${c.id}: typescript=${a} kotlin=${b}`);
  }
}
console.log("verdict histogram (kotlin):", Object.fromEntries([...histogram.entries()].sort()));
console.log(mismatches === 0 ? `PARITY OK over ${cases.length} cases` : `${mismatches} mismatches`);
process.exit(mismatches === 0 ? 0 : 1);
