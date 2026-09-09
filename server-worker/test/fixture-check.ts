// Quick Node check of the port against the recorded OnePlus chain (same clock as RecordedAttestationTest).
import { readFileSync } from "node:fs";
import { AndroidVerifier, parseAnchors, Rejected } from "../src/verifier/verifier.ts";
import { base64UrlDecode } from "../src/verifier/base64.ts";

const root = new URL("../../", import.meta.url);
const fixture = JSON.parse(readFileSync(new URL("fixtures/oneplus9pro-android14-tee-tier2.json", root), "utf8"));
const roots = readFileSync(new URL("server/roots/google-attestation-roots.pem", root), "utf8");
const anchors = await parseAnchors(roots);
const now = Date.parse("2026-09-09T18:52:11Z");
const challenge = base64UrlDecode(fixture.challenge);
const debugSigner = "5bb26e313b60dcb38bf264e8e152111fc76ed51e12ec77d1073be3323beb53be";

async function run(packageName: string) {
  const v = new AndroidVerifier({ anchors, packageName, signerSha256Hex: debugSigner });
  try {
    return "ok:" + (await v.verify(fixture, challenge, new Set(), now));
  } catch (e) {
    return e instanceof Rejected ? e.code : "error:" + (e as Error).message;
  }
}
console.log("anchors:", anchors.length);
console.log("debug package:", await run("org.owasp.mastg.uncrackable5.debug"), "(expect ok:2)");
console.log("release package:", await run("org.owasp.mastg.uncrackable5"), "(expect app_integrity)");
