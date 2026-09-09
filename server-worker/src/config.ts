/** Startup validation mirroring RuntimeConfig.kt. Refuses to serve on any missing or malformed value. */
import { parseAnchors, AndroidVerifier } from "./verifier/verifier.ts";
import type { Certificate } from "./verifier/x509.ts";
import { base64Decode } from "./verifier/base64.ts";
import { Challenges } from "./challenges.ts";
import { hex } from "./verifier/der.ts";
import roots from "../../server/roots/google-attestation-roots.pem";

export const APP_PACKAGE = "org.owasp.mastg.uncrackable5";

export interface Env {
  STATE: DurableObjectNamespace;
  CHALLENGE_HMAC_KEY: string;
  FLAG_TIER2: string;
  APP_SIGNER_SHA256: string;
  APP_PACKAGE?: string;
  /** Test-only override of the bundled Google roots (PEM bundle). Never set in production. */
  ATTESTATION_ROOTS?: string;
}

export interface Runtime {
  challenges: Challenges;
  verifier: AndroidVerifier;
  flag: string;
  packageName: string;
}

let cached: Promise<Runtime> | null = null;

export function runtime(env: Env): Promise<Runtime> {
  cached ??= load(env).catch((e) => {
    cached = null;
    throw e;
  });
  return cached;
}

async function load(env: Env): Promise<Runtime> {
  const required = (name: keyof Env): string => {
    const v = env[name];
    if (typeof v !== "string" || v.trim() === "") throw new Error(`Missing configuration: ${name}`);
    return v;
  };
  const packageName = env.APP_PACKAGE ?? APP_PACKAGE;
  if (packageName !== APP_PACKAGE && packageName !== APP_PACKAGE + ".debug") throw new Error("Invalid configuration: APP_PACKAGE");
  let key: Uint8Array;
  try {
    key = base64Decode(required("CHALLENGE_HMAC_KEY"));
  } catch {
    throw new Error("Invalid configuration: CHALLENGE_HMAC_KEY");
  }
  if (key.length < 32) throw new Error("Invalid configuration: CHALLENGE_HMAC_KEY");
  const flag = required("FLAG_TIER2");
  const signer = required("APP_SIGNER_SHA256").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(signer)) throw new Error("Invalid configuration: APP_SIGNER_SHA256");
  const anchors = await parseAnchors(env.ATTESTATION_ROOTS ?? roots);
  await rejectSoftwareRoots(anchors);
  return {
    challenges: await Challenges.create(key),
    verifier: new AndroidVerifier({ anchors, packageName, signerSha256Hex: signer }),
    flag,
    packageName,
  };
}

async function rejectSoftwareRoots(anchors: Certificate[]): Promise<void> {
  for (const a of anchors) {
    const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", a.publicKey.spki)));
    if (SOFTWARE_ROOT_SPKI_DIGESTS.has(digest)) throw new Error("Software attestation root cannot be used as a trust anchor.");
  }
}

/** SHA-256 over the SubjectPublicKeyInfo of Google's software attestation roots (SoftwareRoot.kt). */
const SOFTWARE_ROOT_SPKI_DIGESTS = new Set<string>(["d5100c7942ef2e8310dc30ef82729680cf48d690735c3f68179a33c7c370f286", "f2c4746f545946c100e72297f8f946344d7052f03a2f694221f9c893b0e6f711"]);
