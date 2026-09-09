/**
 * Port of the Kotlin AndroidVerifier: request-level validation, root completion from trusted
 * anchors, revocation, Google's verifier with the crackme's constraints, proof of possession,
 * and leaf validity. Returns the protocol tier (always 2) or throws Rejected(code).
 */
import { OID, parseCertificate, isSelfIssued, namesEqual, verifyCertificate, verifySignature } from "./x509.ts";
import type { Certificate, PublicKeyInfo } from "./x509.ts";
import { base64Decode } from "./base64.ts";
import { verifyChain, MATCHES_CERTIFICATE, VerifiedBootState } from "./path.ts";
import type { Constraint } from "./path.ts";
import type { KeyDescription } from "./keydescription.ts";
import { DerError } from "./der.ts";

export class Rejected extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "Rejected";
    this.code = code;
  }
}

export interface AttestRequest { challenge: string; chain: string[]; pop: string }

export interface AndroidVerifierConfig {
  anchors: Certificate[];
  packageName: string;
  /** Lowercase hex SHA-256 of the expected signing certificate. */
  signerSha256Hex: string;
}

/** Parses every PEM certificate block without further checks (test oracle input, like CertificateFactory). */
export function parsePemCertificates(pem: string): Certificate[] {
  const pattern = /-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----/g;
  return (pem.match(pattern) ?? []).map((block) => parseCertificate(base64Decode(block.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""))));
}

/** Parses a PEM bundle of self-signed CA certificates; mirrors RuntimeConfig.ATTESTATION_ROOTS. */
export async function parseAnchors(pem: string): Promise<Certificate[]> {
  if (pem.length > 64 * 1024) throw new Error("ATTESTATION_ROOTS too large");
  const pattern = /-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----/g;
  const blocks = pem.match(pattern) ?? [];
  if (blocks.length < 1 || blocks.length > 16 || pem.replace(pattern, "").trim() !== "") throw new Error("ATTESTATION_ROOTS malformed");
  const out: Certificate[] = [];
  for (const cert of parsePemCertificates(pem)) {
    if (cert.basicConstraintsCa === null || !isSelfIssued(cert)) throw new Error("ATTESTATION_ROOTS: not a self-signed CA");
    if (!(await verifyCertificate(cert, cert.publicKey))) throw new Error("ATTESTATION_ROOTS: bad self-signature");
    out.push(cert);
  }
  return out;
}

const SIGN = 2n, EC = 3n, P256 = 1n, SHA256 = 4n, KEY_256 = 256n;

function constraintsFor(packageName: string, signerHex: string): Constraint[] {
  return [
    MATCHES_CERTIFICATE,
    {
      label: "App identity",
      check: (d: KeyDescription) => {
        const app = d.softwareEnforced.attestationApplicationId;
        const ok = app !== null && app.packages.length === 1 && app.packages[0].name === packageName &&
          app.signatures.length === 1 && app.signatures[0] === signerHex;
        return ok ? null : "App identity violates constraint";
      },
    },
    {
      label: "Device integrity",
      check: (d: KeyDescription) => {
        const boot = d.hardwareEnforced.rootOfTrust;
        return boot !== null && boot.deviceLocked && boot.verifiedBootState === VerifiedBootState.VERIFIED ? null : "Device integrity violates constraint";
      },
    },
    {
      label: "Signing key",
      check: (d: KeyDescription) => {
        const a = d.hardwareEnforced;
        const ok = a.purposes !== null && a.purposes.length === 1 && a.purposes[0] === SIGN &&
          a.algorithms === EC && a.keySize === KEY_256 && a.ecCurve === P256 &&
          a.digests !== null && a.digests.length === 1 && a.digests[0] === SHA256;
        return ok ? null : "Signing key violates constraint";
      },
    },
  ];
}

export class AndroidVerifier {
  private readonly constraints: Constraint[];
  private readonly config: AndroidVerifierConfig;
  constructor(config: AndroidVerifierConfig) {
    this.config = config;
    if (config.anchors.length === 0) throw new Error("no anchors");
    if (!config.packageName || !/^[0-9a-f]{64}$/.test(config.signerSha256Hex)) throw new Error("bad verifier config");
    this.constraints = constraintsFor(config.packageName, config.signerSha256Hex);
  }

  /**
   * @param challenge the authenticated challenge bytes
   * @param revokedSerials current revocation snapshot (unpadded lowercase hex serials)
   * @param nowMs verification time
   */
  async verify(request: AttestRequest, challenge: Uint8Array, revokedSerials: Set<string>, nowMs: number): Promise<2> {
    if (!Array.isArray(request.chain) || request.chain.length < 2 || request.chain.length > 6) throw new Rejected("attestation_invalid");
    if (typeof request.pop !== "string" || request.pop.length < 1 || request.pop.length > 128) throw new Rejected("attestation_invalid");

    let chain: Certificate[];
    try {
      chain = request.chain.map((encoded) => {
        if (typeof encoded !== "string" || encoded.length < 1 || encoded.length > 5464) throw new Error("length");
        const der = base64Decode(encoded);
        if (der.length > 4096) throw new Error("size");
        return parseCertificate(der);
      });
      const tail = chain[chain.length - 1];
      if (!isSelfIssued(tail)) {
        const candidates: Certificate[] = [];
        for (const root of this.config.anchors) {
          if (namesEqual(tail.issuer, root.subject) && (await verifyCertificate(tail, root.publicKey))) candidates.push(root);
        }
        if (candidates.length !== 1) throw new Error("no single completing root");
        chain.push(candidates[0]);
      }
    } catch {
      throw new Rejected("attestation_invalid");
    }

    this.rejectListed(chain, revokedSerials);
    const result = await verifyChain(chain, challenge, {
      anchors: this.config.anchors,
      revokedSerials,
      nowMs,
      constraints: this.constraints,
    });
    switch (result.kind) {
      case "success": {
        const leaf = chain[0];
        // Upstream intentionally omits leaf validity; this protocol requires it.
        if (nowMs < leaf.notBefore || nowMs > leaf.notAfter) throw new Rejected("attestation_invalid");
        const key: PublicKeyInfo = result.publicKey;
        if (key.algorithm !== OID.ecPublicKey || key.curve !== OID.p256) throw new Rejected("attestation_invalid");
        let signature: Uint8Array;
        try {
          signature = base64Decode(request.pop);
        } catch {
          throw new Rejected("attestation_invalid");
        }
        if (!(await verifySignature(key, OID.ecdsaSha256, signature, challenge))) throw new Rejected("attestation_invalid");
        this.rejectListed(chain, revokedSerials);
        return 2;
      }
      case "constraint_violation":
        switch (result.label) {
          case "App identity": throw new Rejected("app_integrity");
          case "Device integrity": throw new Rejected("device_integrity");
          case "Security level": throw new Rejected("no_hardware_attestation");
          default: throw new Rejected("attestation_invalid");
        }
      default:
        throw new Rejected("attestation_invalid");
    }
  }

  private rejectListed(chain: Certificate[], serials: Set<string>): void {
    if (chain.some((c) => serials.has(c.serialHex))) throw new Rejected("attestation_invalid");
  }
}

export { DerError };
