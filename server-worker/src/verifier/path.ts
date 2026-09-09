/**
 * Port of Google's KeyAttestationCertPath + KeyAttestationCertPathValidator + Verifier.
 * Only what decides the verdict is reproduced; logging hooks and provisioning-info parsing
 * (which never affect the result) are omitted.
 */
import { OID, namesEqual, nameAttribute, nameHasAttribute, nameContains, extensionValue, verifyCertificate, isSelfIssued } from "./x509.ts";
import type { Certificate, PublicKeyInfo } from "./x509.ts";
import { SecurityLevel, Origin, VerifiedBootState, parseKeyDescription, DEFAULT_LIMITS } from "./keydescription.ts";
import type { KeyDescription, InputLimits } from "./keydescription.ts";
import { bytesEqual } from "./der.ts";

export const ProvisioningMethod = { UNKNOWN: 0, FACTORY_PROVISIONED: 1, REMOTELY_PROVISIONED: 2 } as const;
export type ProvisioningMethod = (typeof ProvisioningMethod)[keyof typeof ProvisioningMethod];

export type VerificationResult =
  | { kind: "success"; publicKey: PublicKeyInfo; keyDescription: KeyDescription }
  | { kind: "challenge_mismatch" }
  | { kind: "path_validation_failure"; message: string }
  | { kind: "chain_parsing_failure"; message: string }
  | { kind: "extension_parsing_failure"; message: string }
  | { kind: "constraint_violation"; label: string; message: string };

export interface Constraint {
  label: string;
  check(description: KeyDescription, path: CertPath): string | null; // null = satisfied
}

/** Software attestation root public keys (SoftwareRoot.kt); never acceptable as anchors. */
const SOFTWARE_ROOT_SPKI_HEX = new Set<string>();
export function registerSoftwareRootSpki(hexSpki: string): void {
  SOFTWARE_ROOT_SPKI_HEX.add(hexSpki);
}

export class CertPath {
  /** Full input chain including the supplied root. */
  readonly certificatesWithAnchor: Certificate[];
  /** Chain without the last (root) certificate; index 0 is the leaf. */
  readonly certificates: Certificate[];

  constructor(certs: Certificate[]) {
    if (certs.length < 3) throw new ChainError("At least 3 certificates are required");
    if (!isSelfIssued(certs[certs.length - 1])) throw new ChainError("Root certificate not found");
    this.certificatesWithAnchor = certs;
    this.certificates = certs.slice(0, -1);
  }
  leafCert(): Certificate { return this.certificates[0]; }
  attestationCert(): Certificate { return this.certificates[1]; }
  intermediateCert(): Certificate { return this.certificates[this.certificates.length - 1]; }

  provisioningMethod(): ProvisioningMethod {
    const subject = this.intermediateCert().subject;
    if (nameHasAttribute(subject, OID.serialNumber)) return ProvisioningMethod.FACTORY_PROVISIONED;
    if (nameAttribute(subject, OID.commonName) === "Droid CA2" && nameAttribute(subject, OID.organization) === "Google LLC") {
      return ProvisioningMethod.REMOTELY_PROVISIONED;
    }
    return ProvisioningMethod.UNKNOWN;
  }

  securityLevel(): SecurityLevel | null {
    switch (this.provisioningMethod()) {
      case ProvisioningMethod.UNKNOWN:
        return null;
      case ProvisioningMethod.REMOTELY_PROVISIONED: {
        const o = nameAttribute(this.attestationCert().subject, OID.organization);
        return o === "TEE" ? SecurityLevel.TRUSTED_ENVIRONMENT : o === "StrongBox" ? SecurityLevel.STRONG_BOX : SecurityLevel.SOFTWARE;
      }
      case ProvisioningMethod.FACTORY_PROVISIONED:
        for (const c of [this.attestationCert(), this.intermediateCert()]) {
          if (nameContains(c.subject, "strongbox")) return SecurityLevel.STRONG_BOX;
        }
        return null;
    }
  }
}

export class ChainError extends Error {}
class PathError extends Error {}

const Step = { FACTORY_INTERMEDIATE: 0, RKP_INTERMEDIATE: 1, RKP_SERVER: 2, ATTESTATION: 3, TARGET: 4 } as const;
type Step = (typeof Step)[keyof typeof Step];

/** Upstream checks nonCriticalExtensionOIDs, so a critical attestation extension does not count here. */
function hasAttestationExtension(c: Certificate): boolean {
  const ext = c.extensions.get(OID.keyAttestation);
  return ext !== undefined && !ext.critical;
}

async function validateWithAnchor(path: CertPath, anchor: Certificate, revokedSerials: Set<string>, nowMs: number): Promise<PublicKeyInfo> {
  const certList = [...path.certificates].reverse();
  let prevKey = anchor.publicKey;
  let prevSubject = anchor.subject;
  let step: Step | null = null;
  let remaining = path.certificates.length;
  const method = path.provisioningMethod();
  for (const cert of certList) {
    // getStep
    if (step === null) {
      if (method === ProvisioningMethod.REMOTELY_PROVISIONED) step = Step.RKP_INTERMEDIATE;
      else if (method === ProvisioningMethod.FACTORY_PROVISIONED || path.certificatesWithAnchor.length === 4) step = Step.FACTORY_INTERMEDIATE;
      else step = Step.ATTESTATION;
    } else if (step === Step.RKP_INTERMEDIATE) step = Step.RKP_SERVER;
    else if (step === Step.RKP_SERVER) step = Step.ATTESTATION;
    else if (step === Step.FACTORY_INTERMEDIATE) step = Step.ATTESTATION;
    else if (step === Step.ATTESTATION) step = Step.TARGET;
    else throw new PathError(hasAttestationExtension(cert) ? "Unexpected attestation extension after the target certificate" : "Unexpected certificate after the target certificate");
    remaining--;
    if (!namesEqual(cert.issuer, prevSubject)) throw new PathError("Subject/Issuer name chaining check failed");
    if (!(await verifyCertificate(cert, prevKey))) throw new PathError("Signature check failed");
    if (remaining !== 0) {
      if (nowMs < cert.notBefore) throw new PathError("Validity check failed: not yet valid");
      if (nowMs > cert.notAfter && method !== ProvisioningMethod.FACTORY_PROVISIONED) throw new PathError("Validity check failed: expired");
    }
    if (step === Step.TARGET) {
      if (!hasAttestationExtension(cert)) throw new PathError("Target certificate does not contain an attestation extension");
    } else if (hasAttestationExtension(cert)) {
      throw new PathError("Only the target certificate should contain an attestation extension");
    }
    // RevocationChecker runs after BasicChecker for each certificate.
    if (revokedSerials.has(cert.serialHex)) throw new PathError("Certificate has been revoked");
    prevKey = cert.publicKey;
    prevSubject = cert.subject;
  }
  return prevKey;
}

export interface VerifierOptions {
  anchors: Certificate[];
  revokedSerials: Set<string>;
  nowMs: number;
  constraints: Constraint[];
  limits?: InputLimits;
}

function defaultConstraints(): Constraint[] {
  return [
    { label: "Origin", check: (d) => (d.hardwareEnforced.origin === Origin.GENERATED ? null : "Origin violates constraint") },
    {
      label: "Security level",
      check: (d) => (d.keyMintSecurityLevel === d.attestationSecurityLevel && d.attestationSecurityLevel !== SecurityLevel.SOFTWARE ? null : "Security level violates constraint"),
    },
    { label: "Root of trust", check: (d) => (d.hardwareEnforced.rootOfTrust !== null ? null : "Root of trust violates constraint") },
  ];
}

export const MATCHES_CERTIFICATE: Constraint = {
  label: "Security level",
  check: (d, path) => {
    const level = path.securityLevel();
    let ok: boolean;
    switch (d.keyMintSecurityLevel) {
      case SecurityLevel.SOFTWARE: ok = level === null || level === SecurityLevel.SOFTWARE; break;
      case SecurityLevel.TRUSTED_ENVIRONMENT: ok = level === null || level === SecurityLevel.TRUSTED_ENVIRONMENT; break;
      case SecurityLevel.STRONG_BOX: ok = level === SecurityLevel.STRONG_BOX; break;
    }
    return ok ? null : "Security level of KeyMint does not match attestation certificate";
  },
};

/** Verifier.verify: chain[0] is the leaf, chain[n-1] the self-issued root. */
export async function verifyChain(chain: Certificate[], expectedChallenge: Uint8Array | null, opts: VerifierOptions): Promise<VerificationResult> {
  let path: CertPath;
  try {
    path = new CertPath(chain);
  } catch (e) {
    return { kind: "chain_parsing_failure", message: (e as Error).message };
  }
  // Trust anchor selection: anchors whose subject matches the issuer of the first validated certificate.
  const first = path.certificates[path.certificates.length - 1];
  let lastError: string | null = null;
  let publicKey: PublicKeyInfo | null = null;
  for (const anchor of opts.anchors) {
    if (!namesEqual(anchor.subject, first.issuer)) continue;
    try {
      publicKey = await validateWithAnchor(path, anchor, opts.revokedSerials, opts.nowMs);
      break;
    } catch (e) {
      lastError = (e as Error).message;
    }
  }
  if (publicKey === null) return { kind: "path_validation_failure", message: lastError ?? "No matching trust anchor found" };

  let keyDescription: KeyDescription;
  try {
    const ext = extensionValue(path.leafCert(), OID.keyAttestation);
    if (!ext) throw new Error("Key attestation extension not found");
    keyDescription = parseKeyDescription(ext, opts.limits ?? DEFAULT_LIMITS);
  } catch (e) {
    return { kind: "extension_parsing_failure", message: (e as Error).message };
  }
  if (expectedChallenge && !bytesEqual(keyDescription.attestationChallenge, expectedChallenge)) return { kind: "challenge_mismatch" };
  for (const c of [...defaultConstraints(), ...opts.constraints]) {
    const failure = c.check(keyDescription, path);
    if (failure !== null) return { kind: "constraint_violation", label: c.label, message: failure };
  }
  return { kind: "success", publicKey, keyDescription };
}

export { SecurityLevel, Origin, VerifiedBootState };
