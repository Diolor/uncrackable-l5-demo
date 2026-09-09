import { DerError, TagClass, U, parseSingle, children, readTlv, sequence, set as derSet, expect, integerValue, booleanValue, octetString, bitString, oidValue, timeValue, hex, bytesEqual, isUniversal } from "./der.ts";
import type { Tlv } from "./der.ts";

export const OID = {
  ecPublicKey: "1.2.840.10045.2.1",
  rsaEncryption: "1.2.840.113549.1.1.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  sha256Rsa: "1.2.840.113549.1.1.11",
  sha384Rsa: "1.2.840.113549.1.1.12",
  sha512Rsa: "1.2.840.113549.1.1.13",
  keyAttestation: "1.3.6.1.4.1.11129.2.1.17",
  provisioningInfo: "1.3.6.1.4.1.11129.2.1.30",
  basicConstraints: "2.5.29.19",
  commonName: "2.5.4.3",
  organization: "2.5.4.10",
  serialNumber: "2.5.4.5",
  title: "2.5.4.12",
} as const;

export interface Attribute {
  oid: string;
  /** Normalised string value, or "#"+hex for non-string types. Approximates X500Principal canonical form. */
  canonical: string;
  /** Decoded string value when the attribute is a string type. */
  text?: string;
}

export interface Name {
  der: Uint8Array;
  /** RDNs in order, each a list of attributes. */
  rdns: Attribute[][];
}

export interface PublicKeyInfo {
  spki: Uint8Array;
  algorithm: string;
  /** Named curve OID for EC keys. */
  curve?: string;
  /** Modulus bit length for RSA keys. */
  rsaBits?: number;
}

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  serial: bigint;
  /** Unpadded lowercase hex, matching BigInteger.toString(16). */
  serialHex: string;
  tbsSignatureAlgorithm: string;
  signatureAlgorithm: string;
  signature: Uint8Array;
  issuer: Name;
  subject: Name;
  notBefore: number;
  notAfter: number;
  publicKey: PublicKeyInfo;
  /** Extension OID -> extnValue content (the OCTET STRING content). */
  extensions: Map<string, { critical: boolean; value: Uint8Array }>;
  basicConstraintsCa: boolean | null;
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function decodeDirectoryString(t: Tlv): string | undefined {
  if (t.cls !== TagClass.Universal || t.constructed) return undefined;
  switch (t.tag) {
    case U.UTF8_STRING:
      return utf8.decode(t.content);
    case U.PRINTABLE_STRING:
    case U.IA5_STRING:
    case U.T61_STRING:
      return String.fromCharCode(...t.content);
    case U.BMP_STRING: {
      if (t.content.length % 2) throw new DerError("BMPString length");
      let s = "";
      for (let i = 0; i < t.content.length; i += 2) s += String.fromCharCode((t.content[i] << 8) | t.content[i + 1]);
      return s;
    }
    case U.UNIVERSAL_STRING: {
      if (t.content.length % 4) throw new DerError("UniversalString length");
      let s = "";
      for (let i = 0; i < t.content.length; i += 4) {
        s += String.fromCodePoint((t.content[i] << 24) | (t.content[i + 1] << 16) | (t.content[i + 2] << 8) | t.content[i + 3]);
      }
      return s;
    }
    default:
      return undefined;
  }
}

/**
 * Attribute types that X500Principal's canonical form (RFC 2253 keywords) normalises as strings.
 * Every other type, including serialNumber (2.5.4.5) and title, compares by exact DER value bytes.
 */
const CANONICAL_STRING_TYPES = new Set([
  "2.5.4.3", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.10", "2.5.4.11", "2.5.4.9",
  "0.9.2342.19200300.100.1.25", "0.9.2342.19200300.100.1.1",
]);

function parseName(t: Tlv): Name {
  const rdns = sequence(t, "Name").map((rdn) => {
    const attrs = derSet(rdn, "RDN").map((atv) => {
      const [oidT, valT, ...rest] = sequence(atv, "AttributeTypeAndValue");
      if (!oidT || !valT || rest.length) throw new DerError("AttributeTypeAndValue");
      const oid = oidValue(oidT);
      const text = decodeDirectoryString(valT);
      const normalisable = CANONICAL_STRING_TYPES.has(oid) && isUniversal(valT, U.PRINTABLE_STRING) || CANONICAL_STRING_TYPES.has(oid) && isUniversal(valT, U.UTF8_STRING);
      const canonical = text !== undefined && normalisable ? text.trim().replace(/\s+/g, " ").toUpperCase().toLowerCase() : "#" + hex(valT.raw);
      return { oid, canonical, text };
    });
    if (attrs.length === 0) throw new DerError("empty RDN");
    return attrs;
  });
  return { der: t.raw, rdns };
}

/** X500Principal.equals approximation: same RDN sequence, each RDN the same attribute set. */
export function namesEqual(a: Name, b: Name): boolean {
  if (bytesEqual(a.der, b.der)) return true;
  if (a.rdns.length !== b.rdns.length) return false;
  for (let i = 0; i < a.rdns.length; i++) {
    const x = a.rdns[i].map((v) => v.oid + "=" + v.canonical).sort();
    const y = b.rdns[i].map((v) => v.oid + "=" + v.canonical).sort();
    if (x.length !== y.length || x.some((v, j) => v !== y[j])) return false;
  }
  return true;
}

/** Last value of an attribute by OID across the DN, like the reference parseDN (last wins). */
export function nameAttribute(n: Name, oid: string): string | undefined {
  let out: string | undefined;
  for (const rdn of n.rdns) for (const a of rdn) if (a.oid === oid && a.text !== undefined) out = a.text.trim();
  return out;
}

export function nameHasAttribute(n: Name, oid: string): boolean {
  return n.rdns.some((rdn) => rdn.some((a) => a.oid === oid));
}

/** True when any string attribute value contains `needle` case-insensitively. */
export function nameContains(n: Name, needle: string): boolean {
  const lower = needle.toLowerCase();
  return n.rdns.some((rdn) => rdn.some((a) => a.text !== undefined && a.text.toLowerCase().includes(lower)));
}

function parseAlgorithmIdentifier(t: Tlv): { oid: string; params?: Tlv; raw: Uint8Array } {
  const kids = sequence(t, "AlgorithmIdentifier");
  if (kids.length < 1 || kids.length > 2) throw new DerError("AlgorithmIdentifier");
  return { oid: oidValue(kids[0]), params: kids[1], raw: t.raw };
}

function parseSpki(t: Tlv): PublicKeyInfo {
  const [algT, keyT, ...rest] = sequence(t, "SubjectPublicKeyInfo");
  if (!algT || !keyT || rest.length) throw new DerError("SubjectPublicKeyInfo");
  const alg = parseAlgorithmIdentifier(algT);
  const key = bitString(keyT);
  const info: PublicKeyInfo = { spki: t.raw, algorithm: alg.oid };
  if (alg.oid === OID.ecPublicKey) {
    if (!alg.params || !isUniversal(alg.params, U.OID, false)) throw new DerError("EC key without named curve");
    info.curve = oidValue(alg.params);
    if (key.length === 0 || key[0] !== 0x04) throw new DerError("EC point must be uncompressed");
  } else if (alg.oid === OID.rsaEncryption) {
    const [n, e, ...rest] = sequence(parseSingle(key), "RSAPublicKey");
    if (!n || !e || rest.length) throw new DerError("RSAPublicKey");
    const modulus = integerValue(n);
    const exponent = integerValue(e);
    if (modulus <= 0n || exponent <= 0n) throw new DerError("RSA key values");
    info.rsaBits = modulus.toString(2).length;
  }
  return info;
}

/**
 * X509CertImpl decodes the extensions it knows while loading a certificate and fails on malformed
 * ones; this reproduces the structural part of those checks for the types seen in attestation chains.
 */
function checkKnownExtension(oid: string, value: Uint8Array): void {
  switch (oid) {
    case "2.5.29.15": // KeyUsage: BIT STRING
      bitString(parseSingle(value));
      return;
    case "2.5.29.14": // SubjectKeyIdentifier: OCTET STRING
      octetString(parseSingle(value));
      return;
    case "2.5.29.35": { // AuthorityKeyIdentifier: SEQUENCE of context tags [0] [1] [2]
      for (const k of sequence(parseSingle(value), "AuthorityKeyIdentifier")) {
        if (k.cls !== TagClass.ContextSpecific || k.tag > 2) throw new DerError("AuthorityKeyIdentifier");
        if (k.tag === 2) integerValue({ ...k, cls: TagClass.Universal, tag: U.INTEGER, constructed: false });
      }
      return;
    }
    case "2.5.29.37": { // ExtendedKeyUsage: SEQUENCE OF OID, non-empty
      const kids = sequence(parseSingle(value), "ExtendedKeyUsage");
      if (kids.length === 0) throw new DerError("ExtendedKeyUsage");
      for (const k of kids) oidValue(k);
      return;
    }
    case "2.5.29.31": // CRLDistributionPoints
    case "2.5.29.32": // CertificatePolicies
    case "2.5.29.17": // SubjectAltName
    case "2.5.29.18": // IssuerAltName
    case "1.3.6.1.5.5.7.1.1": { // AuthorityInfoAccess
      const kids = sequence(parseSingle(value), "extension");
      if (kids.length === 0) throw new DerError("empty extension sequence");
      for (const k of kids) {
        if (oid === "2.5.29.17" || oid === "2.5.29.18") {
          if (k.cls !== TagClass.ContextSpecific || k.tag > 8) throw new DerError("GeneralName");
        } else sequence(k, "extension entry");
      }
      return;
    }
    default:
      return;
  }
}

/** Parses one DER certificate that must occupy the whole buffer. */
export function parseCertificate(der: Uint8Array): Certificate {
  const cert = parseSingle(der);
  const [tbsT, sigAlgT, sigT, ...rest] = sequence(cert, "Certificate");
  if (!tbsT || !sigAlgT || !sigT || rest.length) throw new DerError("Certificate");
  expect(tbsT, U.SEQUENCE, "TBSCertificate", true);
  // X509CertInfo reads the TBS sequentially: fixed fields, optional [1] [2], [3] on v3, and never
  // looks at anything after that. Bytes it does not read are not validated.
  const body = tbsT.content;
  let p = 0;
  const next = (what: string): Tlv => {
    if (p >= body.length) throw new DerError(`missing ${what}`);
    const [t, q] = readTlv(body, p);
    p = q;
    return t;
  };
  const peek = (): Tlv | null => {
    if (p >= body.length) return null;
    try {
      return readTlv(body, p)[0];
    } catch {
      return null;
    }
  };
  let version = 0n;
  let first = next("serialNumber");
  if (first.cls === TagClass.ContextSpecific && first.tag === 0 && first.constructed) {
    const v = children(first);
    if (v.length !== 1) throw new DerError("version");
    version = integerValue(v[0]);
    if (version < 0n || version > 2n) throw new DerError("version");
    first = next("serialNumber");
  }
  const serial = integerValue(first);
  const tbsAlg = parseAlgorithmIdentifier(next("signature"));
  const issuer = parseName(next("issuer"));
  const validity = sequence(next("validity"), "Validity");
  if (validity.length !== 2) throw new DerError("Validity");
  const notBefore = timeValue(validity[0]);
  const notAfter = timeValue(validity[1]);
  const subject = parseName(next("subject"));
  const publicKey = parseSpki(next("subjectPublicKeyInfo"));
  const extensions = new Map<string, { critical: boolean; value: Uint8Array }>();
  let basicConstraintsCa: boolean | null = null;
  let t = peek();
  if (t && t.cls === TagClass.ContextSpecific && t.tag === 1) { next("issuerUniqueID"); t = peek(); }
  if (t && t.cls === TagClass.ContextSpecific && t.tag === 2) { next("subjectUniqueID"); t = peek(); }
  if (version === 2n && t && t.cls === TagClass.ContextSpecific && t.tag === 3) {
    const list = children(next("extensions"));
    if (list.length !== 1) throw new DerError("extensions");
    for (const extT of sequence(list[0], "Extensions")) {
      // sun.security.x509.Extension reads OID, optional BOOLEAN, OCTET STRING and ignores anything after.
      const kids = sequence(extT, "Extension");
      if (kids.length < 2) throw new DerError("Extension");
      const oid = oidValue(kids[0]);
      let critical = false;
      let valT = kids[1];
      if (isUniversal(kids[1], U.BOOLEAN)) {
        critical = booleanValue(kids[1]);
        if (kids.length < 3) throw new DerError("Extension");
        valT = kids[2];
      }
      const value = octetString(valT);
      if (extensions.has(oid)) throw new DerError("duplicate extension");
      extensions.set(oid, { critical, value });
      // Known extensions are decoded on load; a malformed one is fatal only when critical.
      try {
        if (oid === OID.basicConstraints) {
          const bc = sequence(parseSingle(value), "BasicConstraints");
          // BasicConstraintsExtension: an absent or non-BOOLEAN first element means "not a CA".
          if (bc.length > 0 && isUniversal(bc[0], U.BOOLEAN)) {
            basicConstraintsCa = booleanValue(bc[0]);
            if (bc.length > 1) integerValue(bc[1]);
          } else basicConstraintsCa = false;
        } else checkKnownExtension(oid, value);
      } catch (e) {
        if (critical) throw e;
        if (oid === OID.basicConstraints) basicConstraintsCa = null;
      }
    }
  }
  const sigAlg = parseAlgorithmIdentifier(sigAlgT);
  // X509CertImpl rejects a certificate whose outer and TBS algorithm identifiers (OID and parameters) differ.
  if (!bytesEqual(sigAlg.raw, tbsAlg.raw)) throw new DerError("Signature algorithm mismatch");
  return {
    der,
    tbs: tbsT.raw,
    serial,
    serialHex: serial.toString(16),
    tbsSignatureAlgorithm: tbsAlg.oid,
    signatureAlgorithm: sigAlg.oid,
    signature: bitString(sigT),
    issuer,
    subject,
    notBefore,
    notAfter,
    publicKey,
    extensions,
    basicConstraintsCa,
  };
}

export function isSelfIssued(c: Certificate): boolean {
  return namesEqual(c.issuer, c.subject);
}

export function extensionValue(c: Certificate, oid: string): Uint8Array | undefined {
  return c.extensions.get(oid)?.value;
}

// --- signature verification -------------------------------------------------------------



function hashFor(sigOid: string): { kind: "ecdsa" | "rsa"; hash: string } | null {
  switch (sigOid) {
    case OID.ecdsaSha256: return { kind: "ecdsa", hash: "SHA-256" };
    case OID.ecdsaSha384: return { kind: "ecdsa", hash: "SHA-384" };
    case OID.ecdsaSha512: return { kind: "ecdsa", hash: "SHA-512" };
    case OID.sha256Rsa: return { kind: "rsa", hash: "SHA-256" };
    case OID.sha384Rsa: return { kind: "rsa", hash: "SHA-384" };
    case OID.sha512Rsa: return { kind: "rsa", hash: "SHA-512" };
    default: return null;
  }
}

function curveName(oid: string | undefined): { name: string; size: number } | null {
  switch (oid) {
    case OID.p256: return { name: "P-256", size: 32 };
    case OID.p384: return { name: "P-384", size: 48 };
    case OID.p521: return { name: "P-521", size: 66 };
    default: return null;
  }
}

/** Imports a public key for verification with the given signature algorithm; null when unsupported. */
export async function importVerifyKey(key: PublicKeyInfo, sigOid: string): Promise<CryptoKey | null> {
  const spec = hashFor(sigOid);
  if (!spec) return null;
  try {
    if (spec.kind === "ecdsa") {
      if (key.algorithm !== OID.ecPublicKey) return null;
      const curve = curveName(key.curve);
      if (!curve) return null;
      return await crypto.subtle.importKey("spki", key.spki, { name: "ECDSA", namedCurve: curve.name }, false, ["verify"]);
    }
    if (key.algorithm !== OID.rsaEncryption) return null;
    return await crypto.subtle.importKey("spki", key.spki, { name: "RSASSA-PKCS1-v1_5", hash: spec.hash }, false, ["verify"]);
  } catch {
    return null;
  }
}

/** DER ECDSA-Sig-Value to fixed-width r||s; null when malformed. */
export function ecdsaDerToRaw(sig: Uint8Array, size: number): Uint8Array | null {
  try {
    const [rT, sT, ...rest] = sequence(parseSingle(sig), "ECDSA-Sig-Value");
    if (!rT || !sT || rest.length) return null;
    const r = integerValue(rT);
    const s = integerValue(sT);
    if (r < 0n || s < 0n) return null;
    const out = new Uint8Array(size * 2);
    const put = (v: bigint, off: number) => {
      const h = v.toString(16).padStart(size * 2, "0");
      if (h.length > size * 2) throw new DerError("integer too large");
      for (let i = 0; i < size; i++) out[off + i] = parseInt(h.substr(i * 2, 2), 16);
    };
    put(r, 0);
    put(s, size);
    return out;
  } catch {
    return null;
  }
}

/** Verifies `signature` over `data` under `sigOid` with `key`. False on any failure. */
export async function verifySignature(key: PublicKeyInfo, sigOid: string, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const spec = hashFor(sigOid);
  if (!spec) return false;
  const cryptoKey = await importVerifyKey(key, sigOid);
  if (!cryptoKey) return false;
  try {
    if (spec.kind === "ecdsa") {
      const curve = curveName(key.curve);
      if (!curve) return false;
      const raw = ecdsaDerToRaw(signature, curve.size);
      if (!raw) return false;
      return await crypto.subtle.verify({ name: "ECDSA", hash: spec.hash }, cryptoKey, raw, data);
    }
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, data);
  } catch {
    return false;
  }
}

/** X509Certificate.verify(issuerKey): algorithm identifiers must agree, then the signature must check. */
export async function verifyCertificate(cert: Certificate, issuerKey: PublicKeyInfo): Promise<boolean> {
  return verifySignature(issuerKey, cert.signatureAlgorithm, cert.signature, cert.tbs);
}


