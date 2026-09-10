/**
 * Port of Google's KeyDescription parser (Extension.kt in github.com/android/keyattestation).
 *
 * Two failure classes are reproduced exactly because the server's error code depends on them:
 * - AttributeError (upstream ExtensionParsingException inside ASN1Converter.parse): the
 *   attribute becomes null and parsing continues; a later constraint then reports it.
 * - Any other error (upstream require/check/IllegalState/BouncyCastle parse failures): the whole
 *   KeyDescription fails to parse.
 */
import { DerError, TagClass, U, parseSingle, children, sequence, set as derSet, integerValue, booleanValue, octetString, isUniversal } from "./der.ts";
import type { Tlv } from "./der.ts";

export class AttributeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttributeError";
  }
}

export const SecurityLevel = { SOFTWARE: 0, TRUSTED_ENVIRONMENT: 1, STRONG_BOX: 2 } as const;
export type SecurityLevel = (typeof SecurityLevel)[keyof typeof SecurityLevel];
export const Origin = { GENERATED: 0, DERIVED: 1, IMPORTED: 2, RESERVED: 3, SECURELY_IMPORTED: 4 } as const;
export type Origin = (typeof Origin)[keyof typeof Origin];
export const VerifiedBootState = { VERIFIED: 0, SELF_SIGNED: 1, UNVERIFIED: 2, FAILED: 3 } as const;
export type VerifiedBootState = (typeof VerifiedBootState)[keyof typeof VerifiedBootState];

export interface InputLimits { maxPackages: number; maxSignatures: number }
export const DEFAULT_LIMITS: InputLimits = { maxPackages: 32, maxSignatures: 10 };

export interface RootOfTrust {
  verifiedBootKey: Uint8Array;
  deviceLocked: boolean;
  verifiedBootState: VerifiedBootState;
  verifiedBootHash: Uint8Array | null;
}

export interface PackageInfo { name: string; version: bigint }
export interface AttestationApplicationId {
  packages: PackageInfo[];
  /** Unique signature digests (set semantics), as lowercase hex. */
  signatures: string[];
}

export interface AuthorizationList {
  purposes: bigint[] | null;
  algorithms: bigint | null;
  keySize: bigint | null;
  digests: bigint[] | null;
  ecCurve: bigint | null;
  origin: Origin | null;
  rootOfTrust: RootOfTrust | null;
  attestationApplicationId: AttestationApplicationId | null;
}

export interface KeyDescription {
  attestationVersion: bigint;
  attestationSecurityLevel: SecurityLevel;
  keyMintVersion: bigint;
  keyMintSecurityLevel: SecurityLevel;
  attestationChallenge: Uint8Array;
  uniqueId: Uint8Array;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

const KNOWN_TAGS = new Set([
  1, 2, 3, 4, 5, 6, 10, 11, 200, 203, 400, 401, 402, 405, 503, 504, 505, 506, 507, 508, 509,
  701, 702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 723, 724,
]);
const Tag = {
  PURPOSE: 1, ALGORITHM: 2, KEY_SIZE: 3, BLOCK_MODE: 4, DIGEST: 5, PADDING: 6, EC_CURVE: 10,
  ML_DSA_VARIANT: 11, RSA_PUBLIC_EXPONENT: 200, RSA_OAEP_MGF_DIGEST: 203, ACTIVE_DATE_TIME: 400,
  ORIGINATION_EXPIRE_DATE_TIME: 401, USAGE_EXPIRE_DATE_TIME: 402, USAGE_COUNT_LIMIT: 405,
  USER_AUTH_TYPE: 504, AUTH_TIMEOUT: 505, CREATION_DATE_TIME: 701, ORIGIN: 702, ROOT_OF_TRUST: 704,
  OS_VERSION: 705, OS_PATCH_LEVEL: 706, ATTESTATION_APPLICATION_ID: 709, ATTESTATION_ID_BRAND: 710,
  ATTESTATION_ID_DEVICE: 711, ATTESTATION_ID_PRODUCT: 712, ATTESTATION_ID_SERIAL: 713,
  ATTESTATION_ID_IMEI: 714, ATTESTATION_ID_MEID: 715, ATTESTATION_ID_MANUFACTURER: 716,
  ATTESTATION_ID_MODEL: 717, VENDOR_PATCH_LEVEL: 718, BOOT_PATCH_LEVEL: 719,
  ATTESTATION_ID_SECOND_IMEI: 723, MODULE_HASH: 724,
} as const;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// --- upstream ASN1Encodable.toX conversions (throw AttributeError) ---------------------------

function toInt(t: Tlv): bigint {
  if (!isUniversal(t, U.INTEGER, false)) throw new AttributeError("Must be an ASN1Integer");
  return integerValue(t);
}
function toEnumeratedValue(t: Tlv): bigint {
  if (!isUniversal(t, U.ENUMERATED, false)) throw new AttributeError("Must be an ASN1Enumerated");
  return integerValue(t, U.ENUMERATED);
}
function toBoolean(t: Tlv): boolean {
  if (!isUniversal(t, U.BOOLEAN, false)) throw new AttributeError("Must be an ASN1Boolean");
  return booleanValue(t);
}
function toBytes(t: Tlv): Uint8Array {
  if (!isUniversal(t, U.OCTET_STRING, false)) throw new AttributeError("Must be an ASN1OctetString");
  return t.content;
}
function toStr(t: Tlv): string {
  const b = toBytes(t);
  try {
    return utf8.decode(b);
  } catch (e) {
    throw new AttributeError("error decoding ASN.1");
  }
}
function toSetOf(t: Tlv, elementTag: number, what: string): Tlv[] {
  if (!isUniversal(t, U.SET, true)) throw new AttributeError("Object must be an ASN1Set");
  const items = derSet(t);
  for (const it of items) if (!isUniversal(it, elementTag)) throw new AttributeError(`Object must be a ${what}`);
  return items;
}
/** Set<BigInteger> semantics: distinct values, order irrelevant. */
function toIntSet(t: Tlv): bigint[] {
  const out: bigint[] = [];
  for (const it of toSetOf(t, U.INTEGER, "ASN1Integer")) {
    const v = integerValue(it);
    if (!out.includes(v)) out.push(v);
  }
  return out;
}

function toRootOfTrust(t: Tlv): RootOfTrust {
  if (!isUniversal(t, U.SEQUENCE, true)) throw new AttributeError("Object must be an ASN1Sequence");
  const seq = sequence(t);
  if (seq.length !== 3 && seq.length !== 4) throw new Error("RootOfTrust size"); // require: fatal
  const stateValue = toEnumeratedValue(seq[2]);
  const verifiedBootKey = toBytes(seq[0]);
  const deviceLocked = toBoolean(seq[1]);
  if (stateValue < 0n || stateValue > 3n) throw new Error("unknown VerifiedBootState"); // IllegalArgumentException: fatal
  const verifiedBootHash = seq.length > 3 ? toBytes(seq[3]) : null;
  return { verifiedBootKey, deviceLocked, verifiedBootState: Number(stateValue) as VerifiedBootState, verifiedBootHash };
}

function toAttestationApplicationId(t: Tlv, limits: InputLimits): AttestationApplicationId {
  if (!isUniversal(t, U.OCTET_STRING, false)) throw new AttributeError("Object must be an ASN1OctetString");
  // ASN1Sequence.getInstance(octets): any parse failure is fatal.
  const inner = parseSingle(t.content);
  const seq = sequence(inner);
  if (seq.length !== 2) throw new Error("AttestationApplicationId size");
  const packagesSet = seq[0];
  const signaturesSet = seq[1];
  if (isUniversal(packagesSet, U.SET, true) && derSet(packagesSet).length > limits.maxPackages) {
    throw new AttributeError("too many packages");
  }
  if (isUniversal(signaturesSet, U.SET, true) && derSet(signaturesSet).length > limits.maxSignatures) {
    throw new AttributeError("too many signatures");
  }
  const packageSeqs = toSetOf(packagesSet, U.SEQUENCE, "ASN1Sequence");
  const signatureOcts = toSetOf(signaturesSet, U.OCTET_STRING, "ASN1OctetString");
  const packages: PackageInfo[] = [];
  for (const p of packageSeqs) {
    const kids = sequence(p);
    if (kids.length !== 2) throw new Error("AttestationPackageInfo size"); // require: fatal
    const info = { name: toStr(kids[0]), version: toInt(kids[1]) };
    if (!packages.some((q) => q.name === info.name && q.version === info.version)) packages.push(info);
  }
  const signatures: string[] = [];
  for (const s of signatureOcts) {
    let h = "";
    for (const x of s.content) h += x.toString(16).padStart(2, "0");
    if (!signatures.includes(h)) signatures.push(h);
  }
  return { packages, signatures };
}

function recover<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch (e) {
    if (e instanceof AttributeError) return null;
    throw e;
  }
}

function parseAuthorizationList(t: Tlv, limits: InputLimits): AuthorizationList {
  if (!isUniversal(t, U.SEQUENCE, true)) throw new AttributeError("Object must be an ASN1Sequence");
  const objects = new Map<number, Tlv>();
  for (const el of sequence(t)) {
    if (el.cls === TagClass.Universal) throw new Error("Must be an ASN1TaggedObject");
    if (!KNOWN_TAGS.has(el.tag)) throw new Error(`unknown tag number: ${el.tag}`);
    // explicitBaseObject: the tagged object must be constructed with exactly one element.
    if (!el.constructed) throw new Error("implicit tagging");
    const inner = children(el);
    if (inner.length !== 1) throw new Error("implicit tagging");
    objects.set(el.tag, inner[0]); // duplicate tags: last wins (Map.associate)
  }
  const get = (tag: number) => objects.get(tag);
  const parse = <T>(tag: number, fn: (v: Tlv) => T): T | null => {
    const v = get(tag);
    if (v === undefined) return null;
    return recover(() => fn(v));
  };
  // Attributes the server never reads are still parsed, because their fatal errors abort the whole parse.
  for (const tag of [Tag.BLOCK_MODE, Tag.PADDING, Tag.RSA_OAEP_MGF_DIGEST]) parse(tag, toIntSet);
  for (const tag of [
    Tag.ML_DSA_VARIANT, Tag.RSA_PUBLIC_EXPONENT, Tag.ACTIVE_DATE_TIME, Tag.ORIGINATION_EXPIRE_DATE_TIME,
    Tag.USAGE_EXPIRE_DATE_TIME, Tag.USAGE_COUNT_LIMIT, Tag.USER_AUTH_TYPE, Tag.AUTH_TIMEOUT,
    Tag.CREATION_DATE_TIME, Tag.OS_VERSION,
  ]) parse(tag, toInt);
  for (const tag of [Tag.OS_PATCH_LEVEL, Tag.VENDOR_PATCH_LEVEL, Tag.BOOT_PATCH_LEVEL]) {
    const v = get(tag);
    if (v !== undefined && !isUniversal(v, U.INTEGER, false)) throw new Error("Must be an ASN1Integer"); // check: fatal
    if (v !== undefined) integerValue(v);
  }
  for (const tag of [
    Tag.ATTESTATION_ID_BRAND, Tag.ATTESTATION_ID_DEVICE, Tag.ATTESTATION_ID_PRODUCT, Tag.ATTESTATION_ID_SERIAL,
    Tag.ATTESTATION_ID_IMEI, Tag.ATTESTATION_ID_MEID, Tag.ATTESTATION_ID_MANUFACTURER, Tag.ATTESTATION_ID_MODEL,
    Tag.ATTESTATION_ID_SECOND_IMEI,
  ]) parse(tag, toStr);
  parse(Tag.MODULE_HASH, toBytes);

  const origin = parse(Tag.ORIGIN, (v) => {
    const n = toInt(v);
    if (n < 0n || n > 4n) throw new Error("unknown Origin"); // IllegalStateException: fatal
    return Number(n) as Origin;
  });
  return {
    purposes: parse(Tag.PURPOSE, toIntSet),
    algorithms: parse(Tag.ALGORITHM, toInt),
    keySize: parse(Tag.KEY_SIZE, toInt),
    digests: parse(Tag.DIGEST, toIntSet),
    ecCurve: parse(Tag.EC_CURVE, toInt),
    origin,
    rootOfTrust: parse(Tag.ROOT_OF_TRUST, toRootOfTrust),
    attestationApplicationId: parse(Tag.ATTESTATION_APPLICATION_ID, (v) => toAttestationApplicationId(v, limits)),
  };
}

function toSecurityLevel(t: Tlv): SecurityLevel {
  const v = toEnumeratedValue(t);
  if (v < 0n || v > 2n) throw new Error("unknown SecurityLevel");
  return Number(v) as SecurityLevel;
}

/**
 * Parses the KeyDescription from the extension's inner bytes (the OCTET STRING content).
 * Throws on any failure; callers treat every throw as ExtensionParsingFailure.
 */
export function parseKeyDescription(bytes: Uint8Array, limits: InputLimits = DEFAULT_LIMITS): KeyDescription {
  const seq = sequence(parseSingle(bytes), "KeyDescription");
  if (seq.length !== 8) throw new Error("KeyDescription size");
  const attestationVersion = toInt(seq[0]);
  const attestationSecurityLevel = toSecurityLevel(seq[1]);
  const keyMintVersion = toInt(seq[2]);
  const keyMintSecurityLevel = toSecurityLevel(seq[3]);
  const attestationChallenge = toBytes(seq[4]);
  const uniqueId = toBytes(seq[5]);
  const softwareEnforced = parseAuthorizationList(seq[6], limits);
  const hardwareEnforced = parseAuthorizationList(seq[7], limits);
  return { attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced };
}

export { DerError };
