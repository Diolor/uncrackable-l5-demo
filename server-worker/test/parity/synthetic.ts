// Synthetic attestation chains built in TypeScript so every structural detail can be mutated and re-signed.
import { seq, set, octet, bool, utf8, printable, bitstring, ctx, ctxPrimitive, int, enumerated, oid, utcTime, generalizedTime, ecdsaRawToDer, concat, tlv, b64, b64url, hex } from "./der-writer.ts";
import type { Bytes } from "./der-writer.ts";

const FIXED_NOW = Date.parse("2025-01-01T00:00:00Z");
export const NOW = FIXED_NOW;
const DAY = 86_400_000;
export const PACKAGE = "org.owasp.mastg.uncrackable5";
export const SIGNER = new Uint8Array(32).fill(4);
export const SIGNER_HEX = hex(SIGNER);
export const CHALLENGE = Uint8Array.from({ length: 57 }, (_, i) => (i * 7) & 0xff);
CHALLENGE[0] = 1;

const OIDS = {
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  sha256Rsa: "1.2.840.113549.1.1.11",
  keyAttestation: "1.3.6.1.4.1.11129.2.1.17",
  basicConstraints: "2.5.29.19",
  cn: "2.5.4.3",
  o: "2.5.4.10",
  serialNumber: "2.5.4.5",
  title: "2.5.4.12",
};

export interface KeyPair { publicKey: CryptoKey; privateKey: CryptoKey; spki: Bytes; kind: "ec" | "ec384" | "rsa" }

export async function ecKey(curve: "P-256" | "P-384" = "P-256"): Promise<KeyPair> {
  const k = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"])) as CryptoKeyPair;
  return { publicKey: k.publicKey, privateKey: k.privateKey, spki: new Uint8Array((await crypto.subtle.exportKey("spki", k.publicKey)) as ArrayBuffer), kind: curve === "P-256" ? "ec" : "ec384" };
}
export async function jwkKey(pair: { publicKey: JsonWebKey; privateKey: JsonWebKey }): Promise<KeyPair> {
  const alg = { name: "ECDSA", namedCurve: "P-256" };
  const publicKey = await crypto.subtle.importKey("jwk", pair.publicKey, alg, true, ["verify"]);
  const privateKey = await crypto.subtle.importKey("jwk", pair.privateKey, alg, true, ["sign"]);
  return { publicKey, privateKey, spki: new Uint8Array((await crypto.subtle.exportKey("spki", publicKey)) as ArrayBuffer), kind: "ec" };
}

export async function rsaKey(): Promise<KeyPair> {
  const k = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return { publicKey: k.publicKey, privateKey: k.privateKey, spki: new Uint8Array((await crypto.subtle.exportKey("spki", k.publicKey)) as ArrayBuffer), kind: "rsa" };
}

export async function sign(key: KeyPair, data: Bytes, hash: "SHA-256" | "SHA-384" = "SHA-256"): Promise<Bytes> {
  if (key.kind === "rsa") return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, data));
  return ecdsaRawToDer(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, key.privateKey, data)));
}

export type Attr = [oidName: keyof typeof OIDS, value: string, type?: "printable" | "utf8"];
export function name(...attrs: Attr[]): Bytes {
  return seq(...attrs.map(([o, v, t]) => set(seq(oid(OIDS[o]), t === "utf8" ? utf8(v) : printable(v)))));
}

export interface CertSpec {
  serial: bigint;
  issuer: Bytes;
  subject: Bytes;
  notBefore: number;
  notAfter: number;
  key: KeyPair;
  signer: KeyPair;
  /** Signature algorithm OID in the TBS; defaults from signer kind. */
  sigAlg?: string;
  /** Outer signature algorithm OID; defaults to sigAlg. */
  outerSigAlg?: string;
  hash?: "SHA-256" | "SHA-384";
  extensions?: Bytes[];
  version?: 1 | 3;
  generalizedTime?: boolean;
}

export const basicConstraintsExt = seq(oid(OIDS.basicConstraints), bool(true), octet(seq(bool(true))));
export const attestationExt = (kd: Bytes, critical = false): Bytes =>
  critical ? seq(oid(OIDS.keyAttestation), bool(true), octet(kd)) : seq(oid(OIDS.keyAttestation), octet(kd));

export async function buildCert(s: CertSpec): Promise<Bytes> {
  const sigAlg = s.sigAlg ?? (s.signer.kind === "rsa" ? OIDS.sha256Rsa : OIDS.ecdsaSha256);
  const algId = (o: string) => (o === OIDS.sha256Rsa ? seq(oid(o), tlv(0, false, 5, new Uint8Array())) : seq(oid(o)));
  const time = s.generalizedTime ? generalizedTime : utcTime;
  const parts: Bytes[] = [];
  if ((s.version ?? 3) === 3) parts.push(ctx(0, int(2)));
  parts.push(int(s.serial), algId(sigAlg), s.issuer, seq(time(s.notBefore), time(s.notAfter)), s.subject, s.key.spki);
  if ((s.version ?? 3) === 3 && s.extensions && s.extensions.length) parts.push(ctx(3, seq(...s.extensions)));
  const tbs = seq(...parts);
  const hash = s.hash ?? (sigAlg === OIDS.ecdsaSha384 ? "SHA-384" : "SHA-256");
  const signature = await sign(s.signer, tbs, hash);
  return seq(tbs, algId(s.outerSigAlg ?? sigAlg), bitstring(signature));
}

// --- KeyDescription ---------------------------------------------------------------------------

export interface KdSpec {
  attestationVersion?: number;
  attestationSecurityLevel?: Bytes;
  keyMintVersion?: number;
  keyMintSecurityLevel?: Bytes;
  challenge?: Bytes;
  uniqueId?: Bytes;
  sw?: Bytes;
  hw?: Bytes;
  /** Replace the whole sequence body. */
  rawBody?: Bytes[];
}

export function appId(opts: { packages?: Bytes[]; signatures?: Bytes[]; wrap?: (inner: Bytes) => Bytes; body?: Bytes[] } = {}): Bytes {
  const packages = opts.packages ?? [seq(octet(new TextEncoder().encode(PACKAGE)), int(1))];
  const signatures = opts.signatures ?? [octet(SIGNER)];
  const inner = opts.body ? seq(...opts.body) : seq(set(...packages), set(...signatures));
  return (opts.wrap ?? octet)(inner);
}

export function rootOfTrust(opts: { locked?: Bytes; state?: Bytes; key?: Bytes; hash?: Bytes | null; body?: Bytes[] } = {}): Bytes {
  if (opts.body) return seq(...opts.body);
  const items = [opts.key ?? octet(new Uint8Array(32)), opts.locked ?? bool(true), opts.state ?? enumerated(0)];
  if (opts.hash !== undefined && opts.hash !== null) items.push(opts.hash);
  return seq(...items);
}

/** hardwareEnforced list for a valid tier-2 key; entries may be overridden or removed (null). */
export function hwList(overrides: Record<number, Bytes | null> = {}, extra: Bytes[] = []): Bytes {
  const base: Record<number, Bytes> = {
    1: set(int(2)),
    2: int(3),
    3: int(256),
    5: set(int(4)),
    10: int(1),
    702: int(0),
    704: rootOfTrust(),
    705: int(140000),
    706: int(202409),
    710: octet(new TextEncoder().encode("OnePlus")),
  };
  const items: Bytes[] = [];
  const tags = Object.keys(base).map(Number).sort((a, b) => a - b);
  for (const t of tags) {
    const ov = overrides[t];
    if (ov === null) continue;
    items.push(ctx(t, ov ?? base[t]));
  }
  return seq(...items, ...extra);
}

export function swList(overrides: Record<number, Bytes | null> = {}, extra: Bytes[] = []): Bytes {
  const base: Record<number, Bytes> = { 701: int(1700000000000), 709: appId() };
  const items: Bytes[] = [];
  for (const t of [701, 709]) {
    const ov = overrides[t];
    if (ov === null) continue;
    items.push(ctx(t, ov ?? base[t]));
  }
  return seq(...items, ...extra);
}

export function keyDescription(s: KdSpec = {}): Bytes {
  if (s.rawBody) return seq(...s.rawBody);
  return seq(
    int(s.attestationVersion ?? 300),
    s.attestationSecurityLevel ?? enumerated(1),
    int(s.keyMintVersion ?? 300),
    s.keyMintSecurityLevel ?? enumerated(1),
    octet(s.challenge ?? CHALLENGE),
    octet(s.uniqueId ?? new Uint8Array()),
    s.sw ?? swList(),
    s.hw ?? hwList(),
  );
}

// --- Chains -----------------------------------------------------------------------------------

export interface ChainOpts {
  kd?: Bytes;
  leafExtensions?: Bytes[];
  leafKey?: KeyPair;
  leafSigner?: KeyPair;
  leafIssuer?: Bytes;
  leafNotBefore?: number;
  leafNotAfter?: number;
  leafSigAlg?: string;
  leafOuterSigAlg?: string;
  leafVersion?: 1 | 3;
  attestationSubject?: Bytes;
  attestationExtensions?: Bytes[];
  attestationNotAfter?: number;
  attestationNotBefore?: number;
  intermediateSubject?: Bytes;
  intermediateNotAfter?: number;
  intermediateNotBefore?: number;
  rootKey?: KeyPair;
  /** remote: root -> Droid CA2 -> Droid CA3 (rkp) -> attestation(O=TEE) -> leaf */
  remote?: boolean;
  remoteLevel?: "TEE" | "StrongBox";
  /** Reference time for validity windows; defaults to the fixed parity clock. */
  nowMs?: number;
}

export interface Built {
  chain: Bytes[];
  rootPem: string;
  leafKey: KeyPair;
  keys: { root: KeyPair; intermediate: KeyPair; attestation: KeyPair; rkp?: KeyPair };
}

export function pem(der: Bytes): string {
  const body = b64(der).match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}

export async function buildChain(o: ChainOpts = {}, shared?: Built["keys"]): Promise<Built> {
  const NOW = o.nowMs ?? FIXED_NOW;
  const keys = shared ?? { root: o.rootKey ?? (await ecKey()), intermediate: await ecKey(), attestation: await ecKey() };
  if (o.rootKey) keys.root = o.rootKey;
  const rootSubject = name(["cn", "Test Key Attestation CA1"], ["o", "Google LLC"]);
  const root = await buildCert({
    serial: 0xca11cafen, issuer: rootSubject, subject: rootSubject, notBefore: NOW - 5 * 365 * DAY, notAfter: NOW + 5 * 365 * DAY,
    key: keys.root, signer: keys.root, extensions: [basicConstraintsExt],
  });
  const leafKey = o.leafKey ?? (await ecKey());
  const kd = o.kd ?? keyDescription();
  const chain: Bytes[] = [];
  let attestationSubject: Bytes;
  let attestationIssuer: Bytes;
  let attestationSigner: KeyPair;
  if (o.remote) {
    const remoteSubject = name(["cn", "Droid CA2"], ["o", "Google LLC"]);
    const rkpSubject = name(["o", "Google LLC"], ["cn", "Droid CA3"]);
    keys.rkp = keys.rkp ?? (await ecKey());
    const remoteIntermediate = await buildCert({
      serial: 0x1234567890n, issuer: rootSubject, subject: remoteSubject, notBefore: NOW - 7 * DAY, notAfter: NOW + 7 * DAY,
      key: keys.intermediate, signer: keys.root, extensions: [basicConstraintsExt],
    });
    const rkpIntermediate = await buildCert({
      serial: 0x1234567891n, issuer: remoteSubject, subject: rkpSubject, notBefore: NOW - 7 * DAY, notAfter: NOW + 7 * DAY,
      key: keys.rkp, signer: keys.intermediate, extensions: [basicConstraintsExt],
    });
    attestationSubject = o.attestationSubject ?? name(["o", o.remoteLevel ?? "TEE"], ["cn", "f00d"]);
    attestationIssuer = rkpSubject;
    attestationSigner = keys.rkp;
    const attestation = await buildCert({
      serial: 0xf00dn, issuer: attestationIssuer, subject: attestationSubject, notBefore: o.attestationNotBefore ?? NOW - 7 * DAY, notAfter: o.attestationNotAfter ?? NOW + 7 * DAY,
      key: keys.attestation, signer: attestationSigner, extensions: o.attestationExtensions ?? [basicConstraintsExt],
    });
    chain.push(attestation, rkpIntermediate, remoteIntermediate, root);
  } else {
    const intermediateSubject = o.intermediateSubject ?? name(["serialNumber", "e18c4f2ca699739a"], ["title", "TEE"]);
    const intermediate = await buildCert({
      serial: 0x1234567890n, issuer: rootSubject, subject: intermediateSubject, notBefore: o.intermediateNotBefore ?? NOW - 7 * DAY, notAfter: o.intermediateNotAfter ?? NOW + 7 * DAY,
      key: keys.intermediate, signer: keys.root, extensions: [basicConstraintsExt],
    });
    attestationSubject = o.attestationSubject ?? name(["serialNumber", "decafbad"]);
    attestationIssuer = intermediateSubject;
    attestationSigner = keys.intermediate;
    const attestation = await buildCert({
      serial: 0xcafbadn, issuer: attestationIssuer, subject: attestationSubject, notBefore: o.attestationNotBefore ?? NOW - 7 * DAY, notAfter: o.attestationNotAfter ?? NOW + 7 * DAY,
      key: keys.attestation, signer: attestationSigner, extensions: o.attestationExtensions ?? [basicConstraintsExt],
    });
    chain.push(attestation, intermediate, root);
  }
  const leaf = await buildCert({
    serial: 1n, issuer: o.leafIssuer ?? attestationSubject, subject: name(["cn", "Android Keystore Key"]),
    notBefore: o.leafNotBefore ?? NOW - 7 * DAY, notAfter: o.leafNotAfter ?? NOW + 7 * DAY,
    key: leafKey, signer: o.leafSigner ?? keys.attestation, extensions: o.leafExtensions ?? [attestationExt(kd)],
    sigAlg: o.leafSigAlg, outerSigAlg: o.leafOuterSigAlg, version: o.leafVersion,
  });
  chain.unshift(leaf);
  return { chain, rootPem: pem(root), leafKey, keys };
}

export async function pop(leafKey: KeyPair, data: Bytes = CHALLENGE): Promise<Bytes> {
  return sign(leafKey, data);
}

export interface Case {
  id: string;
  request: { challenge: string; chain: string[]; pop: string };
  now: string;
  packageName: string;
  signer: string;
  roots: string;
  serials: string[];
}

export async function toCase(id: string, built: Built, opts: { pop?: Bytes; chain?: Bytes[] | string[]; now?: number; packageName?: string; signer?: string; roots?: string; serials?: string[]; challenge?: string } = {}): Promise<Case> {
  const chain = (opts.chain ?? built.chain).map((c) => (typeof c === "string" || c === null ? c : b64(c)));
  return {
    id,
    request: { challenge: opts.challenge ?? b64url(CHALLENGE), chain, pop: b64(opts.pop ?? (await pop(built.leafKey))) },
    now: new Date(opts.now ?? NOW).toISOString(),
    packageName: opts.packageName ?? PACKAGE,
    signer: opts.signer ?? SIGNER_HEX,
    roots: opts.roots ?? built.rootPem,
    serials: opts.serials ?? [],
  };
}

export { seq, set, octet, bool, utf8, printable, ctx, ctxPrimitive, int, enumerated, oid, concat, tlv, b64, b64url };
