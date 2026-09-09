// Phase 0 spike: minimal DER walk + WebCrypto signature verification of a recorded
// Android key attestation chain plus the proof-of-possession signature.
// Not the verifier port. It only answers "does this fit in the Workers CPU budget?".

type Tlv = { tag: number; start: number; end: number; hStart: number };

function tlv(b: Uint8Array, at: number): Tlv {
  const tag = b[at];
  let len = b[at + 1];
  let p = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[p++];
  }
  if (p + len > b.length) throw new Error("truncated");
  return { tag, start: p, end: p + len, hStart: at };
}

function children(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = t.start;
  while (p < t.end) {
    const c = tlv(b, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

const oidHex = (b: Uint8Array, t: Tlv) =>
  Array.from(b.subarray(t.start, t.end), (x) => x.toString(16).padStart(2, "0")).join("");

const OID = {
  ecdsaSha256: "2a8648ce3d040302",
  sha256Rsa: "2a864886f70d01010b",
  ecPublicKey: "2a8648ce3d0201",
  rsa: "2a864886f70d010101",
  p256: "2a8648ce3d030107",
  p384: "2b81040022",
};

export type ParsedCert = {
  der: Uint8Array;
  tbs: Uint8Array;
  sigAlg: string;
  sig: Uint8Array;
  spki: Uint8Array;
  keyAlg: string;
  curve?: string;
  serialHex: string;
};

export function parseCert(der: Uint8Array): ParsedCert {
  const cert = tlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new Error("not a single DER cert");
  const [tbs, sigAlg, sigVal] = children(der, cert);
  const tbsKids = children(der, tbs);
  let i = 0;
  if (tbsKids[0].tag === 0xa0) i = 1; // explicit version
  const serial = tbsKids[i];
  const spkiT = tbsKids[i + 5];
  const [spkiAlg] = children(der, spkiT);
  const algKids = children(der, spkiAlg);
  const keyAlg = oidHex(der, algKids[0]);
  const curve = algKids[1] && algKids[1].tag === 0x06 ? oidHex(der, algKids[1]) : undefined;
  return {
    der,
    tbs: der.subarray(tbs.hStart, tbs.end),
    sigAlg: oidHex(der, children(der, sigAlg)[0]),
    sig: der.subarray(sigVal.start + 1, sigVal.end), // skip BIT STRING unused-bits byte
    spki: der.subarray(spkiT.hStart, spkiT.end),
    keyAlg,
    curve,
    serialHex: oidHex(der, serial).replace(/^(00)+/, "") || "0",
  };
}

function derEcdsaToRaw(sig: Uint8Array, size: number): Uint8Array {
  const seq = tlv(sig, 0);
  const [r, s] = children(sig, seq);
  const out = new Uint8Array(size * 2);
  const put = (t: Tlv, off: number) => {
    let v = sig.subarray(t.start, t.end);
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error("bad ecdsa int");
    out.set(v, off + size - v.length);
  };
  put(r, 0);
  put(s, size);
  return out;
}

export async function importKey(c: ParsedCert): Promise<CryptoKey> {
  if (c.keyAlg === OID.ecPublicKey) {
    const namedCurve = c.curve === OID.p256 ? "P-256" : c.curve === OID.p384 ? "P-384" : undefined;
    if (!namedCurve) throw new Error("unsupported curve");
    return crypto.subtle.importKey("spki", c.spki, { name: "ECDSA", namedCurve }, false, ["verify"]);
  }
  if (c.keyAlg === OID.rsa) {
    return crypto.subtle.importKey("spki", c.spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  }
  throw new Error("unsupported key");
}

async function verifyWith(signer: ParsedCert, key: CryptoKey, sigAlg: string, sig: Uint8Array, data: Uint8Array) {
  if (sigAlg === OID.ecdsaSha256) {
    const size = signer.curve === OID.p384 ? 48 : 32;
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derEcdsaToRaw(sig, size), data);
  }
  if (sigAlg === OID.sha256Rsa) return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  throw new Error("unsupported sig alg");
}

export type SpikeResult = { chainOk: boolean; popOk: boolean; serials: string[] };

/** chain[0] = leaf ... chain[n-1] = self-signed root. Verifies every signature incl. root self-sig. */
export async function verifyChainAndPop(chainB64: string[], challenge: Uint8Array, popB64: string): Promise<SpikeResult> {
  const certs = chainB64.map((b) => parseCert(Uint8Array.from(atob(b), (ch) => ch.charCodeAt(0))));
  const keys = await Promise.all(certs.map(importKey));
  let chainOk = true;
  for (let i = 0; i < certs.length; i++) {
    const issuer = Math.min(i + 1, certs.length - 1);
    const ok = await verifyWith(certs[issuer], keys[issuer], certs[i].sigAlg, certs[i].sig, certs[i].tbs);
    if (!ok) chainOk = false;
  }
  const pop = Uint8Array.from(atob(popB64), (ch) => ch.charCodeAt(0));
  const popOk = await verifyWith(certs[0], keys[0], OID.ecdsaSha256, pop, challenge);
  return { chainOk, popOk, serials: certs.map((c) => c.serialHex) };
}

export function b64urlDecode(s: string): Uint8Array {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(t + "=".repeat((4 - (t.length % 4)) % 4)), (ch) => ch.charCodeAt(0));
}
