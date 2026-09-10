// Minimal DER writer for building test certificates and attestation extensions.

export type Bytes = Uint8Array;

export function concat(...parts: Bytes[]): Bytes {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function encodeLength(n: number): Bytes {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function encodeTag(cls: number, constructed: boolean, tag: number): Bytes {
  const first = (cls << 6) | (constructed ? 0x20 : 0);
  if (tag < 31) return Uint8Array.of(first | tag);
  const rest: number[] = [];
  let v = tag;
  rest.unshift(v & 0x7f);
  v >>= 7;
  while (v > 0) {
    rest.unshift(0x80 | (v & 0x7f));
    v >>= 7;
  }
  return Uint8Array.of(first | 0x1f, ...rest);
}

export function tlv(cls: number, constructed: boolean, tag: number, content: Bytes): Bytes {
  return concat(encodeTag(cls, constructed, tag), encodeLength(content.length), content);
}

export const seq = (...items: Bytes[]): Bytes => tlv(0, true, 16, concat(...items));
export const set = (...items: Bytes[]): Bytes => tlv(0, true, 17, concat(...items));
export const octet = (b: Bytes): Bytes => tlv(0, false, 4, b);
export const nul = (): Bytes => tlv(0, false, 5, new Uint8Array());
export const bool = (v: boolean, trueByte = 0xff): Bytes => tlv(0, false, 1, Uint8Array.of(v ? trueByte : 0));
export const utf8 = (s: string): Bytes => tlv(0, false, 12, new TextEncoder().encode(s));
export const printable = (s: string): Bytes => tlv(0, false, 19, new TextEncoder().encode(s));
export const bitstring = (b: Bytes): Bytes => tlv(0, false, 3, concat(Uint8Array.of(0), b));
/** Context-specific EXPLICIT tag. */
export const ctx = (tag: number, ...inner: Bytes[]): Bytes => tlv(2, true, tag, concat(...inner));
/** Context-specific IMPLICIT primitive tag (for negative tests). */
export const ctxPrimitive = (tag: number, content: Bytes): Bytes => tlv(2, false, tag, content);

export function integerContent(v: bigint): Bytes {
  const bytes: number[] = [];
  let x = v;
  if (x >= 0n) {
    do {
      bytes.unshift(Number(x & 0xffn));
      x >>= 8n;
    } while (x > 0n);
    if (bytes[0] & 0x80) bytes.unshift(0);
  } else {
    do {
      bytes.unshift(Number(x & 0xffn));
      x >>= 8n;
    } while (x < -1n);
    if (!(bytes[0] & 0x80)) bytes.unshift(0xff);
  }
  return Uint8Array.from(bytes);
}
export const int = (v: bigint | number): Bytes => tlv(0, false, 2, integerContent(BigInt(v)));
export const enumerated = (v: bigint | number): Bytes => tlv(0, false, 10, integerContent(BigInt(v)));

export function oid(s: string): Bytes {
  const parts = s.split(".").map(Number);
  const out: number[] = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const enc: number[] = [p & 0x7f];
    let v = p >> 7;
    while (v > 0) {
      enc.unshift(0x80 | (v & 0x7f));
      v >>= 7;
    }
    out.push(...enc);
  }
  return tlv(0, false, 6, Uint8Array.from(out));
}

export function utcTime(ms: number): Bytes {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0, false, 23, new TextEncoder().encode(s));
}

export function generalizedTime(ms: number): Bytes {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  const s = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0, false, 24, new TextEncoder().encode(s));
}

/** Raw r||s ECDSA signature to DER ECDSA-Sig-Value. */
export function ecdsaRawToDer(raw: Bytes): Bytes {
  const half = raw.length / 2;
  const toBig = (b: Bytes) => b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
  return seq(int(toBig(raw.subarray(0, half))), int(toBig(raw.subarray(half))));
}

export function hex(b: Bytes): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
export function fromHex(h: string): Bytes {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export function b64(b: Bytes): string {
  return Buffer.from(b).toString("base64");
}
export function b64url(b: Bytes): string {
  return Buffer.from(b).toString("base64url");
}
