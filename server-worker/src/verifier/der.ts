/**
 * Strict DER reader. Definite, minimal lengths only; INTEGER and ENUMERATED must be minimal.
 * BER constructs (indefinite length, constructed strings) are rejected. Java's X.509 parser
 * and BouncyCastle reject the same non-minimal INTEGER encodings; other BER leniencies of
 * those parsers are deliberately not reproduced (see PARITY.md).
 */

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

export const TagClass = { Universal: 0, Application: 1, ContextSpecific: 2, Private: 3 } as const;
export type TagClass = (typeof TagClass)[keyof typeof TagClass];

export interface Tlv {
  /** Tag class. */
  cls: TagClass;
  /** Constructed bit. */
  constructed: boolean;
  /** Tag number. */
  tag: number;
  /** Bytes of the whole TLV (header + content). */
  raw: Uint8Array;
  /** Content bytes. */
  content: Uint8Array;
}

export const U = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  ENUMERATED: 10,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  PRINTABLE_STRING: 19,
  T61_STRING: 20,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  UNIVERSAL_STRING: 28,
  BMP_STRING: 30,
} as const;

/** Reads one TLV at `offset`; returns it and the offset after it. */
export function readTlv(b: Uint8Array, offset: number): [Tlv, number] {
  if (offset >= b.length) throw new DerError("unexpected end of data");
  const first = b[offset];
  const cls = (first >> 6) as TagClass;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    let more = true;
    let count = 0;
    while (more) {
      if (p >= b.length) throw new DerError("truncated tag");
      const octet = b[p++];
      if (count === 0 && octet === 0x80) throw new DerError("non-minimal tag");
      tag = tag * 128 + (octet & 0x7f);
      more = (octet & 0x80) !== 0;
      if (++count > 4) throw new DerError("tag too large");
    }
    if (tag < 0x1f) throw new DerError("non-minimal tag");
  }
  if (p >= b.length) throw new DerError("truncated length");
  let len = b[p++];
  if (len === 0x80) throw new DerError("indefinite length");
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new DerError("length too large");
    if (p + n > b.length) throw new DerError("truncated length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + i];
    if (n === 1 && len < 0x80) throw new DerError("non-minimal length");
    if (n > 1 && len < 2 ** (8 * (n - 1))) throw new DerError("non-minimal length");
    p += n;
  }
  if (p + len > b.length) throw new DerError("truncated content");
  const tlv: Tlv = {
    cls,
    constructed,
    tag,
    raw: b.subarray(offset, p + len),
    content: b.subarray(p, p + len),
  };
  return [tlv, p + len];
}

/** Parses exactly one TLV occupying the whole buffer. */
export function parseSingle(b: Uint8Array): Tlv {
  const [tlv, end] = readTlv(b, 0);
  if (end !== b.length) throw new DerError("extra data after element");
  return tlv;
}

/** Parses the content of a constructed element into its children. */
export function children(t: Tlv): Tlv[] {
  if (!t.constructed) throw new DerError("primitive element has no children");
  const out: Tlv[] = [];
  let p = 0;
  while (p < t.content.length) {
    const [c, next] = readTlv(t.content, p);
    out.push(c);
    p = next;
  }
  return out;
}

export function isUniversal(t: Tlv, tag: number, constructed?: boolean): boolean {
  return t.cls === TagClass.Universal && t.tag === tag && (constructed === undefined || t.constructed === constructed);
}

export function expect(t: Tlv, tag: number, what: string, constructed?: boolean): Tlv {
  if (!isUniversal(t, tag, constructed)) throw new DerError(`expected ${what}`);
  return t;
}

export function sequence(t: Tlv, what = "SEQUENCE"): Tlv[] {
  return children(expect(t, U.SEQUENCE, what, true));
}

export function set(t: Tlv, what = "SET"): Tlv[] {
  return children(expect(t, U.SET, what, true));
}

function checkMinimalInteger(c: Uint8Array): void {
  if (c.length === 0) throw new DerError("empty INTEGER");
  if (c.length > 1) {
    if (c[0] === 0 && (c[1] & 0x80) === 0) throw new DerError("non-minimal INTEGER");
    if (c[0] === 0xff && (c[1] & 0x80) !== 0) throw new DerError("non-minimal INTEGER");
  }
}

/** Signed big-endian two's complement INTEGER content to BigInt. */
export function integerValue(t: Tlv, tag: number = U.INTEGER): bigint {
  if (t.cls !== TagClass.Universal || t.tag !== tag || t.constructed) {
    throw new DerError(tag === U.INTEGER ? "expected INTEGER" : "expected ENUMERATED");
  }
  const c = t.content;
  checkMinimalInteger(c);
  let v = 0n;
  for (const byte of c) v = (v << 8n) | BigInt(byte);
  if (c[0] & 0x80) v -= 1n << BigInt(8 * c.length);
  return v;
}

export function booleanValue(t: Tlv): boolean {
  expect(t, U.BOOLEAN, "BOOLEAN", false);
  if (t.content.length !== 1) throw new DerError("BOOLEAN length");
  return t.content[0] !== 0;
}

export function octetString(t: Tlv): Uint8Array {
  return expect(t, U.OCTET_STRING, "OCTET STRING", false).content;
}

/**
 * BIT STRING content without the unused-bits octet. Like the JDK's DerValue.getBitString, 1 to 7
 * unused bits are tolerated and masked out of the final octet rather than rejected.
 */
export function bitString(t: Tlv): Uint8Array {
  expect(t, U.BIT_STRING, "BIT STRING", false);
  if (t.content.length === 0) throw new DerError("empty BIT STRING");
  const unused = t.content[0];
  if (unused > 7) throw new DerError("BIT STRING unused bits");
  const body = t.content.subarray(1);
  if (unused === 0 || body.length === 0) return body;
  const masked = Uint8Array.from(body);
  masked[masked.length - 1] &= 0xff << unused;
  return masked;
}

export function oidValue(t: Tlv): string {
  expect(t, U.OID, "OBJECT IDENTIFIER", false);
  const c = t.content;
  if (c.length === 0) throw new DerError("empty OID");
  const parts: string[] = [];
  let v = 0n;
  let first = true;
  let inSub = false;
  for (let i = 0; i < c.length; i++) {
    const o = c[i];
    if (!inSub && o === 0x80) throw new DerError("non-minimal OID subidentifier");
    v = (v << 7n) | BigInt(o & 0x7f);
    inSub = (o & 0x80) !== 0;
    if (!inSub) {
      if (first) {
        first = false;
        if (v < 40n) parts.push("0", v.toString());
        else if (v < 80n) parts.push("1", (v - 40n).toString());
        else parts.push("2", (v - 80n).toString());
      } else parts.push(v.toString());
      v = 0n;
    }
  }
  if (inSub) throw new DerError("truncated OID");
  return parts.join(".");
}

/** Number of milliseconds since the epoch for UTCTime or GeneralizedTime (DER profile). */
export function timeValue(t: Tlv): number {
  const text = String.fromCharCode(...t.content);
  let m: RegExpMatchArray | null;
  if (isUniversal(t, U.UTC_TIME, false)) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new DerError("malformed UTCTime");
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return utc(year, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
  }
  if (isUniversal(t, U.GENERALIZED_TIME, false)) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,3}))?Z$/.exec(text);
    if (!m) throw new DerError("malformed GeneralizedTime");
    const ms = utc(Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
    return ms + (m[7] ? Number(m[7].padEnd(3, "0")) : 0);
  }
  throw new DerError("expected Time");
}

function utc(y: number, mo: number, d: number, h: number, mi: number, s: number): number {
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) throw new DerError("invalid time");
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const check = new Date(ms);
  if (check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d) throw new DerError("invalid date");
  return ms;
}

export function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
