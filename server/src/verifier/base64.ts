/**
 * Base64 decoders matching java.util.Base64 semantics of the reference verifier:
 * - standard alphabet, no whitespace, no line separators;
 * - padding optional, but if present it must be correct and terminal;
 * - a dangling single sextet is rejected.
 * `atob` is deliberately not used: it accepts whitespace and differs on padding.
 */

function table(alphabet: string): Int16Array {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < alphabet.length; i++) t[alphabet.charCodeAt(i)] = i;
  return t;
}

const STD = table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
const URL = table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

function decode(s: string, t: Int16Array): Uint8Array {
  let end = s.length;
  let pad = 0;
  if (end > 0 && s.charCodeAt(end - 1) === 61) {
    pad++;
    end--;
    if (end > 0 && s.charCodeAt(end - 1) === 61) {
      pad++;
      end--;
    }
  }
  const rem = end % 4;
  if (rem === 1) throw new Error("base64: dangling sextet");
  if (pad > 0 && ((rem === 0 && pad !== 0) || (rem === 2 && pad !== 2) || (rem === 3 && pad !== 1))) {
    throw new Error("base64: bad padding");
  }
  const out = new Uint8Array(Math.floor((end * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < end; i++) {
    const v = t[s.charCodeAt(i) & 0xff];
    if (v < 0 || s.charCodeAt(i) > 255) throw new Error("base64: illegal character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

export const base64Decode = (s: string): Uint8Array => decode(s, STD);
export const base64UrlDecode = (s: string): Uint8Array => decode(s, URL);

const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function encode(b: Uint8Array, alphabet: string, padding: boolean): string {
  let s = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + alphabet[(n >> 6) & 63] + alphabet[n & 63];
  }
  if (i < b.length) {
    const n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8);
    s += alphabet[n >> 18] + alphabet[(n >> 12) & 63];
    s += i + 1 < b.length ? alphabet[(n >> 6) & 63] : padding ? "=" : "";
    s += padding ? "=" : "";
  }
  return s;
}

export const base64Encode = (b: Uint8Array): string => encode(b, STD_ALPHABET, true);
export const base64UrlEncodeNoPad = (b: Uint8Array): string => encode(b, URL_ALPHABET, false);
