/** Challenge issue/verify byte-identical to Challenges.kt: 1 | epochSeconds(8) | nonce(32) | HMAC-SHA256[0..16). */
import { base64UrlDecode, base64UrlEncodeNoPad } from "./verifier/base64.ts";
import { Rejected } from "./verifier/verifier.ts";
import { bytesEqual, hex } from "./verifier/der.ts";

export const CHALLENGE_LIFETIME_SECONDS = 120;

export class Challenges {
  private constructor(private readonly key: CryptoKey) {}

  static async create(rawKey: Uint8Array): Promise<Challenges> {
    if (rawKey.length < 32) throw new Error("CHALLENGE_HMAC_KEY too short");
    const key = await crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Challenges(key);
  }

  private async tag(payload: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign("HMAC", this.key, payload)).subarray(0, 16);
  }

  async issue(nowSeconds: number): Promise<string> {
    const payload = new Uint8Array(41);
    payload[0] = 1;
    new DataView(payload.buffer).setBigUint64(1, BigInt(nowSeconds));
    crypto.getRandomValues(payload.subarray(9, 41));
    const out = new Uint8Array(57);
    out.set(payload, 0);
    out.set(await this.tag(payload), 41);
    return base64UrlEncodeNoPad(out);
  }

  /** Returns the 57 challenge bytes or throws Rejected("attestation_invalid" | "challenge_expired"). */
  async verify(encoded: unknown, nowSeconds: number): Promise<Uint8Array> {
    if (typeof encoded !== "string" || encoded.length !== 76) throw new Rejected("attestation_invalid");
    let bytes: Uint8Array;
    try {
      bytes = base64UrlDecode(encoded);
    } catch {
      throw new Rejected("attestation_invalid");
    }
    if (bytes.length !== 57 || base64UrlEncodeNoPad(bytes) !== encoded || bytes[0] !== 1) throw new Rejected("attestation_invalid");
    const expected = await this.tag(bytes.subarray(0, 41));
    if (!bytesEqual(expected, bytes.subarray(41, 57))) throw new Rejected("attestation_invalid");
    const issued = new DataView(bytes.buffer, bytes.byteOffset).getBigInt64(1);
    const now = BigInt(nowSeconds);
    if (issued < 0n || issued > now || now - issued >= BigInt(CHALLENGE_LIFETIME_SECONDS)) throw new Rejected("challenge_expired");
    return bytes;
  }

  static expiresAtSeconds(bytes: Uint8Array): number {
    return Number(new DataView(bytes.buffer, bytes.byteOffset).getBigInt64(1)) + CHALLENGE_LIFETIME_SECONDS;
  }

  static async id(bytes: Uint8Array): Promise<string> {
    return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  }
}
