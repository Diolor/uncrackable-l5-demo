/** Google attestation status feed handling, mirroring Revocations.kt and GoogleStatusFetcher. */

export const FEED_URL = "https://android.googleapis.com/attestation/status";
export const MAX_TTL_SECONDS = 300;
export const MAX_FEED_BYTES = 4 * 1024 * 1024;

export class Unavailable extends Error {
  constructor() {
    super("verification_unavailable");
    this.name = "Unavailable";
  }
}

/** Normalises a hex serial like BigInteger(serial, 16).toString(16). */
export function normaliseSerial(serial: string): string {
  const s = serial.toLowerCase().replace(/^0+/, "");
  return s === "" ? "0" : s;
}

/** Parses the feed body; every listed serial is rejected regardless of status. Throws Unavailable. */
export function parseFeed(body: string): Set<string> {
  let root: unknown;
  try {
    root = JSON.parse(body);
  } catch {
    throw new Unavailable();
  }
  if (typeof root !== "object" || root === null || Array.isArray(root)) throw new Unavailable();
  const entries = (root as Record<string, unknown>)["entries"];
  if (typeof entries !== "object" || entries === null || Array.isArray(entries)) throw new Unavailable();
  const out = new Set<string>();
  for (const [serial, entry] of Object.entries(entries as Record<string, unknown>)) {
    if (!/^[0-9a-fA-F]{1,128}$/.test(serial)) throw new Unavailable();
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new Unavailable();
    const status = (entry as Record<string, unknown>)["status"];
    if (typeof status !== "string" || status.trim() === "") throw new Unavailable();
    out.add(normaliseSerial(serial));
  }
  return out;
}

/**
 * How long a snapshot may be reused: at most MAX_TTL_SECONDS, and never past the origin's own
 * max-age minus the Age a CDN cache reports. 0 means unusable.
 */
export function snapshotTtl(cacheControl: string | null, ageHeader: string | null): number {
  const cache = cacheControl ?? "";
  if (/no-cache/i.test(cache) || /no-store/i.test(cache)) return 0;
  const m = /(?:^|,)\s*max-age=(\d+)/i.exec(cache);
  const originMaxAge = m ? Number(m[1]) : MAX_TTL_SECONDS;
  const parsedAge = ageHeader !== null && /^\d+$/.test(ageHeader.trim()) ? Number(ageHeader.trim()) : 0;
  const remaining = originMaxAge - Math.max(0, parsedAge);
  return remaining <= 0 ? 0 : Math.min(remaining, MAX_TTL_SECONDS);
}
