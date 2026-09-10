/**
 * Single-instance Durable Object holding replay state, the global request budget and the
 * revocation snapshot. Being single-threaded, every operation here is atomic by construction.
 */
import { DurableObject } from "cloudflare:workers";
import { hex } from "./verifier/der.ts";
import { FEED_URL, MAX_FEED_BYTES, MAX_TTL_SECONDS, parseFeed, snapshotTtl } from "./revocations.ts";

export const RATE_LIMIT_PER_MINUTE = 60;
const FETCH_TIMEOUT_MS = 3000;
const REFRESH_MARGIN_SECONDS = 30;

export interface RevocationView {
  /** Sorted lowercase hex serials, or null when no fresh snapshot exists. */
  serials: string[] | null;
  expiresAt: number;
}

export class State extends DurableObject {
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS used_challenges (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS request_budget (minute INTEGER PRIMARY KEY, requests INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS revocation_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS revoked_serials (serial TEXT PRIMARY KEY);
    `);
  }

  /** Global budget: at most RATE_LIMIT_PER_MINUTE requests per wall-clock minute. */
  allowRequest(nowSeconds: number): boolean {
    const minute = Math.floor(nowSeconds / 60);
    this.sql.exec("DELETE FROM request_budget WHERE minute < ?", minute - 2);
    const row = this.sql.exec<{ requests: number }>("SELECT requests FROM request_budget WHERE minute = ?", minute).toArray()[0];
    const used = row?.requests ?? 0;
    if (used >= RATE_LIMIT_PER_MINUTE) return false;
    this.sql.exec("INSERT INTO request_budget(minute, requests) VALUES (?, 1) ON CONFLICT(minute) DO UPDATE SET requests = requests + 1", minute);
    return true;
  }

  /** Atomic create-if-absent; true exactly once per challenge id. */
  consume(id: string, expiresAtSeconds: number, nowSeconds: number): boolean {
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error("bad challenge id");
    this.sql.exec("DELETE FROM used_challenges WHERE expires_at < ?", nowSeconds - 60);
    const before = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM used_challenges WHERE id = ?", id).toArray()[0].n;
    if (before > 0) return false;
    this.sql.exec("INSERT INTO used_challenges(id, expires_at) VALUES (?, ?)", id, expiresAtSeconds);
    return true;
  }

  /** Current snapshot, refreshing synchronously when absent or expired (fails closed on error). */
  async revocations(nowSeconds: number): Promise<RevocationView> {
    let expiresAt = this.metaNumber("expires_at");
    if (expiresAt === null || nowSeconds >= expiresAt) {
      await this.refresh(nowSeconds);
      expiresAt = this.metaNumber("expires_at");
      if (expiresAt === null || nowSeconds >= expiresAt) return { serials: null, expiresAt: expiresAt ?? 0 };
    }
    const serials = this.sql.exec<{ serial: string }>("SELECT serial FROM revoked_serials ORDER BY serial").toArray().map((r) => r.serial);
    return { serials, expiresAt };
  }

  async alarm(): Promise<void> {
    await this.refresh(Math.floor(Date.now() / 1000));
  }

  private metaNumber(key: string): number | null {
    const v = this.metaString(key);
    return v === null ? null : Number(v);
  }

  private metaString(key: string): string | null {
    const row = this.sql.exec<{ v: string }>("SELECT v FROM revocation_meta WHERE k = ?", key).toArray()[0];
    return row ? row.v : null;
  }

  private putMeta(key: string, value: string): void {
    this.sql.exec("INSERT INTO revocation_meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", key, value);
  }

  /**
   * Fetch the feed and replace the snapshot; leaves the old snapshot untouched on any failure.
   *
   * The feed lists ~1700 serials and changes rarely, while the snapshot is refreshed every few
   * minutes, so rewriting the table unconditionally cost ~3500 row writes per refresh and
   * exhausted the account's daily storage-write budget. When the serial set is byte-identical to
   * the stored one, only the freshness metadata is rewritten (two rows). The digest is compared
   * together with the row count so a truncated table can never be mistaken for a current one.
   */
  private async refresh(nowSeconds: number): Promise<void> {
    try {
      const response = await fetch(FEED_URL, { redirect: "manual", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: { "cache-control": "max-age=0" } });
      if (response.status !== 200) throw new Error("status");
      const length = Number(response.headers.get("content-length") ?? "0");
      if (length > MAX_FEED_BYTES) throw new Error("too large");
      const text = await boundedText(response, MAX_FEED_BYTES);
      const ttl = Math.min(MAX_TTL_SECONDS, Math.max(0, snapshotTtl(response.headers.get("cache-control"), response.headers.get("age"))));
      // Measure freshness from the start of the download, not its completion.
      const expiresAt = nowSeconds + ttl;
      if (Math.floor(Date.now() / 1000) >= expiresAt) throw new Error("stale before use");
      const serials = parseFeed(text);
      const digest = await serialsDigest(serials);
      const unchanged = digest === this.metaString("serials_digest") && this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM revoked_serials").toArray()[0].n === serials.size;
      this.ctx.storage.transactionSync(() => {
        if (!unchanged) {
          this.sql.exec("DELETE FROM revoked_serials");
          for (const s of serials) this.sql.exec("INSERT OR IGNORE INTO revoked_serials(serial) VALUES (?)", s);
          this.putMeta("serials_digest", digest);
          this.putMeta("entries", String(serials.size));
        }
        this.putMeta("expires_at", String(expiresAt));
        this.putMeta("fetched_at", String(nowSeconds));
      });
      const next = Math.max(nowSeconds + 60, expiresAt - REFRESH_MARGIN_SECONDS);
      await this.ctx.storage.setAlarm(next * 1000);
    } catch {
      // Retry soon; requests fail closed once the previous snapshot expires.
      await this.ctx.storage.setAlarm((nowSeconds + 60) * 1000);
    }
  }
}

/** SHA-256 over the sorted serials, so an unchanged feed is recognised without rewriting rows. */
async function serialsDigest(serials: Set<string>): Promise<string> {
  const canonical = [...serials].sort().join("\n");
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))));
}

async function boundedText(response: Response, max: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("no body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      throw new Error("too large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return new TextDecoder().decode(out);
}
