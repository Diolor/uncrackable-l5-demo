/**
 * Single-instance Durable Object: replay table, global request budget and the revocation
 * snapshot. Single-threaded, so every operation is atomic by construction.
 *
 * The snapshot is one row holding the sorted serial list, because the Workers Free plan
 * meters SQLite rows written and read per day. The feed lists ~1,700 serials, so one row
 * per serial cost thousands of writes per refresh and exhausted the daily budget.
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

type SnapshotRow = { serials: string; digest: string; expires_at: number };

export class State extends DurableObject {
  private readonly sql: SqlStorage;
  private cache: { digest: string; serials: string[] } | null = null;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS used_challenges (id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS request_budget (minute INTEGER PRIMARY KEY, requests INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS revocation_snapshot (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        serials TEXT NOT NULL, digest TEXT NOT NULL, expires_at INTEGER NOT NULL, fetched_at INTEGER NOT NULL
      );
    `);
  }

  /** Global budget: at most RATE_LIMIT_PER_MINUTE requests per wall-clock minute. */
  allowRequest(nowSeconds: number): boolean {
    const minute = Math.floor(nowSeconds / 60);
    this.sql.exec("DELETE FROM request_budget WHERE minute < ?", minute - 2);
    const row = this.sql.exec<{ requests: number }>("SELECT requests FROM request_budget WHERE minute = ?", minute).toArray()[0];
    if ((row?.requests ?? 0) >= RATE_LIMIT_PER_MINUTE) return false;
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
    let row = this.snapshot();
    if (row === null || nowSeconds >= row.expires_at) {
      await this.refresh(nowSeconds);
      row = this.snapshot();
      if (row === null || nowSeconds >= row.expires_at) return { serials: null, expiresAt: row?.expires_at ?? 0 };
    }
    if (this.cache?.digest !== row.digest) this.cache = { digest: row.digest, serials: row.serials === "" ? [] : row.serials.split("\n") };
    return { serials: this.cache.serials, expiresAt: row.expires_at };
  }

  async alarm(): Promise<void> {
    await this.refresh(Math.floor(Date.now() / 1000));
  }

  private snapshot(): SnapshotRow | null {
    return this.sql.exec<SnapshotRow>("SELECT serials, digest, expires_at FROM revocation_snapshot WHERE id = 1").toArray()[0] ?? null;
  }

  /** Fetches the feed and replaces the snapshot; leaves the old snapshot untouched on any failure. */
  private async refresh(nowSeconds: number): Promise<void> {
    try {
      const response = await fetch(FEED_URL, { redirect: "manual", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: { "cache-control": "max-age=0" } });
      if (response.status !== 200) throw new Error("status");
      if (Number(response.headers.get("content-length") ?? "0") > MAX_FEED_BYTES) throw new Error("too large");
      const text = await boundedText(response, MAX_FEED_BYTES);
      const ttl = Math.min(MAX_TTL_SECONDS, Math.max(0, snapshotTtl(response.headers.get("cache-control"), response.headers.get("age"))));
      // Freshness counts from the start of the download, not its completion.
      const expiresAt = nowSeconds + ttl;
      if (Math.floor(Date.now() / 1000) >= expiresAt) throw new Error("stale before use");
      const serials = [...parseFeed(text)].sort();
      const joined = serials.join("\n");
      const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(joined))));
      const current = this.snapshot();
      if (current?.digest === digest) {
        this.sql.exec("UPDATE revocation_snapshot SET expires_at = ?, fetched_at = ? WHERE id = 1", expiresAt, nowSeconds);
      } else {
        this.sql.exec(
          "INSERT INTO revocation_snapshot(id, serials, digest, expires_at, fetched_at) VALUES (1, ?, ?, ?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET serials = excluded.serials, digest = excluded.digest, expires_at = excluded.expires_at, fetched_at = excluded.fetched_at",
          joined, digest, expiresAt, nowSeconds,
        );
        this.cache = { digest, serials };
      }
      this.sql.exec("DROP TABLE IF EXISTS revoked_serials; DROP TABLE IF EXISTS revocation_meta;");
      await this.ctx.storage.setAlarm(Math.max(nowSeconds + 60, expiresAt - REFRESH_MARGIN_SECONDS) * 1000);
    } catch {
      await this.ctx.storage.setAlarm((nowSeconds + 60) * 1000);
    }
  }
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
