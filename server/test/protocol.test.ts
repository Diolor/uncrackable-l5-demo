import { SELF, env, runInDurableObject } from "cloudflare:test";
import { beforeAll, beforeEach, afterEach, describe, expect, it } from "vitest";
import keys from "./fixtures/test-keys.json";
import { buildChain, jwkKey, keyDescription, hwList, rootOfTrust, pop, bool, enumerated } from "./corpus/synthetic.ts";
import type { Built } from "./corpus/synthetic.ts";
import { b64 } from "./corpus/der-writer.ts";
import { base64UrlDecode, base64UrlEncodeNoPad, base64Decode } from "../src/verifier/base64.ts";
import type { State } from "../src/state.ts";

const FEED = "https://android.googleapis.com/attestation/status";
const ORIGIN = "https://crackme.lorentzos.com";
let shared: Built["keys"];
let leafKey: Awaited<ReturnType<typeof jwkKey>>;

/** Canned feed responses consumed in order; the Durable Object shares this isolate's global fetch. */
const queued: Array<() => Response> = [];
const realFetch = globalThis.fetch;
function feed(entries: Record<string, { status: string }> = {}, headers: Record<string, string> = { "cache-control": "public, max-age=86400" }, status = 200, body?: string) {
  queued.push(() => new Response(body ?? JSON.stringify({ entries }), { status, headers: { "content-type": "application/json", ...headers } }));
}

const state = () => (env as unknown as { STATE: DurableObjectNamespace<State> }).STATE;
const stub = () => state().get(state().idFromName("singleton"));
async function resetState(): Promise<void> {
  await runInDurableObject(stub(), (instance) => {
    const sql = (instance as unknown as { sql: SqlStorage }).sql;
    sql.exec("DELETE FROM revocation_snapshot");
    sql.exec("DELETE FROM request_budget");
    sql.exec("DELETE FROM used_challenges");
  });
}
async function meta() {
  return await runInDurableObject(stub(), (instance) => {
    const sql = (instance as unknown as { sql: SqlStorage }).sql;
    return sql.exec<{ serials: string; digest: string; expires_at: number; fetched_at: number }>("SELECT serials, digest, expires_at, fetched_at FROM revocation_snapshot WHERE id = 1").toArray()[0];
  });
}
async function expireSnapshot(): Promise<void> {
  await runInDurableObject(stub(), (instance) => {
    (instance as unknown as { sql: SqlStorage }).sql.exec("UPDATE revocation_snapshot SET expires_at = 0");
  });
}

async function challenge(): Promise<string> {
  const r = await SELF.fetch(`${ORIGIN}/v1/challenge`);
  expect(r.status).toBe(200);
  expect(r.headers.get("cache-control")).toBe("no-store");
  const body = await r.json<{ challenge: string; expiresIn: number }>();
  expect(body.challenge).toHaveLength(76);
  expect(body.expiresIn).toBe(120);
  return body.challenge;
}

async function attestRequest(opts: { kd?: (challengeBytes: Uint8Array) => Uint8Array; token?: string } = {}) {
  const token = opts.token ?? (await challenge());
  const bytes = base64UrlDecode(token);
  const kd = opts.kd ? opts.kd(bytes) : keyDescription({ challenge: bytes });
  const built = await buildChain({ kd, leafKey, nowMs: Date.now() }, shared);
  const signature = await pop(leafKey, bytes);
  return { challenge: token, chain: built.chain.map(b64), pop: b64(signature) };
}

async function attest(body: unknown, init: RequestInit = {}) {
  return SELF.fetch(`${ORIGIN}/v1/attest`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
    ...init,
  });
}

/** Forges a challenge with the test HMAC key at an arbitrary issue time. */
async function forgedChallenge(issuedSeconds: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base64Decode("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const payload = new Uint8Array(41);
  payload[0] = 1;
  new DataView(payload.buffer).setBigUint64(1, BigInt(issuedSeconds));
  crypto.getRandomValues(payload.subarray(9));
  const tag = new Uint8Array(await crypto.subtle.sign("HMAC", key, payload)).subarray(0, 16);
  const out = new Uint8Array(57);
  out.set(payload);
  out.set(tag, 41);
  return base64UrlEncodeNoPad(out);
}

beforeAll(async () => {
  shared = { root: await jwkKey(keys.root), intermediate: await jwkKey(keys.intermediate), attestation: await jwkKey(keys.attestation) };
  leafKey = await jwkKey(keys.leaf);
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === FEED) {
      const next = queued.shift();
      if (!next) throw new Error("unexpected feed fetch");
      return next();
    }
    return realFetch(input, init);
  }) as typeof fetch;
});

beforeEach(async () => {
  queued.length = 0;
  await resetState();
});
afterEach(() => {
  expect(queued, "every queued feed response must be consumed").toHaveLength(0);
});

describe("protocol", () => {
  it("health is public and no-store", async () => {
    const r = await SELF.fetch(`${ORIGIN}/v1/health`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ status: "ok" });
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it("locked verified chain receives the tier-two flag exactly once", async () => {
    feed();
    const body = await attestRequest();
    const r = await attest(body);
    const text = await r.text();
    expect(r.status, text).toBe(200);
    expect(JSON.parse(text)).toEqual({ tier: 2, flag: "synthetic-tier-two" });
    expect(r.headers.get("cache-control")).toBe("no-store");
    const replay = await attest(body);
    expect(replay.status).toBe(403);
    expect(await replay.json()).toEqual({ error: "challenge_replayed" });
  });

  it("unlocked device is refused without consuming the challenge", async () => {
    feed();
    const kd = (c: Uint8Array) => keyDescription({ challenge: c, hw: hwList({ 704: rootOfTrust({ locked: bool(false) }) }) });
    const token = await challenge();
    const bad = await attestRequest({ kd, token });
    const r = await attest(bad);
    expect(r.status).toBe(403);
    expect(await r.json()).toEqual({ error: "device_integrity" });
    const good = await attestRequest({ token });
    expect((await attest(good)).status).toBe(200);
  });

  it("software security level maps to no_hardware_attestation", async () => {
    feed();
    const sw = await attestRequest({ kd: (c) => keyDescription({ challenge: c, attestationSecurityLevel: enumerated(0), keyMintSecurityLevel: enumerated(0) }) });
    expect(await (await attest(sw)).json()).toEqual({ error: "no_hardware_attestation" });
  });

  it("bad proof of possession does not consume the challenge", async () => {
    feed();
    const body = await attestRequest();
    const r = await attest({ ...body, pop: "AAAA" });
    expect(await r.json()).toEqual({ error: "attestation_invalid" });
    expect((await attest(body)).status).toBe(200);
  });

  it("challenge is canonical and authenticated", async () => {
    feed();
    const body = await attestRequest();
    expect(await (await attest({ ...body, challenge: body.challenge + "=" })).json()).toEqual({ error: "attestation_invalid" });
    const tampered = base64UrlDecode(body.challenge);
    tampered[10] ^= 1;
    expect(await (await attest({ ...body, challenge: base64UrlEncodeNoPad(tampered) })).json()).toEqual({ error: "attestation_invalid" });
    expect((await attest(body)).status).toBe(200);
  });

  it("challenge expires exactly 120 seconds after issue, and never from the future", async () => {
    feed();
    const now = Math.floor(Date.now() / 1000);
    const expired = await attest(await attestRequest({ token: await forgedChallenge(now - 120) }));
    expect(expired.status).toBe(403);
    expect(await expired.json()).toEqual({ error: "challenge_expired" });
    const future = await attest(await attestRequest({ token: await forgedChallenge(now + 5) }));
    expect(await future.json()).toEqual({ error: "challenge_expired" });
    const edge = await attest(await attestRequest({ token: await forgedChallenge(now - 118) }));
    expect(edge.status, await edge.text()).toBe(200);
  });

  it("malformed requests are rejected with sanitized errors", async () => {
    expect((await attest("{broken")).status).toBe(400);
    expect((await attest("x".repeat(41_000))).status).toBe(413);
    expect((await attest({ challenge: "a", chain: [], pop: "b", extra: 1 })).status).toBe(400);
    expect((await attest({ challenge: "a", chain: [null], pop: "b" })).status).toBe(400);
    expect((await attest("{}", { headers: { "content-type": "text/plain" } })).status).toBe(415);
    expect((await SELF.fetch(`${ORIGIN}/v1/attest`, { method: "GET" })).status).toBe(405);
    expect((await SELF.fetch(`${ORIGIN}/nope`)).status).toBe(404);
  });

  it("listed serial anywhere in the chain is refused", async () => {
    feed({ CA11CAFE: { status: "SUSPENDED" } });
    const r = await attest(await attestRequest());
    expect(await r.json()).toEqual({ error: "attestation_invalid" });
  });

  it("missing or malformed revocation feed fails closed", async () => {
    feed({}, {}, 500, "boom");
    const r = await attest(await attestRequest());
    expect(r.status).toBe(503);
    expect(await r.json()).toEqual({ error: "verification_unavailable" });
    feed({}, { "cache-control": "max-age=300" }, 200, "{}");
    expect((await attest(await attestRequest())).status).toBe(503);
    feed({}, { "cache-control": "no-store" });
    expect((await attest(await attestRequest())).status).toBe(503);
    feed({}, { "cache-control": "max-age=86400", age: "86400" });
    expect((await attest(await attestRequest())).status).toBe(503);
  });

  it("snapshot is reused within its lifetime and refreshed after expiry", async () => {
    feed();
    expect((await attest(await attestRequest())).status).toBe(200);
    expect((await attest(await attestRequest())).status).toBe(200); // no second fetch queued: reuse
    await expireSnapshot();
    feed({ "1": { status: "REVOKED" } });
    expect(await (await attest(await attestRequest())).json()).toEqual({ error: "attestation_invalid" });
  });

  it("unchanged feed refreshes freshness and keeps the serial list", async () => {
    feed({ CA11CAFE: { status: "SUSPENDED" }, "1": { status: "REVOKED" } });
    expect((await attest(await attestRequest())).status).toBe(403);
    const before = await meta();
    expect(before.serials).toBe("1\nca11cafe");
    await expireSnapshot();
    feed({ "1": { status: "REVOKED" }, CA11CAFE: { status: "SUSPENDED" } });
    expect((await attest(await attestRequest())).status).toBe(403);
    const after = await meta();
    expect(after.digest).toBe(before.digest);
    expect(after.serials).toBe(before.serials);
    expect(after.expires_at).toBeGreaterThan(0);
    expect(after.fetched_at).toBeGreaterThanOrEqual(before.fetched_at);
  });

  it("global budget allows sixty requests per minute", async () => {
    if (Date.now() % 60_000 > 50_000) await new Promise((r) => setTimeout(r, 60_000 - (Date.now() % 60_000) + 100));
    for (let i = 0; i < 60; i++) expect((await SELF.fetch(`${ORIGIN}/v1/challenge`)).status).toBe(200);
    const r = await SELF.fetch(`${ORIGIN}/v1/challenge`);
    expect(r.status).toBe(429);
    expect(await r.json()).toEqual({ error: "rate_limited" });
    expect((await SELF.fetch(`${ORIGIN}/v1/health`)).status).toBe(200);
  });

  it("response never contains the flag on rejection", async () => {
    feed();
    const body = await attestRequest({ kd: (c) => keyDescription({ challenge: c, hw: hwList({ 704: rootOfTrust({ state: enumerated(2) }) }) }) });
    const text = await (await attest(body)).text();
    expect(text).not.toContain("synthetic-tier-two");
  });
});
