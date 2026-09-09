/**
 * UnCrackable L5 backend on Cloudflare Workers. Wire protocol identical to the Kotlin server
 * (Application.kt / Challenges.kt / AttestationService). Every response is Cache-Control: no-store.
 */
import { runtime } from "./config.ts";
import type { Env } from "./config.ts";
import { Challenges } from "./challenges.ts";
import { Rejected } from "./verifier/verifier.ts";
import type { AttestRequest } from "./verifier/verifier.ts";
import { Unavailable } from "./revocations.ts";
import { State } from "./state.ts";

export { State };

const MAX_BODY = 40 * 1024;

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const error = (status: number, code: string): Response => json(status, { error: code });

function stateStub(env: Env): DurableObjectStub<State> {
  return env.STATE.get(env.STATE.idFromName("singleton")) as DurableObjectStub<State>;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch (e) {
      if (e instanceof Rejected) return error(403, e.code);
      if (e instanceof Unavailable) return error(503, "verification_unavailable");
      console.error("internal_error", (e as Error)?.name);
      return error(500, "internal_error");
    }
  },
  /** Keeps the revocation snapshot warm so the first solver of the day never waits on Google. */
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await stateStub(env).revocations(Math.floor(Date.now() / 1000));
  },
} satisfies ExportedHandler<Env>;

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/v1/health" && request.method === "GET") return json(200, { status: "ok" });
  if (path !== "/v1/challenge" && path !== "/v1/attest") return error(404, "not_found");

  const state = stateStub(env);
  const now = () => Math.floor(Date.now() / 1000);
  let allowed: boolean;
  try {
    allowed = await state.allowRequest(now());
  } catch {
    throw new Unavailable();
  }
  if (!allowed) return error(429, "rate_limited");

  const rt = await runtime(env);
  if (path === "/v1/challenge") {
    if (request.method !== "GET") return error(405, "invalid_request");
    return json(200, { challenge: await rt.challenges.issue(now()), expiresIn: 120 });
  }
  if (request.method !== "POST") return error(405, "invalid_request");
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return error(415, "invalid_request");

  const body = await readBounded(request, MAX_BODY);
  if (body === null) return error(413, "request_too_large");
  const parsed = decodeAttestRequest(body);
  if (parsed === null) return error(400, "invalid_request");

  // AttestationService.attest, in the same order: verify, attest, re-verify, consume, re-verify.
  const bytes = await rt.challenges.verify(parsed.challenge, now());
  const snapshot = await revocations(state, now());
  const tier = await rt.verifier.verify(parsed, bytes, snapshot, Date.now());
  if (tier !== 2) throw new Rejected("device_integrity");
  await rt.challenges.verify(parsed.challenge, now());
  let consumed: boolean;
  try {
    consumed = await state.consume(await Challenges.id(bytes), Challenges.expiresAtSeconds(bytes), now());
  } catch {
    throw new Unavailable();
  }
  if (!consumed) throw new Rejected("challenge_replayed");
  await rt.challenges.verify(parsed.challenge, now());
  return json(200, { tier: 2, flag: rt.flag });
}

async function revocations(state: DurableObjectStub<State>, nowSeconds: number): Promise<Set<string>> {
  let view;
  try {
    view = await state.revocations(nowSeconds);
  } catch {
    throw new Unavailable();
  }
  if (view.serials === null) throw new Unavailable();
  return new Set(view.serials);
}

/** Reads at most `max` bytes; null when the body is larger. Never trusts Content-Length alone. */
async function readBounded(request: Request, max: number): Promise<Uint8Array | null> {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/** Strict decoding matching kotlinx: exactly the three fields, correct types, no unknown keys, valid UTF-8. */
function decodeAttestRequest(body: Uint8Array): AttestRequest | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return null;
  }
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 3 || !("challenge" in o) || !("chain" in o) || !("pop" in o)) return null;
  if (typeof o.challenge !== "string" || typeof o.pop !== "string" || !Array.isArray(o.chain)) return null;
  if (!o.chain.every((c) => typeof c === "string")) return null;
  return { challenge: o.challenge, chain: o.chain as string[], pop: o.pop };
}
