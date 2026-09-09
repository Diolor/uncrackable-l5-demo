import { verifyChainAndPop, b64urlDecode, parseCert, importKey } from "./verify";
import fixture from "../../../fixtures/oneplus9pro-android14-tee-tier2.json";

const FEED = "https://android.googleapis.com/attestation/status";

export default {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/attest") {
      const n = Number(url.searchParams.get("n") ?? "1");
      let r;
      for (let i = 0; i < n; i++) {
        r = await verifyChainAndPop(fixture.chain, b64urlDecode(fixture.challenge), fixture.pop);
      }
      return Response.json({ iterations: n, ...r });
    }
    if (url.pathname === "/noop") return Response.json({ ok: true });
    if (url.pathname === "/parse") {
      const certs = fixture.chain.map((b) => parseCert(Uint8Array.from(atob(b), (ch) => ch.charCodeAt(0))));
      const keys = await Promise.all(certs.map(importKey));
      return Response.json({ keys: keys.length });
    }
    if (url.pathname === "/feed") {
      const res = await fetch(FEED, { headers: { "cache-control": "max-age=0" } });
      const text = await res.text();
      const json = JSON.parse(text) as { entries: Record<string, unknown> };
      const serials = new Set(Object.keys(json.entries));
      return Response.json({ bytes: text.length, entries: serials.size });
    }
    return new Response("spike", { status: 404 });
  },
};
