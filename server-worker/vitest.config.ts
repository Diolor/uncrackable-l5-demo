import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityFlags: ["nodejs_compat"],
        bindings: {
          CHALLENGE_HMAC_KEY: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
          FLAG_TIER2: "synthetic-tier-two",
          APP_SIGNER_SHA256: "0404040404040404040404040404040404040404040404040404040404040404",
          ATTESTATION_ROOTS: readFileSync(new URL("./test/fixtures/test-root.pem", import.meta.url), "utf8"),
        },
      },
    }),
  ],
  test: { include: ["test/*.test.ts"] },
});
