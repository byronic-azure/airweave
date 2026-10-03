// Types for the `env` object that cloudflare:test hands to the test files.
// `Cloudflare.Env` is the global that `wrangler types` would normally generate;
// we declare it by hand from the gateway's own Env interface instead.
import type { Env } from "../src/env";

declare global {
  namespace Cloudflare {
    interface Env extends Omit<Env, "EVIDENCE_DB" | "DENYLIST"> {
      EVIDENCE_DB: D1Database;
      DENYLIST: KVNamespace;
      TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    }
  }
}

export {};
