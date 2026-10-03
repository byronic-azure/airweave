// Applies the D1 migrations to the (isolated, per-test) evidence database before
// each test file. See vitest.config.ts for where TEST_MIGRATIONS comes from.
import { applyD1Migrations, env } from "cloudflare:test";

await applyD1Migrations(env.EVIDENCE_DB, env.TEST_MIGRATIONS);
