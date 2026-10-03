// Vitest runs the test files inside workerd (the Workers runtime) through
// @cloudflare/vitest-pool-workers, using the bindings declared in wrangler.toml.
// D1 migrations are read here on the Node side and handed to the test worker as
// a binding; test/setup.ts applies them before each test file runs.
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          bindings: { TEST_MIGRATIONS: migrations },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/setup.ts"],
      // The pool shares one local D1/KV store between files; keep files sequential
      // so test/helpers.ts resetStorage() cannot race another file's assertions.
      fileParallelism: false,
    },
  };
});
