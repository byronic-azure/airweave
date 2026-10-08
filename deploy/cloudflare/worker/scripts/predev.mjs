// @ts-check
// Preflight for `npm run dev`: apply local D1 migrations only when wrangler.jsonc
// actually binds EVIDENCE_DB. Without the binding (operator removed it to run
// without evidence storage) the migration is skipped and the Worker logs
// evidence to the console. With the binding present, a migration failure is a
// real error and must fail `npm run dev` instead of being swallowed.
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bindingIndex, readConfig } from "./lib/config.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { data } = readConfig(join(root, "wrangler.jsonc"));
const index = bindingIndex(data, "d1_databases", "binding", "EVIDENCE_DB");

if (index < 0) {
  console.log(
    "EVIDENCE_DB not bound in wrangler.jsonc: skipping local D1 migrations (evidence logs to the console)",
  );
  process.exit(0);
}

const database = String(data.d1_databases[index].database_name);
const wrangler = join(root, "node_modules", "wrangler", "bin", "wrangler.js");
const result = spawnSync(process.execPath, [wrangler, "d1", "migrations", "apply", database, "--local"], {
  cwd: root,
  stdio: "inherit",
});
if (result.error) {
  console.error(`predev: could not run wrangler: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
