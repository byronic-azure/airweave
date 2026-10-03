// Preflight for `npm run dev`: apply local D1 migrations only when wrangler.toml
// actually binds EVIDENCE_DB. Without the binding (operator commented it out to
// run without evidence storage) the migration is skipped and the Worker logs
// evidence to the console. With the binding present, a migration failure is a
// real error and must fail `npm run dev` instead of being swallowed.
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const config = readFileSync(resolve(root, "wrangler.toml"), "utf8");

// Strip comments and blank lines, then look for a d1_databases table that binds
// EVIDENCE_DB (TOML array tables keep their keys until the next table header).
const lines = config
  .split(/\r?\n/)
  .map((line) => line.replace(/#.*$/, "").trim())
  .filter((line) => line !== "");

let inD1 = false;
let bound = false;
for (const line of lines) {
  if (line.startsWith("[")) {
    inD1 = line === "[[d1_databases]]";
    continue;
  }
  if (inD1 && /^binding\s*=\s*"EVIDENCE_DB"$/.test(line)) {
    bound = true;
    break;
  }
}

if (!bound) {
  console.log(
    "EVIDENCE_DB not bound in wrangler.toml: skipping local D1 migrations (evidence logs to the console)",
  );
  process.exit(0);
}

const result = spawnSync(
  "npx",
  ["wrangler", "d1", "migrations", "apply", "airweave-edge-evidence", "--local"],
  { cwd: root, stdio: "inherit", shell: process.platform === "win32" },
);
if (result.error) {
  console.error(`predev: could not run wrangler: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
