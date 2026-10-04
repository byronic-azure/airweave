// @ts-check
// The Worker side: account-specific values written into wrangler.jsonc (so a
// later plain `npm run deploy` keeps working), remote D1 migrations, and one
// `wrangler deploy --secrets-file` so code and secrets go live together.

import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { bindingIndex } from "./config.mjs";

/**
 * @typedef {object} WorkerValues
 * @property {string} apiHost
 * @property {string} originHost
 * @property {"api-key" | "access-jwt"} authMode
 * @property {string} [teamDomain]
 * @property {string} [policyAud]
 * @property {string} [allowedOrigins]
 * @property {string} [kvId]
 * @property {string} [d1Id]
 */

/**
 * The wrangler.jsonc edits for these values. Bindings the operator removed from
 * the config (both are optional) are left out rather than re-added.
 * @param {Record<string, any>} data  parsed wrangler.jsonc
 * @param {WorkerValues} v
 * @returns {import("./config.mjs").ConfigEdit[]}
 */
export function workerConfigEdits(data, v) {
  /** @type {import("./config.mjs").ConfigEdit[]} */
  const edits = [
    { path: ["routes"], value: [{ pattern: v.apiHost, custom_domain: true }], label: `routes: ${v.apiHost} (Custom Domain)` },
    { path: ["workers_dev"], value: false, label: "workers_dev: false" },
    { path: ["preview_urls"], value: false, label: "preview_urls: false" },
    { path: ["vars", "ORIGIN_URL"], value: `https://${v.originHost}`, label: `ORIGIN_URL: https://${v.originHost}` },
    { path: ["vars", "AUTH_MODE"], value: v.authMode, label: `AUTH_MODE: ${v.authMode}` },
    { path: ["vars", "ALLOW_INSECURE_DEV"], value: "0", label: "ALLOW_INSECURE_DEV: 0" },
  ];
  if (v.authMode === "access-jwt" && v.teamDomain && v.policyAud) {
    edits.push({ path: ["vars", "TEAM_DOMAIN"], value: v.teamDomain, label: `TEAM_DOMAIN: ${v.teamDomain}` });
    edits.push({ path: ["vars", "POLICY_AUD"], value: v.policyAud, label: "POLICY_AUD: <Access application AUD tag>" });
  }
  if (v.allowedOrigins !== undefined) {
    edits.push({ path: ["vars", "ALLOWED_ORIGINS"], value: v.allowedOrigins, label: `ALLOWED_ORIGINS: ${v.allowedOrigins}` });
  }
  const kv = bindingIndex(data, "kv_namespaces", "binding", "DENYLIST");
  if (kv >= 0 && v.kvId) edits.push({ path: ["kv_namespaces", kv, "id"], value: v.kvId, label: `DENYLIST id: ${v.kvId}` });
  const d1 = bindingIndex(data, "d1_databases", "binding", "EVIDENCE_DB");
  if (d1 >= 0 && v.d1Id) {
    edits.push({ path: ["d1_databases", d1, "database_id"], value: v.d1Id, label: `EVIDENCE_DB database_id: ${v.d1Id}` });
  }
  return edits;
}

/**
 * @typedef {object} WranglerDeps
 * @property {import("./exec.mjs").Runner} run
 * @property {string} workerDir
 * @property {string} configFile            the wrangler.jsonc that `up` edited
 * @property {Record<string, string>} env   CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID
 */

/**
 * Runs the project's pinned wrangler through node (no shell, no npx lookup).
 * @param {WranglerDeps} deps
 * @param {string[]} args
 */
export function wrangler(deps, args) {
  const bin = join(deps.workerDir, "node_modules", "wrangler", "bin", "wrangler.js");
  return deps.run(process.execPath, [bin, ...args, "--config", deps.configFile], {
    cwd: deps.workerDir,
    env: { ...deps.env, WRANGLER_SEND_METRICS: "false", CI: "1", FORCE_COLOR: "0" },
    echo: true,
  });
}

/**
 * Deploys code and secrets as one version. The secrets file is 0600 in the
 * state directory and removed even when the deploy fails.
 * @param {WranglerDeps} deps
 * @param {{ secrets: Record<string, string>, secretsDir: string }} opts
 */
export async function deployWorker(deps, opts) {
  const file = join(opts.secretsDir, `secrets.${process.pid}.json`);
  writeFileSync(file, JSON.stringify(opts.secrets), { mode: 0o600 });
  try {
    await wrangler(deps, ["deploy", "--secrets-file", file]);
  } finally {
    rmSync(file, { force: true });
  }
}
