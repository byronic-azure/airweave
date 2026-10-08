#!/usr/bin/env node
// @ts-check
// One command for the whole Airweave edge stack:
//
//   client -> Worker airweave-edge-gateway (api.<zone>, Custom Domain)
//          -> https://airweave-origin.<zone>  (Access: the Worker's service token only)
//          -> Cloudflare Tunnel -> cloudflared in Docker Desktop Kubernetes
//          -> Airweave backend :8001 (docker compose on this machine, or in-cluster)
//
//   edge.mjs up      provision or reconcile everything, deploy, smoke-test
//   edge.mjs plan    show what `up` would change; changes nothing
//   edge.mjs status  tunnel, connector and end-to-end checks; changes nothing
//   edge.mjs down    remove what `up` created (asks for --yes)
//
// Run `edge.mjs help` for every flag. Usually invoked as ../scripts/edge.sh.

import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { createCloudflareClient, CloudflareApiError } from "./lib/cloudflare.mjs";
import { applyConfigEdits, bindingIndex, readConfig } from "./lib/config.mjs";
import { run as realRun } from "./lib/exec.mjs";
import { BACKEND_SERVICE, checkCluster, deployConnector, removeConnector } from "./lib/k8s.mjs";
import { createLogger } from "./lib/log.mjs";
import {
  checkCustomDomain,
  deleteCreated,
  ensureAccessApp,
  ensureCname,
  ensureD1,
  ensureIngress,
  ensureKvNamespace,
  ensurePolicy,
  ensureServiceToken,
  ensureTunnel,
  ensureZeroTrust,
  resolveAccount,
  resolveZone,
  tunnelStatus,
  workerExists,
} from "./lib/provision.mjs";
import { smokeTest } from "./lib/smoke.mjs";
import { loadState, removeState, saveState } from "./lib/state.mjs";
import { EdgeError, normalizeHostname, sleep as realSleep, splitList } from "./lib/util.mjs";
import { deployWorker, workerConfigEdits, wrangler } from "./lib/worker.mjs";

const WORKER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CF_DIR = resolve(WORKER_DIR, "..");

/** Names of the resources `up` manages (matched by name on every run). */
export const NAMES = {
  tunnel: "airweave-origin",
  serviceToken: "airweave-edge-gateway-origin",
  policyOrigin: "airweave-edge-gateway: Worker service token",
  policyUsers: "airweave-edge-gateway: users",
  policyHealth: "airweave-edge-gateway: health checks",
  appOrigin: "airweave-origin (edge gateway only)",
  appApi: "airweave-edge-gateway",
  appHealth: "airweave-edge-gateway /healthz",
  kv: "airweave-edge-denylist",
};

const HELP = `Usage: edge.mjs <up|plan|status|down|help> [flags]

  up       provision or reconcile the whole stack, deploy the Worker, start the
           connector in Docker Desktop Kubernetes and smoke-test the path
  plan     print what \`up\` would create or change; changes nothing
  status   tunnel health, connector readiness and end-to-end checks
  down     remove what \`up\` created (prints the plan unless --yes)

Flags (a value given once is remembered in the state file for later runs):
  --zone <zone>               Cloudflare zone, e.g. example.com        (env EDGE_ZONE)
  --account <id>              account id; optional if the token sees one account
                                                                       (env CLOUDFLARE_ACCOUNT_ID)
  --api-host <host>           gateway hostname        (default api.<zone>)
  --origin-host <host>        tunnel hostname         (default airweave-origin.<zone>)
  --auth <api-key|access-jwt> who may call the gateway (default api-key: a generated key
                              in the X-Airweave-Gateway-Key header)
  --allow-email <a,b>         access-jwt: users allowed by email
  --allow-email-domain <d,e>  access-jwt: users allowed by email domain
  --allowed-origins <o1,o2>   browser origins for CORS (default: keep wrangler.jsonc)
  --backend <host|cluster>    host = docker compose on this machine (mode A, default);
                              cluster = an airweave-backend Service in the cluster (mode B)
  --backend-url <url>         where the mode A preflight finds the backend
                              (default http://localhost:8001)
  --context <name>            kube context            (default docker-desktop; env KUBE_CONTEXT)
  --tunnel-name <name>        tunnel name             (default ${NAMES.tunnel})
  --strict-service-tokens     turn on Access strict service token authentication
                              (organization-wide; Cloudflare's recommended setting)
  --rotate-api-key            api-key mode: generate a new gateway key
  --skip-k8s                  leave Kubernetes alone (the connector runs elsewhere)
  --skip-backend-check        skip the mode A preflight (backend up, AUTH_ENABLED=true)
  --skip-smoke                skip the end-to-end checks after \`up\`
  --yes                       down: really delete
  --delete-data               down: also delete the KV denylist and the D1 evidence log
  --state <file>              state file (default deploy/cloudflare/.edge/state.json)

Environment:
  CLOUDFLARE_API_TOKEN  required. Permissions: Account > Cloudflare Tunnel: Edit,
                        Access: Apps and Policies: Edit, Access: Service Tokens: Edit,
                        Access: Organizations, Identity Providers, and Groups: Read (Edit
                        with --strict-service-tokens), Workers Scripts: Edit, Workers KV
                        Storage: Edit, D1: Edit, Account Settings: Read; Zone > Zone: Read,
                        DNS: Edit, Workers Routes: Edit.
  TYPESAFE_API_KEY      optional; uploaded as the Worker secret of the same name.
`;

/**
 * @typedef {object} Deps
 * @property {typeof fetch} [fetchImpl]
 * @property {import("./lib/exec.mjs").Runner} [run]
 * @property {(ms: number) => Promise<unknown>} [sleep]
 * @property {() => number} [now]
 * @property {(s: string) => void} [write]
 * @property {Record<string, string | undefined>} [env]
 * @property {{ workerDir?: string, configFile?: string, k8sDir?: string, stateFile?: string }} [paths]
 * @property {number} [smokeAttempts]
 * @property {number} [tunnelWaitAttempts]
 */

/**
 * @param {string[]} argv  arguments after the script name
 * @param {Deps} [deps]
 * @returns {Promise<number>} exit code
 */
export async function main(argv, deps = {}) {
  const env = deps.env ?? process.env;
  const write = deps.write ?? ((s) => process.stdout.write(s));
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      zone: { type: "string" },
      account: { type: "string" },
      "api-host": { type: "string" },
      "origin-host": { type: "string" },
      auth: { type: "string" },
      "allow-email": { type: "string" },
      "allow-email-domain": { type: "string" },
      "allowed-origins": { type: "string" },
      backend: { type: "string" },
      "backend-url": { type: "string" },
      context: { type: "string" },
      "tunnel-name": { type: "string" },
      "strict-service-tokens": { type: "boolean" },
      "rotate-api-key": { type: "boolean" },
      "skip-k8s": { type: "boolean" },
      "skip-backend-check": { type: "boolean" },
      "skip-smoke": { type: "boolean" },
      yes: { type: "boolean" },
      "delete-data": { type: "boolean" },
      state: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  const command = positionals[0] ?? "help";
  if (values.help || command === "help") {
    write(HELP);
    return 0;
  }
  if (!["up", "plan", "status", "down"].includes(command)) throw new EdgeError(`unknown command "${command}"\n\n${HELP}`);
  if (positionals.length > 1) throw new EdgeError(`unexpected argument "${positionals[1]}"`);

  const workerDir = deps.paths?.workerDir ?? WORKER_DIR;
  const paths = {
    workerDir,
    configFile: deps.paths?.configFile ?? join(workerDir, "wrangler.jsonc"),
    k8sDir: deps.paths?.k8sDir ?? join(CF_DIR, "k8s"),
    stateFile: resolve(values.state ?? deps.paths?.stateFile ?? join(CF_DIR, ".edge", "state.json")),
  };
  const state = loadState(paths.stateFile);
  const token = env.CLOUDFLARE_API_TOKEN;
  if (!token) {
    throw new EdgeError(
      "CLOUDFLARE_API_TOKEN is not set. Create a token at https://dash.cloudflare.com/profile/api-tokens with the " +
        "permissions listed under `edge.mjs help`, then: export CLOUDFLARE_API_TOKEN=...",
    );
  }

  const opts = resolveOptions(values, env, state, command);
  const readOnly = command === "plan" || command === "status" || (command === "down" && !values.yes);
  const log = createLogger({ write, dryRun: readOnly && command !== "status" });
  const api = createCloudflareClient({ token, fetchImpl: deps.fetchImpl, sleep: deps.sleep, readOnly });
  /** @type {import("./lib/provision.mjs").Ctx} */
  const ctx = {
    api,
    log,
    state,
    accountId: "",
    now: deps.now,
    persist: readOnly ? () => {} : () => saveState(paths.stateFile, state),
  };
  const runner = deps.run ?? realRun;
  const common = { deps, opts, ctx, paths, runner, token };

  if (command === "down") return down(common, Boolean(values.yes), Boolean(values["delete-data"]));
  if (command === "status") return status(common);
  return up(common, command === "plan", Boolean(values["rotate-api-key"]));
}

/**
 * @typedef {ReturnType<typeof resolveOptions>} Options
 * @typedef {{ deps: Deps, opts: Options, ctx: import("./lib/provision.mjs").Ctx,
 *   paths: { workerDir: string, configFile: string, k8sDir: string, stateFile: string },
 *   runner: import("./lib/exec.mjs").Runner, token: string }} Common
 */

/**
 * Flags win over the environment, which wins over the previous run's state.
 * @param {Record<string, string | boolean | undefined>} v
 * @param {Record<string, string | undefined>} env
 * @param {import("./lib/state.mjs").EdgeState} state
 * @param {string} command
 */
export function resolveOptions(v, env, state, command) {
  /** @param {string} k */
  const str = (k) => (typeof v[k] === "string" ? /** @type {string} */ (v[k]) : undefined);
  const zoneRaw = str("zone") ?? env.EDGE_ZONE ?? state.zone;
  if (!zoneRaw) throw new EdgeError(`--zone is required (e.g. --zone example.com) for \`${command}\``);
  const zone = normalizeHostname(zoneRaw, "--zone");
  const inZone = (/** @type {string} */ host, /** @type {string} */ flag) => {
    const h = normalizeHostname(host, flag);
    if (h !== zone && !h.endsWith(`.${zone}`)) throw new EdgeError(`${flag} ${h} is not inside the zone ${zone}`);
    return h;
  };
  const apiHost = inZone(str("api-host") ?? state.apiHost ?? `api.${zone}`, "--api-host");
  const originHost = inZone(str("origin-host") ?? state.originHost ?? `airweave-origin.${zone}`, "--origin-host");
  if (apiHost === originHost) throw new EdgeError("--api-host and --origin-host must differ");

  const authMode = str("auth") ?? state.authMode ?? "api-key";
  if (authMode !== "api-key" && authMode !== "access-jwt") {
    throw new EdgeError(`--auth must be api-key or access-jwt, got "${authMode}"`);
  }
  const prev = /** @type {Record<string, unknown>} */ (state);
  const allowEmails = str("allow-email") !== undefined ? splitList(str("allow-email")) : /** @type {string[]} */ (prev.allowEmails ?? []);
  const allowDomains =
    str("allow-email-domain") !== undefined ? splitList(str("allow-email-domain")) : /** @type {string[]} */ (prev.allowEmailDomains ?? []);
  if (authMode === "access-jwt" && command !== "down" && allowEmails.length + allowDomains.length === 0) {
    throw new EdgeError("--auth access-jwt needs --allow-email and/or --allow-email-domain (who may sign in)");
  }
  const backend = str("backend") ?? state.backend ?? "host";
  if (backend !== "host" && backend !== "cluster") throw new EdgeError(`--backend must be host or cluster, got "${backend}"`);
  return {
    zone,
    account: str("account") ?? env.CLOUDFLARE_ACCOUNT_ID ?? state.accountId,
    apiHost,
    originHost,
    authMode: /** @type {"api-key" | "access-jwt"} */ (authMode),
    allowEmails,
    allowDomains,
    allowedOrigins: str("allowed-origins"),
    backend: /** @type {"host" | "cluster"} */ (backend),
    backendUrl: trimSlashes(str("backend-url") ?? "http://localhost:8001"),
    context: str("context") ?? env.KUBE_CONTEXT ?? state.kubeContext ?? "docker-desktop",
    tunnelName: str("tunnel-name") ?? state.tunnelName ?? NAMES.tunnel,
    strict: Boolean(v["strict-service-tokens"]),
    skipK8s: Boolean(v["skip-k8s"]),
    skipBackendCheck: Boolean(v["skip-backend-check"]),
    skipSmoke: Boolean(v["skip-smoke"]),
    typesafeKey: env.TYPESAFE_API_KEY,
  };
}

/**
 * Drops trailing slashes with a loop (a /\/+$/ regex is a ReDoS pattern for CodeQL).
 * @param {string} url
 */
function trimSlashes(url) {
  let end = url.length;
  while (end > 0 && url[end - 1] === "/") end--;
  return url.slice(0, end);
}

/** @param {Common} c */
function remember(c) {
  const s = /** @type {Record<string, unknown>} */ (c.ctx.state);
  Object.assign(s, {
    zone: c.opts.zone,
    apiHost: c.opts.apiHost,
    originHost: c.opts.originHost,
    authMode: c.opts.authMode,
    backend: c.opts.backend,
    kubeContext: c.opts.context,
    tunnelName: c.opts.tunnelName,
    allowEmails: c.opts.allowEmails,
    allowEmailDomains: c.opts.allowDomains,
  });
}

/**
 * Mode A preflight: the backend answers, and it does not serve data to an
 * anonymous caller (AUTH_ENABLED=true), because the tunnel publishes it.
 * @param {Common} c
 */
async function checkBackend(c) {
  const fetchImpl = c.deps.fetchImpl ?? fetch;
  const { log } = c.ctx;
  const base = c.opts.backendUrl;
  /** @param {string} path */
  const get = async (path) => {
    try {
      return (await fetchImpl(`${base}${path}`, { signal: AbortSignal.timeout(10000) })).status;
    } catch {
      return 0;
    }
  };
  const ready = await get("/health/ready");
  if (ready !== 200) {
    throw new EdgeError(
      `the Airweave backend is not answering at ${base}/health/ready (${ready || "unreachable"}). Start it ` +
        "(./start.sh --skip-frontend at the repo root), pass --backend-url, or --skip-backend-check.",
    );
  }
  log.ok(`backend ${base} is ready`);
  const anon = await get("/collections/count");
  if (anon === 200) {
    throw new EdgeError(
      `${base}/collections/count answered 200 without credentials: AUTH_ENABLED is off. The tunnel would ` +
        "publish an unauthenticated API. Set AUTH_ENABLED=true in .env, restart the backend, re-run.",
    );
  }
  log.ok(`backend requires authentication (anonymous request -> ${anon})`);
}

/**
 * @param {Common} c
 * @param {boolean} dryRun
 * @param {boolean} rotateApiKey
 */
async function up(c, dryRun, rotateApiKey) {
  const { ctx, opts, paths } = c;
  const { log, state } = ctx;
  const kube = { run: c.runner, log, k8sDir: paths.k8sDir, context: opts.context };
  if (dryRun) log.info("Plan only: nothing is changed. Lines marked with ? are what `up` would do.");

  log.step("Preflight");
  if (opts.skipK8s) log.skip("Kubernetes (--skip-k8s)");
  else await checkCluster(kube);
  if (opts.backend === "cluster") log.skip("backend preflight (mode B: checked by the smoke test)");
  else if (opts.skipBackendCheck) log.skip("backend preflight (--skip-backend-check)");
  else await checkBackend(c);

  log.step("Cloudflare account");
  ctx.accountId = await resolveAccount(ctx, opts.account);
  state.accountId = ctx.accountId;
  remember(c);
  ctx.persist();
  const zoneId = await resolveZone(ctx, opts.zone);
  state.zoneId = zoneId;
  const { teamDomain } = await ensureZeroTrust(ctx, { strict: opts.strict });

  log.step("Tunnel");
  const tunnel = await ensureTunnel(ctx, opts.tunnelName);
  await ensureIngress(ctx, tunnel.id, opts.originHost, BACKEND_SERVICE[opts.backend]);
  await ensureCname(ctx, zoneId, opts.originHost, `${tunnel.id}.cfargotunnel.com`);

  log.step(`Access: only the Worker may reach ${opts.originHost}`);
  const serviceToken = await ensureServiceToken(ctx, NAMES.serviceToken);
  const originPolicy = await ensurePolicy(ctx, "origin", {
    name: NAMES.policyOrigin,
    decision: "non_identity",
    include: [{ service_token: { token_id: serviceToken.id } }],
  });
  await ensureAccessApp(ctx, "origin", {
    name: NAMES.appOrigin,
    domain: opts.originHost,
    policyIds: [originPolicy],
    warnOnExtraPolicies: true,
  });

  log.step(`Gateway authentication (${opts.authMode})`);
  /** @type {string | undefined} */
  let policyAud;
  let newApiKey = false;
  if (opts.authMode === "access-jwt") {
    const users = await ensurePolicy(ctx, "users", {
      name: NAMES.policyUsers,
      decision: "allow",
      include: [
        ...opts.allowEmails.map((email) => ({ email: { email } })),
        ...opts.allowDomains.map((domain) => ({ email_domain: { domain } })),
      ],
    });
    const health = await ensurePolicy(ctx, "health", {
      name: NAMES.policyHealth,
      decision: "bypass",
      include: [{ everyone: {} }],
    });
    const apiApp = await ensureAccessApp(ctx, "api", { name: NAMES.appApi, domain: opts.apiHost, policyIds: [users] });
    await ensureAccessApp(ctx, "health", { name: NAMES.appHealth, domain: `${opts.apiHost}/healthz`, policyIds: [health] });
    policyAud = apiApp.aud;
  } else {
    // Access applications an earlier access-jwt run created would answer before
    // the Worker ever sees the API key.
    await deleteCreated(ctx, "app:health", `Access application on ${opts.apiHost}/healthz (api-key mode)`, `/accounts/${ctx.accountId}/access/apps/{id}`);
    await deleteCreated(ctx, "app:api", `Access application on ${opts.apiHost} (api-key mode)`, `/accounts/${ctx.accountId}/access/apps/{id}`);
    if (!state.gatewayApiKey || rotateApiKey) {
      const hadKey = Boolean(state.gatewayApiKey);
      if (!dryRun) {
        state.gatewayApiKey = randomBytes(32).toString("base64url");
        ctx.persist();
        newApiKey = true;
      }
      log[hadKey ? "update" : "create"](`gateway API key (X-Airweave-Gateway-Key)${hadKey ? ": rotated" : ""}`);
    } else {
      log.ok("gateway API key (in the state file)");
    }
  }

  log.step("Worker bindings and hostname");
  const config = readConfig(paths.configFile);
  const workerName = String(config.data.name);
  const kvId = bindingIndex(config.data, "kv_namespaces", "binding", "DENYLIST") >= 0 ? await ensureKvNamespace(ctx, NAMES.kv) : undefined;
  const d1Index = bindingIndex(config.data, "d1_databases", "binding", "EVIDENCE_DB");
  const d1Name = d1Index >= 0 ? String(config.data.d1_databases[d1Index].database_name) : undefined;
  const d1Id = d1Name ? await ensureD1(ctx, d1Name) : undefined;
  if (kvId === undefined) log.skip("KV denylist (DENYLIST binding not in wrangler.jsonc)");
  if (d1Id === undefined) log.skip("D1 evidence log (EVIDENCE_DB binding not in wrangler.jsonc)");
  await checkCustomDomain(ctx, zoneId, opts.apiHost, workerName);

  log.step(`Worker configuration (${relative(process.cwd(), paths.configFile) || paths.configFile})`);
  const edits = workerConfigEdits(config.data, {
    apiHost: opts.apiHost,
    originHost: opts.originHost,
    authMode: opts.authMode,
    teamDomain,
    policyAud,
    allowedOrigins: opts.allowedOrigins,
    kvId,
    d1Id,
  });
  const patched = applyConfigEdits(config.text, edits);
  if (patched.changed.length === 0) log.ok("wrangler.jsonc already matches");
  for (const label of patched.changed) log.update(label);
  if (!dryRun && patched.changed.length) writeFileSync(paths.configFile, patched.text);

  log.step(`Deploy Worker ${workerName}`);
  /** @type {Record<string, string>} */
  const secrets = {
    ORIGIN_SERVICE_TOKEN_ID: serviceToken.clientId,
    ORIGIN_SERVICE_TOKEN_SECRET: serviceToken.clientSecret,
  };
  if (opts.authMode === "api-key" && state.gatewayApiKey) secrets.GATEWAY_API_KEY = state.gatewayApiKey;
  if (opts.typesafeKey) secrets.TYPESAFE_API_KEY = opts.typesafeKey;
  const wranglerDeps = {
    run: c.runner,
    workerDir: paths.workerDir,
    configFile: paths.configFile,
    env: { CLOUDFLARE_API_TOKEN: c.token, CLOUDFLARE_ACCOUNT_ID: ctx.accountId },
  };
  if (dryRun) {
    if (d1Name) log.update(`wrangler d1 migrations apply ${d1Name} --remote`);
    log.update(`wrangler deploy with secrets ${Object.keys(secrets).join(", ")}`);
  } else {
    const existed = await workerExists(ctx, workerName);
    if (d1Name) {
      await wrangler(wranglerDeps, ["d1", "migrations", "apply", d1Name, "--remote"]);
      log.ok(`D1 ${d1Name}: migrations applied`);
    }
    const secretsDir = dirname(paths.stateFile);
    mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
    await deployWorker(wranglerDeps, { secrets, secretsDir });
    if (!existed) {
      state.created.worker = true;
      state.ids.worker = workerName;
      ctx.persist();
    }
    log[existed ? "update" : "create"](`Worker ${workerName} on https://${opts.apiHost} with secrets ${Object.keys(secrets).join(", ")}`);
  }

  log.step(`Connector (cloudflared in kube context ${opts.context})`);
  if (opts.skipK8s) log.skip("--skip-k8s: run cloudflared with this tunnel's token yourself");
  else if (dryRun || !tunnel.token) log.update("Secret cloudflared-token and overlay k8s/overlays/token, then wait for the rollout");
  else await deployConnector(kube, { token: tunnel.token });

  if (dryRun) {
    log.info("\nPlan complete. Run the same command with `up` to apply it.");
    return 0;
  }

  log.step("Tunnel health");
  await waitForTunnel(c, tunnel.id);

  let healthy = true;
  if (opts.skipSmoke) {
    log.step("Smoke test");
    log.skip("--skip-smoke");
  } else {
    log.step("Smoke test (from this machine; new hostnames can take a minute or two)");
    healthy = await smokeTest(
      { fetchImpl: c.deps.fetchImpl, sleep: c.deps.sleep, log, attempts: c.deps.smokeAttempts },
      {
        apiHost: opts.apiHost,
        originHost: opts.originHost,
        authMode: opts.authMode,
        apiKey: state.gatewayApiKey,
        originToken: serviceToken,
      },
    );
  }
  summary(c, healthy, newApiKey);
  return healthy ? 0 : 1;
}

/**
 * @param {Common} c
 * @param {string} tunnelId
 */
async function waitForTunnel(c, tunnelId) {
  const attempts = c.deps.tunnelWaitAttempts ?? 24;
  const pause = c.deps.sleep ?? realSleep;
  let last = "unknown";
  for (let i = 0; i < attempts; i++) {
    last = await tunnelStatus(c.ctx, tunnelId);
    if (last === "healthy") {
      c.ctx.log.ok("tunnel is healthy");
      return;
    }
    if (i + 1 < attempts) await pause(5000);
  }
  c.ctx.log.warn(`tunnel status is "${last}" (expected healthy); is cloudflared running with this tunnel's token?`);
}

/**
 * @param {Common} c
 * @param {boolean} healthy
 * @param {boolean} newApiKey
 */
function summary(c, healthy, newApiKey) {
  const { opts, ctx, paths } = c;
  const say = ctx.log.info;
  const statePath = relative(process.cwd(), paths.stateFile) || paths.stateFile;
  say("");
  say(healthy ? "Edge stack is up." : "Edge stack is deployed, but some checks failed (see FAIL above).");
  say(`  Gateway  https://${opts.apiHost}   (AUTH_MODE ${opts.authMode})`);
  say(`  Origin   https://${opts.originHost}   (Access admits only the Worker's service token)`);
  say(
    `  Backend  ${opts.backend === "host" ? "mode A: docker compose on this machine via host.docker.internal:8001" : "mode B: Service airweave-backend in the cluster"}`,
  );
  say(`  State    ${statePath} (0600; holds the origin service token secret and the gateway key)`);
  if (opts.authMode === "api-key") {
    say(`\n  ${newApiKey ? "A new gateway API key was generated. " : ""}Read it from the state file (never printed):`);
    say(`    KEY=$(node -p "require('${resolve(paths.stateFile)}').gatewayApiKey")`);
    say(`    curl -H "X-Airweave-Gateway-Key: $KEY" https://${opts.apiHost}/health/ready`);
  } else {
    say(`\n  Sign in at https://${opts.apiHost}/ in a browser, or: cloudflared access curl https://${opts.apiHost}/health/ready`);
  }
  say("\n  Re-run `up` any time: Cloudflare resources change only where they drifted and the Worker is");
  say("  redeployed with the current code. `status` re-checks the path; `down --yes` removes the stack.");
}

/** @param {Common} c */
async function status(c) {
  const { ctx, opts } = c;
  const { log, state } = ctx;
  if (!state.ids.tunnel) throw new EdgeError(`no state at ${c.paths.stateFile}; run \`up\` first`);
  ctx.accountId = opts.account ?? state.accountId ?? (await resolveAccount(ctx, undefined));
  log.step("Tunnel");
  const tstatus = await tunnelStatus(ctx, state.ids.tunnel);
  if (tstatus === "healthy") log.ok(`tunnel ${opts.tunnelName} is healthy`);
  else log.fail(`tunnel ${opts.tunnelName} is ${tstatus}`);
  log.step(`Connector (kube context ${opts.context})`);
  if (opts.skipK8s) log.skip("--skip-k8s");
  else {
    const r = await c.runner(
      "kubectl",
      ["--context", opts.context, "get", "deployment/cloudflared", "-n", "airweave", "-o", "jsonpath={.status.readyReplicas}"],
      { allowFailure: true },
    ).catch(() => ({ code: 1, stdout: "", stderr: "kubectl not found" }));
    if (r.code === 0 && Number(r.stdout) >= 1) log.ok(`deployment/cloudflared has ${r.stdout} ready replica(s)`);
    else log.fail(`deployment/cloudflared is not ready ${r.stderr.trim()}`);
  }
  log.step("End-to-end");
  const ok = await smokeTest(
    { fetchImpl: c.deps.fetchImpl, sleep: c.deps.sleep, log, attempts: c.deps.smokeAttempts ?? 2 },
    {
      apiHost: opts.apiHost,
      originHost: opts.originHost,
      authMode: opts.authMode,
      apiKey: state.gatewayApiKey,
      originToken: state.serviceToken,
    },
  );
  const failed = log.actions.some((a) => a.tag === "fail");
  log.info(failed || !ok ? "\nSome checks failed." : "\nAll checks passed.");
  return failed || !ok ? 1 : 0;
}

/**
 * @param {Common} c
 * @param {boolean} yes
 * @param {boolean} deleteData
 */
async function down(c, yes, deleteData) {
  const { ctx, opts, paths } = c;
  const { log, state } = ctx;
  if (!yes) log.info("Plan only: re-run with --yes to delete. Only resources `up` created are removed.");
  ctx.accountId = opts.account ?? state.accountId ?? (await resolveAccount(ctx, undefined));
  const a = `/accounts/${ctx.accountId}`;

  log.step("Connector");
  if (opts.skipK8s) log.skip("--skip-k8s");
  else await removeConnector({ run: c.runner, log, k8sDir: paths.k8sDir, context: opts.context });

  log.step("Worker");
  if (state.created.worker) {
    const name = state.ids.worker ?? String(readConfig(paths.configFile).data.name);
    if (yes) {
      await wrangler(
        {
          run: c.runner,
          workerDir: paths.workerDir,
          configFile: paths.configFile,
          env: { CLOUDFLARE_API_TOKEN: c.token, CLOUDFLARE_ACCOUNT_ID: ctx.accountId },
        },
        ["delete", "--name", name, "--force"],
      );
      delete state.created.worker;
      delete state.ids.worker;
      ctx.persist();
    }
    log.remove(`Worker ${name} and its Custom Domain ${opts.apiHost}`);
  } else log.skip("Worker (not created by up)");

  log.step("Access");
  await deleteCreated(ctx, "app:health", "Access application /healthz", `${a}/access/apps/{id}`);
  await deleteCreated(ctx, "app:api", "Access application on the gateway", `${a}/access/apps/{id}`);
  await deleteCreated(ctx, "app:origin", "Access application on the origin", `${a}/access/apps/{id}`);
  await deleteCreated(ctx, "policy:health", "Access policy health checks", `${a}/access/policies/{id}`);
  await deleteCreated(ctx, "policy:users", "Access policy users", `${a}/access/policies/{id}`);
  await deleteCreated(ctx, "policy:origin", "Access policy Worker service token", `${a}/access/policies/{id}`);
  await deleteCreated(ctx, "service-token", "Access service token", `${a}/access/service_tokens/{id}`);
  if (yes && !state.created["service-token"]) delete state.serviceToken;

  log.step("Tunnel and DNS");
  if (state.created["dns:origin"] && state.zoneId) {
    await deleteCreated(ctx, "dns:origin", `DNS record ${opts.originHost}`, `/zones/${state.zoneId}/dns_records/{id}`);
  }
  if (state.created.tunnel && state.ids.tunnel) {
    if (yes) {
      await ctx.api.del(`${a}/cfd_tunnel/${state.ids.tunnel}/connections`).catch((err) => {
        if (!(err instanceof CloudflareApiError && err.status === 404)) throw err;
      });
    }
    await deleteCreated(ctx, "tunnel", `tunnel ${opts.tunnelName}`, `${a}/cfd_tunnel/{id}`);
  }

  log.step("Data");
  if (deleteData) {
    await deleteCreated(ctx, "kv", "KV namespace (denylist)", `${a}/storage/kv/namespaces/{id}`);
    await deleteCreated(ctx, "d1", "D1 database (evidence log)", `${a}/d1/database/{id}`);
  } else if (state.created.kv || state.created.d1) {
    log.skip("KV denylist and D1 evidence log kept (pass --delete-data to remove them)");
  }

  if (!yes) return 0;
  if (Object.keys(state.created).length === 0) {
    removeState(paths.stateFile);
    log.info(`\nRemoved ${paths.stateFile}.`);
  }
  log.info("wrangler.jsonc keeps the account values `up` wrote; `git checkout -- deploy/cloudflare/worker/wrangler.jsonc` restores the template.");
  return 0;
}

/** @param {unknown} err */
function report(err) {
  if (err instanceof EdgeError || err instanceof CloudflareApiError) {
    process.stderr.write(`\nerror: ${err.message}\n`);
    return 1;
  }
  if (err instanceof Error && /** @type {{ code?: string }} */ (err).code?.startsWith("ERR_PARSE_ARGS")) {
    process.stderr.write(`error: ${err.message}\n\n${HELP}`);
    return 2;
  }
  process.stderr.write(`\nerror: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  return 1;
}

const isEntry = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntry) {
  const [major] = process.versions.node.split(".").map(Number);
  if ((major ?? 0) < 22) {
    process.stderr.write(`error: Node.js 22 or newer is required (this is ${process.versions.node})\n`);
    process.exit(1);
  }
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => process.exit(report(err)),
  );
}

