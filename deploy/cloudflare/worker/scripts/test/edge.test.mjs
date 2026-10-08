// @ts-check
// End-to-end tests of edge.mjs against the in-memory Cloudflare fake.
// Run with: npm run test:scripts  (node --test)

import assert from "node:assert/strict";
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { main } from "../edge.mjs";
import { parseJsonc } from "../lib/config.mjs";
import { EdgeError } from "../lib/util.mjs";
import { FakeCloudflare, fakeFetch, fakeRunner, healthyWeb } from "./fake-cloudflare.mjs";

const WORKER_DIR = resolve(fileURLToPath(import.meta.url), "../../..");

/** @type {string} */ let dir;
/** @type {FakeCloudflare} */ let cf;
/** @type {ReturnType<typeof fakeRunner>} */ let runner;
/** @type {string} */ let out;

const stateFile = () => join(dir, ".edge", "state.json");
const configFile = () => join(dir, "wrangler.jsonc");
const readState = () => JSON.parse(readFileSync(stateFile(), "utf8"));

/**
 * @param {string[]} argv
 * @param {{ web?: (url: URL, init: RequestInit) => Response | undefined, env?: Record<string, string> }} [o]
 */
async function edge(argv, o = {}) {
  out = "";
  const live = {
    apiKey: () => (existsSync(stateFile()) ? readState().gatewayApiKey : undefined),
    origin: () => {
      const t = cf.tokens[0];
      return t ? { id: t.client_id, secret: t.client_secret } : undefined;
    },
  };
  return main(argv, {
    fetchImpl: fakeFetch(cf, o.web ?? healthyWeb(live)),
    run: runner.run,
    sleep: async () => {},
    now: () => Date.parse("2026-10-04T00:00:00Z"),
    write: (s) => {
      out += s;
    },
    env: { CLOUDFLARE_API_TOKEN: "test-token", ...o.env },
    paths: { workerDir: WORKER_DIR, configFile: configFile(), k8sDir: "/k8s", stateFile: stateFile() },
    smokeAttempts: 1,
    tunnelWaitAttempts: 1,
  });
}

/** Every external command line, joined, to prove no secret ever reached argv. */
const allArgv = () => runner.calls.map((c) => [c.cmd, ...c.args].join(" ")).join("\n");

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "edge-test-"));
  copyFileSync(join(WORKER_DIR, "wrangler.jsonc"), configFile());
  cf = new FakeCloudflare();
  runner = fakeRunner(cf);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("edge.mjs plan", () => {
  it("changes nothing on a fresh account and lists what up would create", async () => {
    const before = readFileSync(configFile(), "utf8");
    assert.equal(await edge(["plan", "--zone", "example.com"]), 0);
    assert.deepEqual(cf.mutations, []);
    assert.equal(existsSync(stateFile()), false);
    assert.equal(readFileSync(configFile(), "utf8"), before);
    assert.ok(!runner.calls.some((c) => c.args.includes("deploy") || c.args.includes("apply")));
    for (const want of ["tunnel airweave-origin", "Access service token", "KV namespace", "D1 database", "wrangler deploy"]) {
      assert.match(out, new RegExp(`(create|update)\\?\\s.*${want}`), want);
    }
  });
});

describe("edge.mjs up (api-key)", () => {
  it("provisions every resource, deploys with secrets via a file, and passes the smoke test", async () => {
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);

    assert.equal(cf.tunnels.length, 1);
    assert.deepEqual(cf.tunnelConfigs[cf.tunnels[0].id].ingress, [
      { hostname: "airweave-origin.example.com", service: "http://airweave-backend-host.airweave.svc.cluster.local:8001", originRequest: {} },
      { service: "http_status:404" },
    ]);
    assert.deepEqual(
      cf.dns.map((r) => [r.type, r.name, r.content, r.proxied]),
      [["CNAME", "airweave-origin.example.com", `${cf.tunnels[0].id}.cfargotunnel.com`, true]],
    );
    assert.equal(cf.tokens.length, 1);
    assert.deepEqual(cf.policies.map((p) => [p.name, p.decision, p.include]), [
      ["airweave-edge-gateway: Worker service token", "non_identity", [{ service_token: { token_id: cf.tokens[0].id } }]],
    ]);
    assert.deepEqual(cf.apps.map((a) => a.domain), ["airweave-origin.example.com"]);
    assert.equal(cf.kv.length, 1);
    assert.equal(cf.d1.length, 1);

    // wrangler.jsonc: account values written, comments kept
    const text = readFileSync(configFile(), "utf8");
    const cfg = parseJsonc(text);
    assert.deepEqual(cfg.routes, [{ pattern: "api.example.com", custom_domain: true }]);
    assert.equal(cfg.vars.ORIGIN_URL, "https://airweave-origin.example.com");
    assert.equal(cfg.vars.AUTH_MODE, "api-key");
    assert.equal(cfg.kv_namespaces[0].id, cf.kv[0].id);
    assert.equal(cfg.d1_databases[0].database_id, cf.d1[0].uuid);
    assert.match(text, /\/\/ Never publish the gateway on <name>\.<account>\.workers\.dev/);

    // secrets: through a 0600 file that is gone afterwards, never argv
    const deploy = runner.calls.find((c) => c.args.includes("deploy"));
    assert.ok(deploy?.secretsFile, "wrangler deploy got a secrets file");
    const state = readState();
    assert.deepEqual(deploy.secretsFile, {
      ORIGIN_SERVICE_TOKEN_ID: cf.tokens[0].client_id,
      ORIGIN_SERVICE_TOKEN_SECRET: cf.tokens[0].client_secret,
      GATEWAY_API_KEY: state.gatewayApiKey,
    });
    const secretsPath = deploy.args[deploy.args.indexOf("--secrets-file") + 1] ?? "";
    assert.equal(existsSync(secretsPath), false, "secrets file removed after deploy");
    for (const secret of [cf.tokens[0].client_secret, state.gatewayApiKey, cf.tunnels[0].token]) {
      assert.ok(!allArgv().includes(secret), "no secret on any command line");
    }
    const migrate = runner.calls.findIndex((c) => c.args.includes("migrations"));
    assert.ok(migrate >= 0 && migrate < runner.calls.indexOf(deploy), "D1 migrations run before the deploy");

    // tunnel token: into the cluster through stdin
    const secretApply = runner.calls.find((c) => c.cmd === "kubectl" && c.args.includes("-") && c.input);
    assert.match(secretApply?.input ?? "", new RegExp(`"TUNNEL_TOKEN":"${cf.tunnels[0].token}"`));

    // state: 0600, remembers the flags and what was created
    if (process.platform !== "win32") assert.equal(statSync(stateFile()).mode & 0o777, 0o600);
    assert.equal(state.zone, "example.com");
    assert.equal(state.serviceToken.clientSecret, cf.tokens[0].client_secret);
    for (const key of ["tunnel", "dns:origin", "service-token", "policy:origin", "app:origin", "kv", "d1", "worker"]) {
      assert.equal(state.created[key], true, key);
    }
    assert.match(out, /Edge stack is up\./);
    assert.match(out, /ok\s+end-to-end/);
    assert.match(out, /ok\s+evidence/);
  });

  it("is idempotent: a second run changes nothing in Cloudflare and needs no flags", async () => {
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    const config = readFileSync(configFile(), "utf8");
    cf.mutations.length = 0;
    const restartsBefore = runner.calls.filter((c) => c.args.includes("restart")).length;

    assert.equal(await edge(["up"]), 0, out);
    assert.deepEqual(cf.mutations, []);
    assert.equal(readFileSync(configFile(), "utf8"), config);
    assert.match(out, /wrangler\.jsonc already matches/);
    assert.equal(runner.calls.filter((c) => c.args.includes("restart")).length, restartsBefore);
    assert.doesNotMatch(out, /^create /m);
  });

  it("rotates the service token secret instead of duplicating it when the state file is lost", async () => {
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    const first = cf.tokens[0].client_secret;
    rmSync(stateFile());
    cf.mutations.length = 0;

    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    assert.equal(cf.tokens.length, 1);
    assert.equal(cf.tunnels.length, 1);
    assert.ok(cf.mutations.some((m) => m.endsWith("/rotate")));
    assert.notEqual(readState().serviceToken.clientSecret, first);
    assert.match(out, /secret rotated/);
  });

  it("keeps other hostnames in an existing tunnel's ingress", async () => {
    cf.tunnels.push({ id: "tun-x", name: "airweave-origin", config_src: "cloudflare", status: "inactive", token: "tok-x" });
    cf.tunnelConfigs["tun-x"] = {
      "warp-routing": { enabled: false },
      ingress: [{ hostname: "grafana.example.com", service: "http://grafana:3000" }, { service: "http_status:404" }],
    };
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    const cfg = cf.tunnelConfigs["tun-x"];
    assert.deepEqual(cfg["warp-routing"], { enabled: false });
    assert.deepEqual(cfg.ingress.map((/** @type {any} */ r) => r.hostname ?? "*"), [
      "grafana.example.com",
      "airweave-origin.example.com",
      "*",
    ]);
  });

  it("refuses to overwrite a DNS record that points elsewhere", async () => {
    cf.dns.push({ id: "dns-x", type: "A", name: "airweave-origin.example.com", content: "192.0.2.1", proxied: true });
    await assert.rejects(edge(["up", "--zone", "example.com"]), (err) => {
      assert.ok(err instanceof EdgeError);
      assert.match(err.message, /already has DNS record\(s\) \[A 192\.0\.2\.1\]/);
      return true;
    });
    assert.deepEqual(cf.dns.map((r) => r.id), ["dns-x"]);
  });

  it("refuses a gateway hostname that already has a DNS record", async () => {
    cf.dns.push({ id: "dns-y", type: "CNAME", name: "api.example.com", content: "elsewhere.example.net", proxied: true });
    await assert.rejects(edge(["up", "--zone", "example.com"]), /Workers Custom Domain cannot be created over them/);
    assert.ok(!runner.calls.some((c) => c.args.includes("deploy")), "no deploy after a failed check");
  });

  it("refuses to publish a backend that has AUTH_ENABLED=false", async () => {
    const web = healthyWeb({ authDisabled: true });
    await assert.rejects(edge(["up", "--zone", "example.com"], { web }), /AUTH_ENABLED is off/);
    assert.deepEqual(cf.mutations, []);
  });

  it("turns on strict service token authentication only when asked", async () => {
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    assert.equal(cf.org.strict_service_token_auth, false);
    assert.match(out, /warn\s+strict service token authentication is off/);
    assert.equal(await edge(["up", "--strict-service-tokens"]), 0, out);
    assert.equal(cf.org.strict_service_token_auth, true);
  });
});

describe("edge.mjs up (access-jwt)", () => {
  it("puts Access in front of the gateway, with a /healthz bypass, and wires TEAM_DOMAIN / POLICY_AUD", async () => {
    const code = await edge(
      ["up", "--zone", "example.com", "--auth", "access-jwt", "--allow-email-domain", "example.com", "--skip-smoke"],
    );
    assert.equal(code, 0, out);
    const users = cf.policies.find((p) => p.name === "airweave-edge-gateway: users");
    assert.deepEqual([users?.decision, users?.include], ["allow", [{ email_domain: { domain: "example.com" } }]]);
    const bypass = cf.policies.find((p) => p.name === "airweave-edge-gateway: health checks");
    assert.equal(bypass?.decision, "bypass");
    const api = cf.apps.find((a) => a.domain === "api.example.com");
    assert.ok(api);
    assert.ok(cf.apps.find((a) => a.domain === "api.example.com/healthz"));

    const cfg = parseJsonc(readFileSync(configFile(), "utf8"));
    assert.equal(cfg.vars.AUTH_MODE, "access-jwt");
    assert.equal(cfg.vars.TEAM_DOMAIN, "https://acme.cloudflareaccess.com");
    assert.equal(cfg.vars.POLICY_AUD, api.aud);
    const deploy = runner.calls.find((c) => c.args.includes("deploy"));
    assert.equal(deploy?.secretsFile.GATEWAY_API_KEY, undefined);
  });

  it("requires someone to be allowed in", async () => {
    await assert.rejects(edge(["up", "--zone", "example.com", "--auth", "access-jwt"]), /--allow-email/);
  });

  it("removes its own gateway Access applications when switching back to api-key", async () => {
    await edge(["up", "--zone", "example.com", "--auth", "access-jwt", "--allow-email", "a@example.com", "--skip-smoke"]);
    assert.equal(cf.apps.length, 3);
    assert.equal(await edge(["up", "--auth", "api-key"]), 0, out);
    assert.deepEqual(cf.apps.map((a) => a.domain), ["airweave-origin.example.com"]);
  });
});

describe("edge.mjs status and down", () => {
  it("status passes on a healthy stack and changes nothing", async () => {
    await edge(["up", "--zone", "example.com"]);
    cf.mutations.length = 0;
    assert.equal(await edge(["status"]), 0, out);
    assert.deepEqual(cf.mutations, []);
    assert.match(out, /All checks passed/);
  });

  it("status fails when the origin answers without the service token", async () => {
    await edge(["up", "--zone", "example.com"]);
    const leaky = (/** @type {URL} */ url) =>
      url.host === "airweave-origin.example.com" ? new Response("{}", { status: 200 }) : undefined;
    assert.equal(await edge(["status"], { web: leaky }), 1);
    assert.match(out, /fail\s+origin-guard.*bypasses the Worker/);
  });

  it("down without --yes only plans; with --yes removes what up created and keeps the data", async () => {
    // A pre-existing policy someone else made must survive.
    cf.policies.push({ id: "pol-foreign", name: "someone else's", decision: "allow", include: [] });
    await edge(["up", "--zone", "example.com"]);
    cf.mutations.length = 0;

    assert.equal(await edge(["down"]), 0, out);
    assert.deepEqual(cf.mutations, []);
    assert.match(out, /delete\?\s+tunnel airweave-origin/);

    assert.equal(await edge(["down", "--yes"]), 0, out);
    assert.deepEqual([cf.tunnels.length, cf.dns.length, cf.tokens.length, cf.apps.length], [0, 0, 0, 0]);
    assert.deepEqual(cf.policies.map((p) => p.id), ["pol-foreign"]);
    assert.equal(cf.kv.length, 1);
    assert.equal(cf.d1.length, 1);
    assert.ok(runner.calls.some((c) => c.args.includes("delete") && c.args.includes("--force")));
    assert.deepEqual(Object.keys(readState().created).sort(), ["d1", "kv"]);

    assert.equal(await edge(["down", "--yes", "--delete-data"]), 0, out);
    assert.deepEqual([cf.kv.length, cf.d1.length], [0, 0]);
    assert.equal(existsSync(stateFile()), false);
  });
});

describe("edge.mjs without kubectl", () => {
  it("down explains how to skip Kubernetes instead of crashing", async () => {
    await edge(["up", "--zone", "example.com"]);
    const missing = runner.run;
    runner.run = async (cmd, args, opts) => {
      if (cmd === "kubectl") throw new Error("kubectl not found on PATH");
      return missing(cmd, args, opts);
    };
    await assert.rejects(edge(["down", "--yes"]), (err) => {
      assert.ok(err instanceof EdgeError);
      assert.match(err.message, /kubectl not found on PATH; pass --skip-k8s/);
      return true;
    });
    assert.equal(await edge(["down", "--yes", "--skip-k8s"]), 0, out);
    assert.equal(cf.tunnels.length, 0);
  });
});

describe("edge.mjs state file", () => {
  it("refuses a state file that group or others can write", { skip: process.platform === "win32" }, async () => {
    await edge(["up", "--zone", "example.com"]);
    chmodSync(stateFile(), 0o666);
    await assert.rejects(edge(["status"]), /writable by group or others \(mode 666\); run chmod 600/);
    chmodSync(stateFile(), 0o600);
    assert.equal(await edge(["status"]), 0, out);
  });
});

describe("edge.mjs options", () => {
  it("rejects hostnames outside the zone and identical hostnames", async () => {
    await assert.rejects(edge(["plan", "--zone", "example.com", "--api-host", "api.other.org"]), /not inside the zone/);
    await assert.rejects(
      edge(["plan", "--zone", "example.com", "--api-host", "x.example.com", "--origin-host", "x.example.com"]),
      /must differ/,
    );
  });

  it("explains a missing API token", async () => {
    await assert.rejects(main(["plan", "--zone", "example.com"], { env: {}, write: () => {} }), /CLOUDFLARE_API_TOKEN/);
  });

  it("prints help", async () => {
    assert.equal(await edge(["help"]), 0);
    assert.match(out, /Usage: edge\.mjs <up\|plan\|status\|down\|help>/);
  });

  it("keeps a hand-edited wrangler.jsonc intact apart from the managed values", async () => {
    const text = readFileSync(configFile(), "utf8").replace('"TYPESAFE_AUTOBLOCK": "0",', '"TYPESAFE_AUTOBLOCK": "1", // operator choice');
    writeFileSync(configFile(), text);
    assert.equal(await edge(["up", "--zone", "example.com"]), 0, out);
    assert.match(readFileSync(configFile(), "utf8"), /"TYPESAFE_AUTOBLOCK": "1", \/\/ operator choice/);
  });
});
