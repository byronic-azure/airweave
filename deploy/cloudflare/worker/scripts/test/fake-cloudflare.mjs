// @ts-check
// In-memory stand-in for the slice of the Cloudflare v4 API that edge.mjs uses,
// plus fakes for the web endpoints the smoke test probes and for the external
// commands (kubectl, wrangler). Every mutating API call is recorded.

import { existsSync, readFileSync } from "node:fs";

export const API = "https://api.cloudflare.com/client/v4";
export const ACCOUNT = "acc1";

let seq = 0;
const nextId = (/** @type {string} */ prefix) => `${prefix}-${++seq}`;

export class FakeCloudflare {
  constructor() {
    /** @type {string[]} */
    this.mutations = [];
    this.accounts = [{ id: ACCOUNT, name: "Acme" }];
    this.zones = [{ id: "zone1", name: "example.com", status: "active", account: { id: ACCOUNT } }];
    /** @type {any} */
    this.org = { auth_domain: "acme.cloudflareaccess.com", strict_service_token_auth: false };
    /** @type {any[]} */ this.tunnels = [];
    /** @type {Record<string, any>} */ this.tunnelConfigs = {};
    /** @type {any[]} */ this.dns = [];
    /** @type {any[]} */ this.tokens = [];
    /** @type {any[]} */ this.policies = [];
    /** @type {any[]} */ this.apps = [];
    /** @type {any[]} */ this.kv = [];
    /** @type {any[]} */ this.d1 = [];
    /** @type {any[]} */ this.workerDomains = [];
    /** @type {Set<string>} */ this.scripts = new Set();
    this.tunnelHealthy = false;
    /** @type {{ method: string, path: string }[]} */
    this.failOnce = [];
  }

  /**
   * @param {string} method @param {string} path @param {any} body @param {URLSearchParams} q
   * @returns {{ status: number, result?: any, errors?: { code: number, message: string }[] }}
   */
  handle(method, path, body, q) {
    const a = `/accounts/${ACCOUNT}`;
    const ok = (/** @type {any} */ result) => ({ status: 200, result });
    const notFound = () => ({ status: 404, errors: [{ code: 1000, message: "not found" }] });
    /** @param {any[]} list @param {any} item */
    const drop = (list, item) => list.splice(list.indexOf(item), 1);
    /** @type {any} */
    let m;

    if (method !== "GET") this.mutations.push(`${method} ${path}`);

    if (method === "GET" && path === "/accounts") return ok(this.accounts);
    if (method === "GET" && path === "/zones") {
      return ok(this.zones.filter((z) => z.name === q.get("name") && z.account.id === q.get("account.id")));
    }
    if (path === `${a}/access/organizations`) {
      if (!this.org) return notFound();
      if (method === "PATCH") Object.assign(this.org, body);
      return ok(this.org);
    }

    // tunnels
    if (path === `${a}/cfd_tunnel`) {
      if (method === "GET") return ok(this.tunnels.filter((t) => !q.get("name") || t.name === q.get("name")));
      const t = { id: nextId("tun"), name: body.name, config_src: body.config_src, status: "inactive", token: `tok-${seq}` };
      this.tunnels.push(t);
      return ok(t);
    }
    if ((m = path.match(/^\/accounts\/acc1\/cfd_tunnel\/([^/]+)(\/.*)?$/))) {
      const t = this.tunnels.find((x) => x.id === m[1]);
      if (!t) return notFound();
      const sub = m[2] ?? "";
      if (sub === "" && method === "GET") return ok({ ...t, status: this.tunnelHealthy ? "healthy" : "inactive" });
      if (sub === "" && method === "DELETE") return ok(drop(this.tunnels, t));
      if (sub === "/token") return ok(t.token);
      if (sub === "/connections") return ok(null);
      if (sub === "/configurations" && method === "GET") return ok({ config: this.tunnelConfigs[t.id] ?? null });
      if (sub === "/configurations" && method === "PUT") return ok({ config: (this.tunnelConfigs[t.id] = body.config) });
    }

    // DNS
    if ((m = path.match(/^\/zones\/zone1\/dns_records(?:\/([^/]+))?$/))) {
      if (!m[1] && method === "GET") return ok(this.dns.filter((r) => r.name === q.get("name")));
      if (!m[1] && method === "POST") {
        const r = { id: nextId("dns"), ...body };
        this.dns.push(r);
        return ok(r);
      }
      const r = this.dns.find((x) => x.id === m[1]);
      if (!r) return notFound();
      if (method === "PATCH") return ok(Object.assign(r, body));
      if (method === "DELETE") return ok(drop(this.dns, r));
    }

    // Access service tokens
    if (path === `${a}/access/service_tokens`) {
      if (method === "GET") return ok(this.tokens.map(({ client_secret, ...rest }) => rest));
      const t = {
        id: nextId("st"),
        name: body.name,
        client_id: `cid-${seq}.access`,
        client_secret: `secret-${seq}`,
        expires_at: "2099-01-01T00:00:00Z",
      };
      this.tokens.push(t);
      return ok(t);
    }
    if ((m = path.match(/^\/accounts\/acc1\/access\/service_tokens\/([^/]+)(\/rotate|\/refresh)?$/))) {
      const t = this.tokens.find((x) => x.id === m[1]);
      if (!t) return notFound();
      if (m[2] === "/rotate") return ok({ ...t, client_secret: (t.client_secret = `rotated-${++seq}`) });
      if (m[2] === "/refresh") return ok({ ...t, expires_at: (t.expires_at = "2099-06-01T00:00:00Z") });
      if (method === "DELETE") return ok(drop(this.tokens, t));
    }

    // Access policies and applications
    for (const [kind, list] of /** @type {[string, any[]][]} */ ([["policies", this.policies], ["apps", this.apps]])) {
      if (path === `${a}/access/${kind}`) {
        if (method === "GET") return ok(list);
        const item = { id: nextId(kind), ...body };
        if (kind === "apps") {
          item.aud = `aud-${seq}`;
          item.policies = (body.policies ?? []).map((/** @type {any} */ p) => ({
            ...p,
            ...this.policies.find((x) => x.id === p.id),
          }));
        }
        list.push(item);
        return ok(item);
      }
      if ((m = path.match(new RegExp(`^/accounts/acc1/access/${kind}/([^/]+)$`)))) {
        const item = list.find((x) => x.id === m[1]);
        if (!item) return notFound();
        if (method === "PUT") return ok(Object.assign(item, body));
        if (method === "DELETE") return ok(drop(list, item));
      }
    }

    // KV, D1, Workers
    if (path === `${a}/storage/kv/namespaces`) {
      if (method === "GET") return ok(this.kv);
      const n = { id: nextId("kv"), title: body.title };
      this.kv.push(n);
      return ok(n);
    }
    if ((m = path.match(/^\/accounts\/acc1\/storage\/kv\/namespaces\/(.+)$/)) && method === "DELETE") {
      const n = this.kv.find((x) => x.id === m[1]);
      return n ? ok(drop(this.kv, n)) : notFound();
    }
    if (path === `${a}/d1/database`) {
      if (method === "GET") return ok(this.d1.filter((d) => !q.get("name") || d.name === q.get("name")));
      const d = { uuid: nextId("d1"), name: body.name };
      this.d1.push(d);
      return ok(d);
    }
    if ((m = path.match(/^\/accounts\/acc1\/d1\/database\/(.+)$/)) && method === "DELETE") {
      const d = this.d1.find((x) => x.uuid === m[1]);
      return d ? ok(drop(this.d1, d)) : notFound();
    }
    if (path === `${a}/workers/domains`) return ok(this.workerDomains.filter((d) => d.hostname === q.get("hostname")));
    if (path === `${a}/workers/scripts`) return ok([...this.scripts].map((id) => ({ id })));

    return { status: 404, errors: [{ code: 7003, message: `fake: no route for ${method} ${path}` }] };
  }
}

/**
 * @param {FakeCloudflare} cf
 * @param {(url: URL, init: RequestInit) => Response | undefined} [web]  non-API URLs
 * @returns {typeof fetch}
 */
export function fakeFetch(cf, web) {
  return /** @type {typeof fetch} */ (
    async (input, init = {}) => {
      const url = new URL(String(input));
      if (url.href.startsWith(API)) {
        const path = url.pathname.replace("/client/v4", "");
        const method = init.method ?? "GET";
        const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
        const r = cf.handle(method, path, body, url.searchParams);
        const success = r.status < 400;
        return new Response(
          JSON.stringify(
            success
              ? { success, errors: [], result: r.result, result_info: { page: 1, total_pages: 1 } }
              : { success, errors: r.errors },
          ),
          { status: r.status, headers: { "content-type": "application/json" } },
        );
      }
      const res = web?.(url, init);
      if (!res) throw new TypeError(`fetch failed: no fake for ${url.href}`);
      return res;
    }
  );
}

/**
 * A healthy deployment as seen from outside: backend with auth on, origin behind
 * Access, Worker answering with api-key auth.
 * @param {{ apiKey?: () => string | undefined, origin?: () => { id: string, secret: string } | undefined, authDisabled?: boolean }} live
 */
export function healthyWeb(live) {
  return (/** @type {URL} */ url, /** @type {RequestInit} */ init) => {
    const h = new Headers(init.headers);
    const json = (/** @type {number} */ status, /** @type {unknown} */ body) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.host === "localhost:8001") {
      if (url.pathname === "/health/ready") return json(200, { status: "ready" });
      if (url.pathname === "/collections/count") return live.authDisabled ? json(200, 0) : json(401, {});
    }
    if (url.host === "airweave-origin.example.com") {
      const tok = live.origin?.();
      const authed = tok && h.get("CF-Access-Client-Id") === tok.id && h.get("CF-Access-Client-Secret") === tok.secret;
      return authed ? json(200, { status: "ready" }) : json(403, { error: "forbidden" });
    }
    if (url.host === "api.example.com") {
      if (url.pathname === "/healthz") return json(200, { ok: true });
      const key = live.apiKey?.();
      if (!key || h.get("X-Airweave-Gateway-Key") !== key) return json(401, { error: "missing_api_key" });
      if (url.pathname === "/evidence/verify") return json(200, { ok: true, count: 0, head: null });
      return json(200, { status: "ready" });
    }
    return undefined;
  };
}

/**
 * Records every command. kubectl answers like a fresh Docker Desktop cluster;
 * wrangler `deploy` captures the secrets file and "publishes" the Worker.
 * @param {FakeCloudflare} cf
 */
export function fakeRunner(cf) {
  /** @type {{ cmd: string, args: string[], input?: string, secretsFile?: any }[]} */
  const calls = [];
  const state = { deployment: false, secret: "" };
  /** @type {import("../lib/exec.mjs").Runner} */
  const run = async (cmd, args, opts = {}) => {
    /** @type {{ cmd: string, args: string[], input?: string, secretsFile?: any }} */
    const call = { cmd, args, input: opts.input };
    calls.push(call);
    const ok = (/** @type {string} */ stdout = "") => ({ code: 0, stdout, stderr: "" });
    if (cmd === "kubectl") {
      const a = args.join(" ");
      if (a.includes("get deployment/cloudflared")) return state.deployment ? ok("1") : { code: 1, stdout: "", stderr: "NotFound" };
      if (a.includes("apply -f -")) {
        const same = state.secret === opts.input;
        state.secret = opts.input ?? "";
        return ok(`secret/cloudflared-token ${same ? "unchanged" : "configured"}`);
      }
      if (a.includes("apply -k")) {
        const first = !state.deployment;
        state.deployment = true;
        cf.tunnelHealthy = true;
        return ok(first ? "deployment.apps/cloudflared created" : "deployment.apps/cloudflared unchanged");
      }
      if (a.includes("get namespace")) return state.deployment ? ok("airweave") : { code: 1, stdout: "", stderr: "" };
      return ok("");
    }
    // wrangler, run as: node <worker>/node_modules/wrangler/bin/wrangler.js ...
    const i = args.indexOf("--secrets-file");
    if (args.includes("deploy") && i >= 0) {
      const file = args[i + 1] ?? "";
      call.secretsFile = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
      cf.scripts.add("airweave-edge-gateway");
      if (!cf.workerDomains.some((d) => d.hostname === "api.example.com")) {
        cf.workerDomains.push({ hostname: "api.example.com", service: "airweave-edge-gateway" });
      }
    }
    if (args.includes("delete")) {
      cf.scripts.delete("airweave-edge-gateway");
      cf.workerDomains = cf.workerDomains.filter((d) => d.service !== "airweave-edge-gateway");
    }
    return ok("");
  };
  return { run, calls, state };
}
