// @ts-check
// End-to-end checks of the live path, from this machine:
//   origin-guard   the tunnel hostname refuses a request without the service token
//   origin-token   ...and lets the Worker's token through to the backend
//   gateway        GET /healthz on the Worker's hostname
//   gateway-auth   the Worker rejects an unauthenticated request
//   end-to-end     api-key mode: an authenticated request reaches the backend
//   evidence       api-key mode: /evidence/verify reports an intact chain
// New hostnames need a moment (DNS, the Custom Domain's certificate), so
// connection errors and 52x answers are retried for a while.

import { sleep as realSleep } from "./util.mjs";

/**
 * @typedef {object} SmokeTarget
 * @property {string} apiHost
 * @property {string} originHost
 * @property {"api-key" | "access-jwt"} authMode
 * @property {string} [apiKey]
 * @property {{ clientId: string, clientSecret: string }} [originToken]
 */

/**
 * @typedef {object} SmokeDeps
 * @property {typeof fetch} [fetchImpl]
 * @property {(ms: number) => Promise<unknown>} [sleep]
 * @property {import("./log.mjs").Logger} log
 * @property {number} [attempts]   per check, for transient failures (default 36, 5 s apart)
 */

/** @typedef {{ status: number, body: string, setCookie: string }} Probe */

const TRANSIENT = new Set([0, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530]);

/**
 * @param {SmokeDeps} deps
 * @param {SmokeTarget} t
 * @returns {Promise<boolean>} true when every check passed
 */
export async function smokeTest(deps, t) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const pause = deps.sleep ?? realSleep;
  const attempts = deps.attempts ?? 36;
  let failed = 0;

  /**
   * @param {string} url
   * @param {Record<string, string>} [headers]
   * @param {(p: Probe) => boolean} [settled]  stop retrying once this holds
   * @returns {Promise<Probe>}
   */
  async function probe(url, headers = {}, settled = (p) => !TRANSIENT.has(p.status)) {
    /** @type {Probe} */
    let last = { status: 0, body: "", setCookie: "" };
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await fetchImpl(url, { headers, redirect: "manual", signal: AbortSignal.timeout(15000) });
        last = { status: res.status, body: (await res.text()).slice(0, 300), setCookie: res.headers.get("set-cookie") ?? "" };
      } catch (err) {
        last = { status: 0, body: err instanceof Error ? err.message : String(err), setCookie: "" };
      }
      if (settled(last)) return last;
      if (i + 1 < attempts) await pause(5000);
    }
    return last;
  }
  /** @param {string} name @param {string} msg */
  const pass = (name, msg) => deps.log.ok(`${name.padEnd(13)}${msg}`);
  /** @param {string} name @param {string} msg */
  const fail = (name, msg) => {
    failed++;
    deps.log.fail(`${name.padEnd(13)}${msg}`);
  };
  /** @param {Probe} p */
  const show = (p) => (p.status === 0 ? `unreachable (${p.body})` : `${p.status} ${p.body.replace(/\s+/g, " ").slice(0, 120)}`);

  const origin = `https://${t.originHost}/health/ready`;
  const guard = await probe(origin);
  if ([302, 401, 403].includes(guard.status)) pass("origin-guard", `${origin} -> ${guard.status} without the service token`);
  else if (guard.status === 200) fail("origin-guard", `${origin} -> 200 WITHOUT a service token: the origin bypasses the Worker`);
  else fail("origin-guard", `${origin} -> ${show(guard)} (expected 302/401/403 from Access)`);

  if (t.originToken) {
    const withToken = await probe(origin, {
      "CF-Access-Client-Id": t.originToken.clientId,
      "CF-Access-Client-Secret": t.originToken.clientSecret,
    });
    if (withToken.status === 200) {
      pass("origin-token", `${origin} -> 200 with the Worker's service token (tunnel and backend are up)`);
      if (/CF_Authorization=/i.test(withToken.setCookie)) {
        deps.log.warn("origin-token Access answered with a CF_Authorization cookie; re-run with --strict-service-tokens");
      }
    } else if ([401, 403].includes(withToken.status)) {
      fail("origin-token", `${origin} -> ${withToken.status} with the service token: it is not in the origin policy`);
    } else if (withToken.status === 502) {
      fail("origin-token", `${origin} -> 502: the tunnel is up but cannot reach the backend (docker compose up? port 8001?)`);
    } else {
      fail("origin-token", `${origin} -> ${show(withToken)}`);
    }
  }

  const health = `https://${t.apiHost}/healthz`;
  const h = await probe(health);
  if (h.status === 200 && /"ok"\s*:\s*true/.test(h.body)) pass("gateway", `${health} -> 200 ${h.body.trim()}`);
  else fail("gateway", `${health} -> ${show(h)}`);

  const api = `https://${t.apiHost}/health/ready`;
  const anon = await probe(api);
  if ([302, 401, 403].includes(anon.status)) {
    const who = t.authMode === "access-jwt" ? "Access" : "the Worker";
    pass("gateway-auth", `${api} -> ${anon.status} without credentials (${who} is enforcing)`);
  } else {
    fail("gateway-auth", `${api} -> ${show(anon)} without credentials (expected 401/403)`);
  }

  if (t.authMode === "api-key" && t.apiKey) {
    const key = { "X-Airweave-Gateway-Key": t.apiKey };
    const e2e = await probe(api, key);
    if (e2e.status === 200) pass("end-to-end", `${api} -> 200 through Worker, tunnel and backend`);
    else fail("end-to-end", `${api} -> ${show(e2e)} with the gateway key`);
    const ev = await probe(`https://${t.apiHost}/evidence/verify`, key);
    if (ev.status === 200 && /"ok"\s*:\s*true/.test(ev.body)) pass("evidence", `/evidence/verify -> ${ev.body.trim()}`);
    else fail("evidence", `/evidence/verify -> ${show(ev)}`);
  } else if (t.authMode === "access-jwt") {
    deps.log.skip(`end-to-end   access-jwt: sign in at https://${t.apiHost}/health/ready, or: cloudflared access curl ${api}`);
  }
  return failed === 0;
}
