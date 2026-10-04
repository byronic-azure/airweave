// @ts-check
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createCloudflareClient } from "../lib/cloudflare.mjs";
import { applyConfigEdits, parseJsonc } from "../lib/config.mjs";
import { mergeIngress } from "../lib/provision.mjs";
import { isSubset, normalizeHostname } from "../lib/util.mjs";

const SVC = "http://airweave-backend-host.airweave.svc.cluster.local:8001";
const rule = { hostname: "o.example.com", service: SVC, originRequest: {} };

describe("mergeIngress", () => {
  it("adds the rule before a default catch-all", () => {
    assert.deepEqual(mergeIngress([], rule), [rule, { service: "http_status:404" }]);
  });
  it("keeps other hostnames and their order, and one catch-all at the end", () => {
    const other = { hostname: "g.example.com", service: "http://g" };
    const merged = mergeIngress([{ service: "http_status:503" }, other], rule);
    assert.deepEqual(merged, [other, rule, { service: "http_status:503" }]);
  });
  it("updates the service in place and drops duplicates for the hostname", () => {
    const old = { hostname: "O.example.com", service: "http://old", originRequest: { noTLSVerify: true } };
    const merged = mergeIngress([old, { hostname: "o.example.com", service: "http://dup" }, { service: "http_status:404" }], rule);
    assert.deepEqual(merged, [{ ...old, service: SVC }, { service: "http_status:404" }]);
  });
  it("is a fixed point", () => {
    const once = mergeIngress([{ hostname: "g.example.com", service: "http://g" }], rule);
    assert.deepEqual(mergeIngress(once, rule), once);
  });
  it("leaves path-specific rules for the hostname alone", () => {
    const pathRule = { hostname: "o.example.com", path: "/metrics", service: "http_status:404" };
    assert.deepEqual(mergeIngress([pathRule], rule), [pathRule, rule, { service: "http_status:404" }]);
  });
});

describe("applyConfigEdits", () => {
  const text = `// header comment
{
  "name": "w", // trailing comment
  "vars": { "A": "1" },
  "kv_namespaces": [{ "binding": "DENYLIST", "id": "REPLACE_ME" }]
}
`;
  it("changes only differing values and keeps comments", () => {
    const { text: out, changed } = applyConfigEdits(text, [
      { path: ["vars", "A"], value: "1", label: "A" },
      { path: ["vars", "B"], value: "2", label: "B" },
      { path: ["kv_namespaces", 0, "id"], value: "kv-1", label: "kv" },
    ]);
    assert.deepEqual(changed, ["B", "kv"]);
    assert.match(out, /\/\/ header comment/);
    assert.match(out, /"name": "w", \/\/ trailing comment/);
    const data = parseJsonc(out);
    assert.deepEqual(data.vars, { A: "1", B: "2" });
    assert.equal(data.kv_namespaces[0].id, "kv-1");
    assert.deepEqual(applyConfigEdits(out, [{ path: ["vars", "B"], value: "2", label: "B" }]).changed, []);
  });
  it("reports syntax errors with a position", () => {
    assert.throws(() => parseJsonc('{\n  "a": 1,,\n}', "x.jsonc"), /x\.jsonc:2:\d+: /);
  });
});

describe("Cloudflare client", () => {
  /** @param {Array<() => Response>} answers */
  const scripted = (answers) => {
    /** @type {{ url: string, init: RequestInit }[]} */
    const seen = [];
    /** @type {typeof fetch} */
    const fetchImpl = async (input, init = {}) => {
      seen.push({ url: String(input), init });
      const next = answers.shift();
      if (!next) throw new Error("no more answers");
      return next();
    };
    return { fetchImpl, seen };
  };
  const json = (/** @type {number} */ status, /** @type {unknown} */ body, headers = {}) =>
    () => new Response(JSON.stringify(body), { status, headers });

  it("retries 429 and 5xx, honouring Retry-After", async () => {
    /** @type {number[]} */
    const waits = [];
    const { fetchImpl, seen } = scripted([
      json(429, { success: false }, { "retry-after": "2" }),
      json(502, {}),
      json(200, { success: true, result: { id: "x" } }),
    ]);
    const api = createCloudflareClient({ token: "t", fetchImpl, sleep: async (ms) => waits.push(ms) });
    assert.deepEqual(await api.get("/thing"), { id: "x" });
    assert.equal(seen.length, 3);
    assert.equal(waits[0], 2000);
  });

  it("names the missing permission on 403 and never echoes the token", async () => {
    const { fetchImpl } = scripted([json(403, { success: false, errors: [{ code: 10000, message: "Authentication error" }] })]);
    const api = createCloudflareClient({ token: "super-secret-token", fetchImpl, sleep: async () => {} });
    await assert.rejects(api.get("/accounts/a/cfd_tunnel", { need: "Cloudflare Tunnel: Edit" }), (err) => {
      assert.match(String(err), /403: 10000: Authentication error \(the API token needs "Cloudflare Tunnel: Edit"\)/);
      assert.doesNotMatch(String(err), /super-secret-token/);
      return true;
    });
  });

  it("says plainly when the token itself is rejected", async () => {
    const { fetchImpl } = scripted([json(400, { success: false, errors: [{ code: 6003, message: "Invalid request headers" }] })]);
    const api = createCloudflareClient({ token: "bogus", fetchImpl, sleep: async () => {} });
    await assert.rejects(api.get("/accounts"), /rejected CLOUDFLARE_API_TOKEN as invalid or expired/);
  });

  it("refuses writes in read-only mode before any request", async () => {
    const { fetchImpl, seen } = scripted([]);
    const api = createCloudflareClient({ token: "t", fetchImpl, readOnly: true });
    await assert.rejects(api.post("/x", { body: {} }), /read-only/);
    assert.equal(seen.length, 0);
  });

  it("follows page-based pagination", async () => {
    const { fetchImpl, seen } = scripted([
      json(200, { success: true, result: [1, 2], result_info: { page: 1, total_pages: 2 } }),
      json(200, { success: true, result: [3], result_info: { page: 2, total_pages: 2 } }),
    ]);
    const api = createCloudflareClient({ token: "t", fetchImpl });
    assert.deepEqual(await api.list("/items"), [1, 2, 3]);
    assert.match(seen[1]?.url ?? "", /page=2/);
  });
});

describe("util", () => {
  it("normalizes and validates hostnames", () => {
    assert.equal(normalizeHostname("API.Example.com.", "--x"), "api.example.com");
    for (const bad of ["example", "-a.example.com", "a..example.com", "a_b.example.com", `${"a".repeat(64)}.com`]) {
      assert.throws(() => normalizeHostname(bad, "--x"), /not a valid hostname/, bad);
    }
  });
  it("isSubset ignores server-added fields", () => {
    assert.ok(isSubset([{ service_token: { token_id: "t" } }], [{ service_token: { token_id: "t", extra: 1 } }]));
    assert.ok(!isSubset([{ service_token: { token_id: "t" } }], [{ service_token: { token_id: "u" } }]));
  });
});
