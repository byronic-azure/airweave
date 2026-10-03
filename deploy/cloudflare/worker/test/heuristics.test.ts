import { env as testEnv } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { deepDecode, hasTraversal, inspectRequest } from "../src/heuristics";
import { ORIGIN, FetchStub, gatewayRequest, makeEnv, resetStorage, run, type EchoBody } from "./helpers";

async function evidenceRows(): Promise<Array<{ verdict: string; reason: string; principal: string; path: string }>> {
  const { results } = await testEnv.EVIDENCE_DB.prepare(
    "SELECT verdict, reason, principal, path FROM evidence_events ORDER BY seq",
  ).all<{ verdict: string; reason: string; principal: string; path: string }>();
  return results;
}

describe("heuristics (unit)", () => {
  it("decodes nested percent-encoding and flags undecodable input", () => {
    expect(deepDecode("/a/%252e%252e/b")).toEqual({ value: "/a/../b", malformed: false });
    expect(deepDecode("/100%")).toEqual({ value: "/100%", malformed: true });
    expect(deepDecode("/plain")).toEqual({ value: "/plain", malformed: false });
  });

  it("detects traversal segments in every spelling", () => {
    expect(hasTraversal("/a/../b")).toBe(true);
    expect(hasTraversal("/a\\..\\b")).toBe(true);
    expect(hasTraversal("/a/..;/b")).toBe(true);
    expect(hasTraversal("/a/..b/c")).toBe(false);
    expect(hasTraversal("/a/b..")).toBe(false);
    expect(hasTraversal("/a/.../b")).toBe(false);
  });

  it("classifies hard and soft signals", () => {
    const inspect = (url: string, init: RequestInit = {}) => inspectRequest(new Request(url, init), new URL(url));
    expect(inspect("https://gw.test/items?q=1' or 1=1--")).toMatchObject({ hard: [], soft: ["sqli_signature"] });
    expect(inspect("https://gw.test/items?cmd=;cat /etc/passwd")).toMatchObject({ hard: [], soft: ["shell_signature"] });
    expect(inspect("https://gw.test/items", { headers: { "User-Agent": "sqlmap/1.7" } }).soft).toEqual([
      "scanner_user_agent",
    ]);
    expect(inspect("https://gw.test/items", { method: "PROPFIND" }).hard).toEqual(["method_not_allowed"]);
    expect(inspect("https://gw.test/a/%252e%252e/b").hard).toEqual(["path_traversal"]);
    expect(inspect("https://gw.test/a%00.json").hard).toEqual(["null_byte"]);
    expect(inspect("https://gw.test/a/..../b").soft).toEqual(["dot_segment_variant"]);
    expect(inspect(`https://gw.test/items?q=${"a".repeat(5000)}`).soft).toEqual(["long_url"]);
    expect(inspect("https://gw.test/collections/my-collection/search?query=hello%20world")).toEqual({
      hard: [],
      soft: [],
    });
  });
});

describe("heuristics (gateway)", () => {
  let stub: FetchStub;
  beforeEach(async () => {
    await resetStorage();
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  const env = () => makeEnv({ EVIDENCE_DB: testEnv.EVIDENCE_DB });

  it.each([
    ["double-encoded traversal", "/api/%252e%252e/%252e%252e/etc/passwd", "path_traversal"],
    ["semicolon traversal", "/api/..;/admin", "path_traversal"],
    ["null byte", "/api/file%00.json", "null_byte"],
  ])("blocks %s with 400 before authentication and records evidence", async (_name, path, reason) => {
    const res = await run(gatewayRequest(path, { apiKey: null }), env());
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string; reasons: string[] };
    expect(body.error).toBe("bad_request");
    expect(body.reasons).toContain(reason);
    expect(stub.calls).toHaveLength(0);

    const rows = await evidenceRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ verdict: "blocked", principal: "unauthenticated" });
    expect(rows[0]?.reason).toContain(reason);
  });

  it("blocks methods outside the allowlist", async () => {
    const res = await run(gatewayRequest("/collections", { method: "PROPFIND" }), env());
    expect(res.status).toBe(400);
    expect(((await res.json()) as { reasons: string[] }).reasons).toEqual(["method_not_allowed"]);
    expect(stub.calls).toHaveLength(0);
  });

  it("forwards soft-flagged requests, tags them upstream only, and records evidence", async () => {
    const res = await run(gatewayRequest("/collections?q=1%27%20or%201%3D1--"), env());
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Airweave-Suspicion")).toBeNull();
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["x-airweave-suspicion"]).toBe("sqli_signature");

    const rows = await evidenceRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ verdict: "flagged", reason: "soft:sqli_signature" });
    expect(rows[0]?.principal).toMatch(/^apikey:/);
    expect(rows[0]?.path).toBe("/collections?q=1%27%20or%201%3D1--");
  });

  it("ignores a client-supplied suspicion header", async () => {
    const res = await run(gatewayRequest("/collections", { headers: { "X-Airweave-Suspicion": "nothing" } }), env());
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["x-airweave-suspicion"]).toBeUndefined();
    expect(await evidenceRows()).toHaveLength(0);
  });

  it("records nothing for ordinary traffic", async () => {
    await run(gatewayRequest("/collections/abc/search?query=hello&limit=5"), env());
    await run(gatewayRequest("/source-connections", { method: "POST", body: "{}" }), env());
    expect(await evidenceRows()).toHaveLength(0);
  });
});
