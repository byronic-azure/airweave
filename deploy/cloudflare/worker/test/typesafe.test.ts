import { env as testEnv } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TYPESAFE_ENDPOINT, TYPESAFE_MODEL } from "../src/typesafe";
import { sha256Hex } from "../src/util";
import {
  API_KEY,
  FetchStub,
  gatewayRequest,
  makeAccessIssuer,
  makeEnv,
  ORIGIN,
  POLICY_AUD,
  resetStorage,
  run,
  serveJwks,
  SERVICE_TOKEN_SECRET,
  TEAM_DOMAIN,
} from "./helpers";

const TYPESAFE_ORIGIN = new URL(TYPESAFE_ENDPOINT).origin;
const TYPESAFE_KEY = "ts-secret-key-abcdef";
const SECRET_QUERY_VALUE = "1' or 1=1--";
const FLAGGED_PATH = `/collections/abc/search?q=${encodeURIComponent(SECRET_QUERY_VALUE)}&limit=5`;
const REQUEST_BODY = '{"query":"body-text-that-must-not-leak"}';

interface TypeSafeCall {
  headers: Headers;
  body: {
    state: Record<string, unknown>;
    model: string;
    questions: Record<string, { type: string; instructions: string; criteria: Record<string, string | null> }>;
  };
  raw: string;
}

function typeSafeAnswer(isProbe: number, choice = "injection") {
  return {
    model: TYPESAFE_MODEL,
    answers: {
      is_probe: { noul: isProbe },
      category: { choice, probabilities: { benign: 1 - isProbe, [choice]: isProbe }, confidence: 0.9 },
    },
    usage: { input_tokens: 10, output_tokens: 2 },
  };
}

async function judgementRows(): Promise<Array<{ verdict: string; judgement_json: string | null }>> {
  const { results } = await testEnv.EVIDENCE_DB.prepare(
    "SELECT verdict, judgement_json FROM evidence_events ORDER BY seq",
  ).all<{ verdict: string; judgement_json: string | null }>();
  return results;
}

describe("TypeSafe verify-and-escalate", () => {
  let stub: FetchStub;
  let calls: TypeSafeCall[];

  function serveTypeSafe(reply: () => Response): void {
    stub.on(TYPESAFE_ORIGIN, async (_request, captured) => {
      calls.push({ headers: captured.headers, body: JSON.parse(captured.body ?? "{}"), raw: captured.body ?? "" });
      return reply();
    });
  }

  beforeEach(async () => {
    await resetStorage();
    calls = [];
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  const baseEnv = () => makeEnv({ EVIDENCE_DB: testEnv.EVIDENCE_DB, TYPESAFE_API_KEY: TYPESAFE_KEY });

  it("sends a sanitised state with the documented questions and stores the answers", async () => {
    serveTypeSafe(() => Response.json(typeSafeAnswer(0.3, "benign")));
    const res = await run(
      gatewayRequest(FLAGGED_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "airweave-sdk/1.0" },
        body: REQUEST_BODY,
      }),
      baseEnv(),
    );
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
    const call = calls[0] as TypeSafeCall;

    expect(call.headers.get("Authorization")).toBe(`Bearer ${TYPESAFE_KEY}`);
    expect(call.headers.get("Content-Type")).toBe("application/json");
    expect(call.body.model).toBe("jev-latest");
    expect(call.body.state).toEqual({
      method: "POST",
      path: "/collections/abc/search",
      query_keys: ["q", "limit"],
      user_agent: "airweave-sdk/1.0",
      flagged_signals: ["sqli_signature"],
      principal_kind: "api-key",
      status_returned: 200,
    });
    expect(call.body.questions.is_probe).toMatchObject({ type: "noul", criteria: { true: expect.any(String), false: expect.any(String) } });
    expect(call.body.questions.category).toMatchObject({ type: "choice" });
    expect(Object.keys(call.body.questions.category?.criteria ?? {})).toEqual([
      "benign",
      "traversal",
      "injection",
      "enumeration",
      "credential_abuse",
      "other",
    ]);

    // Nothing sensitive crosses the wire: no query values, body, keys or tokens.
    for (const secret of [SECRET_QUERY_VALUE, "1=1", "body-text-that-must-not-leak", API_KEY, SERVICE_TOKEN_SECRET]) {
      expect(call.raw).not.toContain(secret);
    }

    const rows = await judgementRows();
    expect(rows).toHaveLength(1);
    const judgement = JSON.parse(rows[0]?.judgement_json ?? "null");
    expect(judgement).toMatchObject({
      model: "jev-latest",
      answers: { is_probe: { noul: 0.3 }, category: { choice: "benign", confidence: 0.9 } },
      autoblock: { applied: false, threshold: 0.95 },
    });
  });

  it("is never called for ordinary traffic", async () => {
    serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
    const res = await run(gatewayRequest("/collections/abc/search?query=hello", { method: "POST", body: "{}" }), baseEnv());
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(0);
    expect(await judgementRows()).toHaveLength(0);
  });

  it("is not called without TYPESAFE_API_KEY, and evidence still lands", async () => {
    serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
    await run(gatewayRequest(FLAGGED_PATH), makeEnv({ EVIDENCE_DB: testEnv.EVIDENCE_DB }));
    expect(calls).toHaveLength(0);
    const rows = await judgementRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.judgement_json).toBeNull();
  });

  it("is also consulted for hard-blocked requests with the anonymous principal", async () => {
    serveTypeSafe(() => Response.json(typeSafeAnswer(0.99, "traversal")));
    const res = await run(gatewayRequest("/a/%252e%252e/etc/passwd", { apiKey: null }), baseEnv());
    expect(res.status).toBe(400);
    expect(calls[0]?.body.state).toMatchObject({
      principal_kind: "anonymous",
      status_returned: 400,
      flagged_signals: expect.arrayContaining(["path_traversal"]),
    });
  });

  it("records the failure and keeps serving when TypeSafe is down", async () => {
    serveTypeSafe(() => new Response("nope", { status: 500 }));
    const res = await run(gatewayRequest(FLAGGED_PATH), baseEnv());
    expect(res.status).toBe(200);
    const rows = await judgementRows();
    expect(JSON.parse(rows[0]?.judgement_json ?? "null")).toMatchObject({ error: "typesafe_http_500" });
  });

  describe("autoblock", () => {
    const principalKey = async () => `apikey:${await sha256Hex(API_KEY)}`;
    // One issuer for the Access-JWT cases: jose caches the remote JWKS per isolate.
    let issuer: Awaited<ReturnType<typeof makeAccessIssuer>>;
    beforeAll(async () => {
      issuer = await makeAccessIssuer();
    });

    it("stays label-only by default even for a certain probe", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      await run(gatewayRequest(FLAGGED_PATH), makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST }));
      expect(await testEnv.DENYLIST.get(await principalKey())).toBeNull();
      const res = await run(gatewayRequest("/collections"), makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST }));
      expect(res.status).toBe(200);
    });

    it("denies the principal when enabled, bound and above the threshold", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      const env = makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST, TYPESAFE_AUTOBLOCK: "1" });
      const first = await run(gatewayRequest(FLAGGED_PATH), env);
      expect(first.status).toBe(200); // the triggering request itself is served; the block applies afterwards

      const entry = await testEnv.DENYLIST.get(await principalKey());
      expect(entry).not.toBeNull();
      expect(JSON.parse(entry as string)).toMatchObject({ is_probe: 0.99 });
      expect(JSON.parse((await judgementRows())[0]?.judgement_json ?? "null")).toMatchObject({
        autoblock: { requested: true, applied: true, threshold: 0.95 },
      });

      const originCallsBefore = stub.callsTo(ORIGIN).length;
      const second = await run(gatewayRequest("/collections"), env);
      expect(second.status).toBe(403);
      expect(((await second.json()) as { error: string }).error).toBe("principal_denied");
      expect(stub.callsTo(ORIGIN)).toHaveLength(originCallsBefore);
    });

    it("never denylists an Access-JWT principal on soft-only signals from a proxied request", async () => {
      // A cross-site GET carries the victim's Access cookie, so soft signals under
      // an Access identity can be planted by a third party: label-only, no block.
      serveJwks(stub, issuer);
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      const env = makeEnv({
        ...baseEnv(),
        DENYLIST: testEnv.DENYLIST,
        TYPESAFE_AUTOBLOCK: "1",
        AUTH_MODE: "access-jwt",
        TEAM_DOMAIN,
        POLICY_AUD,
        GATEWAY_API_KEY: undefined,
      });
      const token = await issuer.sign({ email: "victim@example.test", sub: "user-1" });
      const res = await run(
        gatewayRequest(FLAGGED_PATH, { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }),
        env,
      );
      expect(res.status).toBe(200);
      expect((await testEnv.DENYLIST.list()).keys).toHaveLength(0);
      expect(JSON.parse((await judgementRows())[0]?.judgement_json ?? "null")).toMatchObject({
        autoblock: { requested: false, applied: false },
      });
      const again = await run(
        gatewayRequest("/collections", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }),
        env,
      );
      expect(again.status).toBe(200);
    });

    it("never denylists an Access-JWT principal that was rate limited either", async () => {
      // A page of cross-site <img> loads can trip the limit under the victim's cookie.
      serveJwks(stub, issuer);
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99, "enumeration")));
      const limiter = { async limit() { return { success: false }; } };
      const env = makeEnv({
        ...baseEnv(),
        DENYLIST: testEnv.DENYLIST,
        TYPESAFE_AUTOBLOCK: "1",
        RATE_LIMITER: limiter,
        AUTH_MODE: "access-jwt",
        TEAM_DOMAIN,
        POLICY_AUD,
        GATEWAY_API_KEY: undefined,
      });
      const token = await issuer.sign({ email: "victim@example.test", sub: "user-1" });
      const res = await run(
        gatewayRequest("/collections", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }),
        env,
      );
      expect(res.status).toBe(429);
      expect((await testEnv.DENYLIST.list()).keys).toHaveLength(0);
      const rows = await judgementRows();
      expect(rows[0]?.verdict).toBe("rate_limited");
      expect(JSON.parse(rows[0]?.judgement_json ?? "null")).toMatchObject({
        autoblock: { requested: false, applied: false },
      });
    });

    it("still denylists a rate-limited api-key principal", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99, "enumeration")));
      const limiter = { async limit() { return { success: false }; } };
      const env = makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST, TYPESAFE_AUTOBLOCK: "1", RATE_LIMITER: limiter });
      expect((await run(gatewayRequest("/collections"), env)).status).toBe(429);
      expect(await testEnv.DENYLIST.get(await principalKey())).not.toBeNull();
    });

    it("still denylists an Access service token (no email claim), which a browser cannot be made to send", async () => {
      const issuer = await makeAccessIssuer();
      serveJwks(stub, issuer);
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      const env = makeEnv({
        ...baseEnv(),
        DENYLIST: testEnv.DENYLIST,
        TYPESAFE_AUTOBLOCK: "1",
        AUTH_MODE: "access-jwt",
        TEAM_DOMAIN,
        POLICY_AUD,
        GATEWAY_API_KEY: undefined,
      });
      const token = await issuer.sign({ common_name: "ci-runner.access" });
      const res = await run(
        gatewayRequest(FLAGGED_PATH, { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }),
        env,
      );
      expect(res.status).toBe(200);
      expect(await testEnv.DENYLIST.get("jwt:ci-runner.access")).not.toBeNull();
    });

    it("records applied: false when the DENYLIST write fails", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      const puts: string[] = [];
      const flaky = {
        get: async () => null,
        put: async (key: string) => {
          puts.push(key);
          throw new Error("KV PUT failed: 429 Too Many Requests");
        },
      } as unknown as KVNamespace;
      const env = makeEnv({ ...baseEnv(), DENYLIST: flaky, TYPESAFE_AUTOBLOCK: "1" });
      const error = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        expect((await run(gatewayRequest(FLAGGED_PATH), env)).status).toBe(200);
        expect(error.mock.calls.map((c) => String(c[0])).some((l) => l.includes('"autoblock_failed"'))).toBe(true);
      } finally {
        error.mockRestore();
      }
      expect(puts).toEqual([await principalKey()]);
      // The hash-chained row says what happened, not what was intended.
      expect(JSON.parse((await judgementRows())[0]?.judgement_json ?? "null")).toMatchObject({
        answers: { is_probe: { noul: 0.99 } },
        autoblock: { requested: true, applied: false, threshold: 0.95 },
      });
      expect((await run(gatewayRequest("/collections"), env)).status).toBe(200); // still not denied
    });

    it("does nothing below the threshold", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.5)));
      await run(gatewayRequest(FLAGGED_PATH), makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST, TYPESAFE_AUTOBLOCK: "1" }));
      expect(await testEnv.DENYLIST.get(await principalKey())).toBeNull();
    });

    it("honours TYPESAFE_BLOCK_THRESHOLD from env", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.5)));
      await run(
        gatewayRequest(FLAGGED_PATH),
        makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST, TYPESAFE_AUTOBLOCK: "1", TYPESAFE_BLOCK_THRESHOLD: "0.4" }),
      );
      expect(await testEnv.DENYLIST.get(await principalKey())).not.toBeNull();
    });

    it("does nothing without a DENYLIST binding", async () => {
      serveTypeSafe(() => Response.json(typeSafeAnswer(0.99)));
      const env = makeEnv({ ...baseEnv(), TYPESAFE_AUTOBLOCK: "1" });
      await run(gatewayRequest(FLAGGED_PATH), env);
      expect(JSON.parse((await judgementRows())[0]?.judgement_json ?? "null")).toMatchObject({
        autoblock: { requested: false, applied: false },
      });
      expect((await run(gatewayRequest("/collections"), env)).status).toBe(200);
    });

    it("ignores a judgement without a usable probability", async () => {
      serveTypeSafe(() => Response.json({ model: TYPESAFE_MODEL, answers: {} }));
      await run(gatewayRequest(FLAGGED_PATH), makeEnv({ ...baseEnv(), DENYLIST: testEnv.DENYLIST, TYPESAFE_AUTOBLOCK: "1" }));
      expect(await testEnv.DENYLIST.get(await principalKey())).toBeNull();
    });
  });
});
