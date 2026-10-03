// Escalation budget: rejected requests (400 from the hard rules, 401/403 from
// authentication or the denylist) are judged and recorded only while their
// principal key is within the rate limit and not denylisted, so an anonymous
// flood cannot run up TypeSafe calls and D1 appends. Soft-flagged requests that
// are rejected still get an evidence row inside that budget.
import { env as testEnv } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import type { RateLimitBinding } from "../src/env";
import { TYPESAFE_ENDPOINT, TYPESAFE_MODEL } from "../src/typesafe";
import { sha256Hex } from "../src/util";
import { API_KEY, CLIENT_IP, ORIGIN, FetchStub, gatewayRequest, makeEnv, resetStorage, run } from "./helpers";

const TYPESAFE_ORIGIN = new URL(TYPESAFE_ENDPOINT).origin;
const TRAVERSAL = "/a/%252e%252e/etc/passwd";
const SQLMAP_PATH = "/collections?id=1%27%20or%201%3D1--";
const SQLMAP_HEADERS = { "User-Agent": "sqlmap/1.7" };
const ANON_KEY = `ip:${CLIENT_IP}`;

interface Row {
  verdict: string;
  reason: string;
  principal: string;
  client_ip: string;
}

async function evidenceRows(): Promise<Row[]> {
  const { results } = await testEnv.EVIDENCE_DB.prepare(
    "SELECT verdict, reason, principal, client_ip FROM evidence_events ORDER BY seq",
  ).all<Row>();
  return results;
}

function fakeLimiter(success: boolean): RateLimitBinding & { keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    async limit({ key }) {
      keys.push(key);
      return { success };
    },
  };
}

describe("escalation budget and pre-auth evidence", () => {
  let stub: FetchStub;
  let typesafeCalls: number;
  let warn: MockInstance<typeof console.warn>;

  beforeEach(async () => {
    await resetStorage();
    typesafeCalls = 0;
    stub = new FetchStub().echo(ORIGIN).on(TYPESAFE_ORIGIN, () => {
      typesafeCalls++;
      return Response.json({ model: TYPESAFE_MODEL, answers: { is_probe: { noul: 0.99 } } });
    });
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    warn.mockRestore();
    stub.restore();
  });

  const suppressedLogs = () =>
    warn.mock.calls.map((c) => String(c[0])).filter((l) => l.includes('"escalation_suppressed"'));

  const baseEnv = (overrides = {}) =>
    makeEnv({ EVIDENCE_DB: testEnv.EVIDENCE_DB, DENYLIST: testEnv.DENYLIST, TYPESAFE_API_KEY: "ts-key", ...overrides });

  describe("hard-blocked requests", () => {
    it("are escalated within the anonymous budget, keyed by client IP", async () => {
      const limiter = fakeLimiter(true);
      const res = await run(gatewayRequest(TRAVERSAL, { apiKey: null }), baseEnv({ RATE_LIMITER: limiter }));
      expect(res.status).toBe(400);
      expect(limiter.keys).toEqual([ANON_KEY]);
      expect(typesafeCalls).toBe(1);
      expect(await evidenceRows()).toMatchObject([{ verdict: "blocked", principal: "unauthenticated" }]);
    });

    it("stop being judged and recorded once the IP is over its rate limit", async () => {
      const limiter = fakeLimiter(false);
      const env = baseEnv({ RATE_LIMITER: limiter });
      for (let i = 0; i < 5; i++) {
        const res = await run(gatewayRequest(`${TRAVERSAL}${i}`, { apiKey: null }), env);
        expect(res.status).toBe(400); // the rejection itself is unchanged
      }
      expect(limiter.keys).toEqual(Array(5).fill(ANON_KEY));
      expect(typesafeCalls).toBe(0);
      expect(await evidenceRows()).toHaveLength(0);
      expect(suppressedLogs()).toHaveLength(5);
      expect(JSON.parse(suppressedLogs()[0] as string)).toMatchObject({ principal_key: ANON_KEY, why: "rate_limited" });
      expect(stub.callsTo(ORIGIN)).toHaveLength(0);
    });

    it("stop being judged and recorded once autoblock has denylisted the IP", async () => {
      const env = baseEnv({ TYPESAFE_AUTOBLOCK: "1", RATE_LIMITER: fakeLimiter(true) });
      expect((await run(gatewayRequest(TRAVERSAL, { apiKey: null }), env)).status).toBe(400);
      expect(await testEnv.DENYLIST.get(ANON_KEY)).not.toBeNull(); // the first probe got the IP denylisted
      expect(typesafeCalls).toBe(1);

      expect((await run(gatewayRequest(`${TRAVERSAL}2`, { apiKey: null }), env)).status).toBe(400);
      expect(typesafeCalls).toBe(1);
      expect(await evidenceRows()).toHaveLength(1);
      expect(JSON.parse(suppressedLogs()[0] as string)).toMatchObject({ principal_key: ANON_KEY, why: "principal_denied" });
    });

    it("are always escalated when neither binding exists", async () => {
      const env = baseEnv({ DENYLIST: undefined });
      for (let i = 0; i < 3; i++) await run(gatewayRequest(`${TRAVERSAL}${i}`, { apiKey: null }), env);
      expect(typesafeCalls).toBe(3);
      expect(await evidenceRows()).toHaveLength(3);
    });
  });

  describe("soft-flagged requests that are rejected", () => {
    it("get an evidence row with the anonymous principal when no credential is sent", async () => {
      const res = await run(gatewayRequest(SQLMAP_PATH, { apiKey: null, headers: SQLMAP_HEADERS }), baseEnv());
      expect(res.status).toBe(401);
      expect(stub.callsTo(ORIGIN)).toHaveLength(0);
      expect(await evidenceRows()).toEqual([
        {
          verdict: "flagged",
          reason: "soft:sqli_signature,scanner_user_agent",
          principal: "unauthenticated",
          client_ip: CLIENT_IP,
        },
      ]);
      expect(typesafeCalls).toBe(1);
      expect(stub.callsTo(TYPESAFE_ORIGIN)[0]?.body).toContain('"status_returned":401');
    });

    it("get an evidence row when the credential is rejected", async () => {
      const res = await run(gatewayRequest(SQLMAP_PATH, { apiKey: "wrong-key", headers: SQLMAP_HEADERS }), baseEnv());
      expect(res.status).toBe(403);
      expect(await evidenceRows()).toMatchObject([{ verdict: "flagged", principal: "unauthenticated" }]);
    });

    it("get an evidence row under the authenticated principal when it is denylisted", async () => {
      const key = `apikey:${await sha256Hex(API_KEY)}`;
      await testEnv.DENYLIST.put(key, "{}", { expirationTtl: 60 });
      const limiter = fakeLimiter(true);
      const res = await run(gatewayRequest(SQLMAP_PATH, { headers: SQLMAP_HEADERS }), baseEnv({ RATE_LIMITER: limiter }));
      expect(res.status).toBe(403);
      expect(((await res.json()) as { error: string }).error).toBe("principal_denied");
      expect(limiter.keys).toEqual([key]); // bounded by the principal's own bucket
      expect(await evidenceRows()).toMatchObject([{ verdict: "flagged", principal: expect.stringMatching(/^apikey:/) }]);
      expect(stub.callsTo(TYPESAFE_ORIGIN)[0]?.body).toContain('"status_returned":403');
    });

    it("are not escalated when the anonymous budget is exhausted", async () => {
      const env = baseEnv({ RATE_LIMITER: fakeLimiter(false) });
      const res = await run(gatewayRequest(SQLMAP_PATH, { apiKey: null, headers: SQLMAP_HEADERS }), env);
      expect(res.status).toBe(401);
      expect(typesafeCalls).toBe(0);
      expect(await evidenceRows()).toHaveLength(0);
      expect(suppressedLogs()).toHaveLength(1);
    });

    it("leave no row and consult nothing when a clean request merely lacks credentials", async () => {
      const limiter = fakeLimiter(false);
      const res = await run(gatewayRequest("/collections", { apiKey: null }), baseEnv({ RATE_LIMITER: limiter }));
      expect(res.status).toBe(401);
      expect(limiter.keys).toHaveLength(0);
      expect(await evidenceRows()).toHaveLength(0);
      expect(typesafeCalls).toBe(0);
    });
  });
});
