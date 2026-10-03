import { env as testEnv } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { RateLimitBinding } from "../src/env";
import { sha256Hex } from "../src/util";
import {
  API_KEY,
  ORIGIN,
  POLICY_AUD,
  TEAM_DOMAIN,
  FetchStub,
  gatewayRequest,
  makeAccessIssuer,
  makeEnv,
  resetStorage,
  run,
  serveJwks,
  type AccessIssuer,
} from "./helpers";

/** A rate limiter that records keys and answers with a fixed verdict. */
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

describe("rate limiting", () => {
  let stub: FetchStub;
  let issuer: AccessIssuer;
  beforeAll(async () => {
    issuer = await makeAccessIssuer();
  });
  beforeEach(async () => {
    await resetStorage();
    stub = new FetchStub().echo(ORIGIN);
    serveJwks(stub, issuer);
  });
  afterEach(() => stub.restore());

  it("answers 429 with Retry-After and records evidence when the binding says no", async () => {
    const limiter = fakeLimiter(false);
    const env = makeEnv({ RATE_LIMITER: limiter, EVIDENCE_DB: testEnv.EVIDENCE_DB });
    const res = await run(gatewayRequest("/collections"), env);
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
    expect(res.headers.get("X-Airweave-RateLimit")).toBe("exceeded");
    const body = (await res.json()) as { error: string; retry_after: number };
    expect(body.error).toBe("rate_limited");
    expect(body.retry_after).toBe(60);
    expect(stub.callsTo(ORIGIN)).toHaveLength(0);

    const row = await testEnv.EVIDENCE_DB.prepare("SELECT verdict, reason, principal FROM evidence_events").first<{
      verdict: string;
      reason: string;
      principal: string;
    }>();
    expect(row).toMatchObject({ verdict: "rate_limited", reason: "rate_limit_exceeded" });
    expect(row?.principal).toMatch(/^apikey:[0-9a-f]{16}$/);
  });

  it("keys api-key callers by the SHA-256 of the key, never the key itself", async () => {
    const limiter = fakeLimiter(true);
    const res = await run(gatewayRequest("/collections"), makeEnv({ RATE_LIMITER: limiter }));
    expect(res.status).toBe(200);
    expect(limiter.keys).toEqual([`apikey:${await sha256Hex(API_KEY)}`]);
    expect(limiter.keys[0]).not.toContain(API_KEY);
    expect(res.headers.get("X-Airweave-RateLimit")).toBeNull();
  });

  it("keys Access callers by their email", async () => {
    const limiter = fakeLimiter(true);
    const token = await issuer.sign({ email: "alice@example.test", sub: "user-1" });
    const env = makeEnv({ AUTH_MODE: "access-jwt", TEAM_DOMAIN, POLICY_AUD, RATE_LIMITER: limiter });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env);
    expect(res.status).toBe(200);
    expect(limiter.keys).toEqual(["jwt:alice@example.test"]);
  });

  it("keys unauthenticated dev-mode callers by client IP", async () => {
    const limiter = fakeLimiter(true);
    const env = makeEnv({ AUTH_MODE: "off", ALLOW_INSECURE_DEV: "1", RATE_LIMITER: limiter });
    await run(gatewayRequest("/x", { apiKey: null }), env);
    expect(limiter.keys).toEqual(["ip:203.0.113.7"]);
  });

  it("uses RATE_LIMIT_PERIOD_SECONDS for the Retry-After hint", async () => {
    const res = await run(gatewayRequest("/x"), makeEnv({ RATE_LIMITER: fakeLimiter(false), RATE_LIMIT_PERIOD_SECONDS: "10" }));
    expect(res.headers.get("Retry-After")).toBe("10");
  });

  it("skips limiting and labels the response when no binding is bound", async () => {
    const res = await run(gatewayRequest("/collections"), makeEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Airweave-RateLimit")).toBe("disabled");
  });

  it("fails open when the binding throws", async () => {
    const broken: RateLimitBinding = {
      async limit() {
        throw new Error("ratelimit backend down");
      },
    };
    const res = await run(gatewayRequest("/collections"), makeEnv({ RATE_LIMITER: broken }));
    expect(res.status).toBe(200);
  });

  it("does not consult the limiter for unauthenticated requests", async () => {
    const limiter = fakeLimiter(false);
    const res = await run(gatewayRequest("/collections", { apiKey: null }), makeEnv({ RATE_LIMITER: limiter }));
    expect(res.status).toBe(401);
    expect(limiter.keys).toHaveLength(0);
  });
});
