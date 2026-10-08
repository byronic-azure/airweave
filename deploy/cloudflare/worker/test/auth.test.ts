import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  API_KEY,
  ORIGIN,
  POLICY_AUD,
  TEAM_DOMAIN,
  FetchStub,
  gatewayRequest,
  makeAccessIssuer,
  makeEnv,
  run,
  serveJwks,
  type AccessIssuer,
  type EchoBody,
} from "./helpers";

describe("AUTH_MODE=access-jwt", () => {
  let issuer: AccessIssuer;
  let stub: FetchStub;
  const env = () => makeEnv({ AUTH_MODE: "access-jwt", TEAM_DOMAIN, POLICY_AUD, GATEWAY_API_KEY: undefined });

  beforeAll(async () => {
    issuer = await makeAccessIssuer();
  });
  beforeEach(() => {
    stub = new FetchStub().echo(ORIGIN);
    serveJwks(stub, issuer);
  });
  afterEach(() => stub.restore());

  it("accepts a token signed by the team's JWKS and strips it before proxying", async () => {
    const token = await issuer.sign({ email: "alice@example.test", sub: "user-1" });
    const res = await run(gatewayRequest("/collections", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(200);
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["cf-access-jwt-assertion"]).toBeUndefined();
    expect(stub.callsTo(TEAM_DOMAIN).length).toBeGreaterThanOrEqual(1);
    expect(res.headers.get("X-Airweave-Gateway-Auth")).toBeNull();
  });

  it("accepts a service-token assertion that only carries common_name", async () => {
    const token = await issuer.sign({ common_name: "ci-runner.access" });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(200);
  });

  it("rejects a missing assertion with 401", async () => {
    const res = await run(gatewayRequest("/collections", { apiKey: null }), env());
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("missing_access_token");
    expect(stub.callsTo(ORIGIN)).toHaveLength(0);
  });

  it("rejects the wrong audience", async () => {
    const token = await issuer.sign({ email: "a@b.test" }, { audience: "another-app" });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_access_token");
  });

  it("rejects the wrong issuer", async () => {
    const token = await issuer.sign({ email: "a@b.test" }, { issuer: "https://other.cloudflareaccess.test" });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(403);
  });

  it("rejects an expired token", async () => {
    const token = await issuer.sign({ email: "a@b.test" }, { exp: Math.floor(Date.now() / 1000) - 120 });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(403);
  });

  it("rejects a token signed with a different key", async () => {
    const token = await issuer.signForged({ email: "mallory@example.test" });
    const res = await run(gatewayRequest("/x", { apiKey: null, headers: { "Cf-Access-Jwt-Assertion": token } }), env());
    expect(res.status).toBe(403);
    expect(stub.callsTo(ORIGIN)).toHaveLength(0);
  });

  it("refuses to run without TEAM_DOMAIN / POLICY_AUD", async () => {
    const res = await run(gatewayRequest("/x", { apiKey: null }), makeEnv({ AUTH_MODE: "access-jwt" }));
    expect(res.status).toBe(500);
    expect(((await res.json()) as { error: string }).error).toBe("gateway_misconfigured");
  });
});

describe("AUTH_MODE=api-key", () => {
  let stub: FetchStub;
  beforeEach(() => {
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  it("accepts the configured key and does not forward it", async () => {
    const res = await run(gatewayRequest("/collections"), makeEnv());
    expect(res.status).toBe(200);
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["x-airweave-gateway-key"]).toBeUndefined();
  });

  it("rejects a wrong key with 403", async () => {
    const res = await run(gatewayRequest("/collections", { apiKey: `${API_KEY}x` }), makeEnv());
    expect(res.status).toBe(403);
    expect(stub.calls).toHaveLength(0);
  });

  it("rejects a key with the same length but one different byte", async () => {
    const wrong = API_KEY.slice(0, -1) + (API_KEY.endsWith("f") ? "e" : "f");
    const res = await run(gatewayRequest("/collections", { apiKey: wrong }), makeEnv());
    expect(res.status).toBe(403);
  });

  it("rejects a missing key with 401", async () => {
    const res = await run(gatewayRequest("/collections", { apiKey: null }), makeEnv());
    expect(res.status).toBe(401);
  });

  it("refuses to run when the secret is not set", async () => {
    const res = await run(gatewayRequest("/collections"), makeEnv({ GATEWAY_API_KEY: undefined }));
    expect(res.status).toBe(500);
    expect(stub.calls).toHaveLength(0);
  });
});

describe("AUTH_MODE=off", () => {
  let stub: FetchStub;
  beforeEach(() => {
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  it("is refused unless ALLOW_INSECURE_DEV is exactly '1'", async () => {
    for (const value of [undefined, "0", "true", "yes", " 1"]) {
      const res = await run(gatewayRequest("/x", { apiKey: null }), makeEnv({ AUTH_MODE: "off", ALLOW_INSECURE_DEV: value }));
      expect(res.status).toBe(500);
      const body = (await res.json()) as { error: string; message: string };
      expect(body.error).toBe("gateway_misconfigured");
      expect(body.message).toContain("ALLOW_INSECURE_DEV");
      expect(res.headers.get("X-Airweave-Gateway-Auth")).toBeNull();
    }
    expect(stub.calls).toHaveLength(0);
  });

  it("proxies and labels responses when explicitly allowed", async () => {
    const res = await run(gatewayRequest("/x", { apiKey: null }), makeEnv({ AUTH_MODE: "off", ALLOW_INSECURE_DEV: "1" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Airweave-Gateway-Auth")).toBe("off");
  });
});

describe("AUTH_MODE validation", () => {
  it("rejects unknown modes with 500", async () => {
    const stub = new FetchStub();
    try {
      const res = await run(gatewayRequest("/x"), makeEnv({ AUTH_MODE: "basic" }));
      expect(res.status).toBe(500);
      expect(stub.calls).toHaveLength(0);
    } finally {
      stub.restore();
    }
  });

  it("defaults to access-jwt when AUTH_MODE is unset", async () => {
    const stub = new FetchStub();
    try {
      const res = await run(gatewayRequest("/x"), makeEnv({ AUTH_MODE: undefined, TEAM_DOMAIN, POLICY_AUD }));
      expect(res.status).toBe(401);
    } finally {
      stub.restore();
    }
  });
});
