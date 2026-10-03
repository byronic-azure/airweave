import { afterEach, beforeEach, describe, expect, it } from "vitest";
import pkg from "../package.json";
import { VERSION } from "../src/util";
import { FetchStub, UUID_RE, gatewayRequest, makeEnv, run } from "./helpers";

describe("GET /healthz", () => {
  let stub: FetchStub;
  beforeEach(() => {
    stub = new FetchStub(); // no routes: any outbound call would throw
  });
  afterEach(() => stub.restore());

  it("answers without authentication and never calls the origin", async () => {
    const res = await run(gatewayRequest("/healthz", { apiKey: null }), makeEnv({ GATEWAY_API_KEY: undefined }));
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    expect(await res.json()).toEqual({ ok: true, service: "airweave-edge-gateway", version: VERSION });
    expect(res.headers.get("X-Request-Id")).toMatch(UUID_RE);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(stub.calls).toHaveLength(0);
  });

  it("reports the package.json version", () => {
    expect(VERSION).toBe(pkg.version);
  });

  it("supports HEAD", async () => {
    const res = await run(gatewayRequest("/healthz", { method: "HEAD", apiKey: null }), makeEnv());
    expect(res.status).toBe(200);
  });

  it("marks responses when the rate limiter binding is absent", async () => {
    const res = await run(gatewayRequest("/healthz", { apiKey: null }), makeEnv());
    expect(res.headers.get("X-Airweave-RateLimit")).toBe("disabled");
  });
});
