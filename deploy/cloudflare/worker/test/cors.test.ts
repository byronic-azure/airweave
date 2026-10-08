import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ORIGIN, FetchStub, gatewayRequest, makeEnv, run } from "./helpers";

const ALLOWED = "http://localhost:8080";
const DENIED = "https://evil.test";

describe("CORS", () => {
  let stub: FetchStub;
  beforeEach(() => {
    // The origin answers with its own permissive CORS header, which the gateway must override.
    stub = new FetchStub().echo(ORIGIN, { "Access-Control-Allow-Origin": "*", Vary: "Accept-Encoding" });
  });
  afterEach(() => stub.restore());

  it("answers preflight for an allowed origin with 204 and no auth", async () => {
    const res = await run(
      gatewayRequest("/collections", {
        method: "OPTIONS",
        apiKey: null,
        origin: ALLOWED,
        headers: {
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "content-type, x-organization-id",
        },
      }),
      makeEnv(),
    );
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(ALLOWED);
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("PATCH");
    expect(res.headers.get("Access-Control-Allow-Headers")).toBe("content-type, x-organization-id");
    expect(res.headers.get("Access-Control-Allow-Credentials")).toBe("true");
    expect(res.headers.get("Access-Control-Max-Age")).toBe("600");
    expect(res.headers.get("Vary")).toBe("Origin");
    expect(stub.calls).toHaveLength(0);
  });

  it("does not repeat Origin in Vary when the upstream already lists it", async () => {
    stub.restore();
    stub = new FetchStub().echo(ORIGIN, { Vary: "Accept-Encoding, origin" });
    const res = await run(gatewayRequest("/collections", { origin: ALLOWED }), makeEnv());
    expect(res.headers.get("Vary")).toBe("Accept-Encoding, origin");
  });

  it("rejects preflight from an origin outside the allowlist", async () => {
    const res = await run(gatewayRequest("/collections", { method: "OPTIONS", apiKey: null, origin: DENIED }), makeEnv());
    expect(res.status).toBe(403);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(res.headers.get("Vary")).toContain("Origin");
    expect(((await res.json()) as { error: string }).error).toBe("origin_not_allowed");
  });

  it("matches origins case-insensitively and ignores a trailing slash in the allowlist", async () => {
    const env = makeEnv({ ALLOWED_ORIGINS: " HTTPS://App.Test/ , http://localhost:8080" });
    const res = await run(gatewayRequest("/x", { method: "OPTIONS", apiKey: null, origin: "https://app.test" }), env);
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://app.test");
  });

  it("stamps CORS headers on proxied responses for an allowed origin and drops the upstream's", async () => {
    const res = await run(gatewayRequest("/collections", { origin: ALLOWED }), makeEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(ALLOWED);
    expect(res.headers.get("Access-Control-Expose-Headers")).toContain("X-Request-Id");
    expect(res.headers.get("Vary")).toBe("Accept-Encoding, Origin");
  });

  it("proxies but withholds CORS headers for a disallowed origin", async () => {
    const res = await run(gatewayRequest("/collections", { origin: DENIED }), makeEnv());
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(res.headers.get("Vary")).toContain("Origin");
  });

  it("adds no CORS headers for non-browser callers", async () => {
    const res = await run(gatewayRequest("/collections"), makeEnv());
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(res.headers.get("Vary")).toContain("Origin");
  });

  it("supports a wildcard allowlist without credentials", async () => {
    const res = await run(gatewayRequest("/collections", { origin: DENIED }), makeEnv({ ALLOWED_ORIGINS: "*" }));
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  });

  it("answers a non-CORS OPTIONS with 204 and Allow", async () => {
    const res = await run(gatewayRequest("/collections", { method: "OPTIONS", apiKey: null }), makeEnv());
    expect(res.status).toBe(204);
    expect(res.headers.get("Allow")).toContain("GET");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});
