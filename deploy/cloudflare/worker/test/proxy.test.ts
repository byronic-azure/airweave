import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildUpstreamUrl } from "../src/proxy";
import {
  API_KEY,
  CLIENT_IP,
  GATEWAY,
  ORIGIN,
  SERVICE_TOKEN_ID,
  SERVICE_TOKEN_SECRET,
  UUID_RE,
  FetchStub,
  gatewayRequest,
  makeEnv,
  run,
  type EchoBody,
} from "./helpers";

describe("proxy", () => {
  let stub: FetchStub;
  beforeEach(() => {
    stub = new FetchStub().echo(ORIGIN);
  });
  afterEach(() => stub.restore());

  it("forwards method, path, query and body and scrubs the headers", async () => {
    const res = await run(
      gatewayRequest("/collections/abc/search?query=hello&limit=5", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Organization-ID": "org-1",
          "Cf-Access-Jwt-Assertion": "forged.jwt.value",
          "CF-Access-Client-Id": "spoofed-id",
          "CF-Access-Client-Secret": "spoofed-secret",
          "cf-access-authenticated-user-email": "mallory@example.test",
          "X-Request-Id": "client-chosen",
          "X-Forwarded-Host": "spoofed.host",
          "X-Forwarded-Proto": "gopher",
          "X-Forwarded-For": "10.0.0.1, 203.0.113.250",
          "X-Real-IP": "10.8.8.8",
          Forwarded: "for=10.9.9.9",
          Connection: "keep-alive, X-Custom-Hop",
          "X-Custom-Hop": "drop-me",
        },
        body: JSON.stringify({ query: "hello" }),
      }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    const echo = (await res.json()) as EchoBody;
    expect(echo.method).toBe("POST");
    expect(echo.url).toBe(`${ORIGIN}/collections/abc/search?query=hello&limit=5`);
    expect(echo.body).toBe(JSON.stringify({ query: "hello" }));

    const h = echo.headers;
    expect(h["x-organization-id"]).toBe("org-1");
    expect(h["content-type"]).toBe("application/json");
    expect(h["cf-access-jwt-assertion"]).toBeUndefined();
    expect(h["cf-access-authenticated-user-email"]).toBeUndefined();
    expect(h["x-airweave-gateway-key"]).toBeUndefined();
    expect(h["cf-access-client-id"]).toBe(SERVICE_TOKEN_ID);
    expect(h["cf-access-client-secret"]).toBe(SERVICE_TOKEN_SECRET);
    expect(h["x-request-id"]).toMatch(UUID_RE);
    expect(h["x-request-id"]).toBe(res.headers.get("X-Request-Id"));
    expect(h["x-forwarded-host"]).toBe("gw.test");
    expect(h["x-forwarded-proto"]).toBe("https");
    expect(h["x-forwarded-for"]).toBe(CLIENT_IP); // CF-Connecting-IP, never the client's chain
    expect(h["x-real-ip"]).toBeUndefined();
    expect(h["forwarded"]).toBeUndefined();
    expect(h["connection"]).toBeUndefined();
    expect(h["x-custom-hop"]).toBeUndefined();
    expect(h["x-airweave-suspicion"]).toBeUndefined();
    expect(Object.keys(h).some((k) => k.startsWith("cf-access-") && !k.startsWith("cf-access-client-"))).toBe(false);
  });

  it("keeps Access cookies on the gateway side in both directions", async () => {
    let upstreamCookie: string | null | undefined;
    stub.restore();
    stub = new FetchStub().on(ORIGIN, (request) => {
      upstreamCookie = request.headers.get("Cookie");
      const headers = new Headers({ "Content-Type": "text/plain" });
      headers.append("Set-Cookie", "CF_Authorization=origin-session; Path=/; HttpOnly");
      headers.append("Set-Cookie", "cf_appsession=abc; Path=/");
      headers.append("Set-Cookie", "theme=dark; Path=/");
      return new Response("ok", { headers });
    });
    const res = await run(
      gatewayRequest("/collections", { headers: { Cookie: "CF_Authorization=stolen; theme=dark" } }),
      makeEnv(),
    );
    expect(res.status).toBe(200);
    expect(upstreamCookie).toBe("theme=dark");
    const setCookies = [...res.headers].filter(([name]) => name === "set-cookie").map(([, value]) => value);
    expect(setCookies).toEqual(["theme=dark; Path=/"]);
  });

  it("omits X-Forwarded-For rather than trusting the client when CF-Connecting-IP is absent", async () => {
    const request = new Request(`${GATEWAY}/x`, {
      headers: { "X-Airweave-Gateway-Key": API_KEY, "X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.8.8.8" },
    });
    const res = await run(request, makeEnv());
    expect(res.status).toBe(200);
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["x-forwarded-for"]).toBeUndefined();
    expect(echo.headers["x-real-ip"]).toBeUndefined();
  });

  it("omits the service token headers when the secrets are not set", async () => {
    const res = await run(
      gatewayRequest("/x"),
      makeEnv({ ORIGIN_SERVICE_TOKEN_ID: undefined, ORIGIN_SERVICE_TOKEN_SECRET: undefined }),
    );
    const echo = (await res.json()) as EchoBody;
    expect(echo.headers["cf-access-client-id"]).toBeUndefined();
    expect(echo.headers["cf-access-client-secret"]).toBeUndefined();
  });

  it("honours a base path in ORIGIN_URL", () => {
    const upstream = buildUpstreamUrl(new URL("https://origin.test/base/"), new URL("https://gw.test/collections?x=1"));
    expect(upstream.toString()).toBe("https://origin.test/base/collections?x=1");
  });

  it("streams the upstream body and status through unchanged", async () => {
    stub.restore();
    stub = new FetchStub().on(ORIGIN, () => {
      const encoder = new TextEncoder();
      const body = new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode("data: one\n\n"));
          controller.enqueue(encoder.encode("data: two\n\n"));
          controller.close();
        },
      });
      return new Response(body, {
        status: 201,
        headers: { "Content-Type": "text/event-stream", "X-Upstream": "yes", "Cache-Control": "no-cache" },
      });
    });
    const res = await run(gatewayRequest("/sync/stream"), makeEnv());
    expect(res.status).toBe(201);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
    expect(res.headers.get("X-Upstream")).toBe("yes");
    expect(res.headers.get("X-Request-Id")).toMatch(UUID_RE);
    expect(await res.text()).toBe("data: one\n\ndata: two\n\n");
  });

  it("passes redirects back to the client instead of following them", async () => {
    stub.restore();
    stub = new FetchStub().on(ORIGIN, () => new Response(null, { status: 302, headers: { Location: "/elsewhere" } }));
    const res = await run(gatewayRequest("/old"), makeEnv());
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/elsewhere");
    expect(stub.calls).toHaveLength(1);
  });

  it("answers 502 when the origin is unreachable", async () => {
    stub.restore();
    stub = new FetchStub().on(ORIGIN, () => {
      throw new TypeError("connect ECONNREFUSED");
    });
    const res = await run(gatewayRequest("/x"), makeEnv());
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: string }).error).toBe("origin_unreachable");
    expect(res.headers.get("X-Request-Id")).toMatch(UUID_RE);
  });

  it("answers 500 when ORIGIN_URL is missing or invalid", async () => {
    for (const value of [undefined, "not a url", "ftp://x"]) {
      const res = await run(gatewayRequest("/x"), makeEnv({ ORIGIN_URL: value }));
      expect(res.status).toBe(500);
      expect(((await res.json()) as { error: string }).error).toBe("gateway_misconfigured");
    }
    expect(stub.calls).toHaveLength(0);
  });

  it("does not proxy the gateway's own evidence endpoint", async () => {
    const res = await run(gatewayRequest("/evidence/verify"), makeEnv());
    expect(res.status).toBe(503);
    expect(stub.calls).toHaveLength(0);
  });
});
