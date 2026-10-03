/**
 * Shared test plumbing.
 *
 * Tests call the Worker's `fetch` handler directly with a hand-built `env`, so
 * every test controls its own configuration, and stub the global `fetch` so no
 * request leaves workerd. (`@cloudflare/vitest-pool-workers` 0.22 no longer ships
 * a `fetchMock`; `FetchStub` below is the equivalent, and additionally records
 * every outbound request so header hygiene can be asserted.)
 */
import { createExecutionContext, env as testEnv, waitOnExecutionContext } from "cloudflare:test";
import { SignJWT, exportJWK, generateKeyPair, type JWTPayload } from "jose";
import { vi } from "vitest";
import type { Env } from "../src/env";
import worker from "../src/index";

export const GATEWAY = "https://gw.test";
export const ORIGIN = "https://airweave-origin.test";
export const TEAM_DOMAIN = "https://team.cloudflareaccess.test";
export const POLICY_AUD = "aud-0123456789abcdef";
export const API_KEY = "test-gateway-key-0123456789abcdef";
export const SERVICE_TOKEN_ID = "svc-token-id.access";
export const SERVICE_TOKEN_SECRET = "svc-token-secret-do-not-leak";
export const CLIENT_IP = "203.0.113.7";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface Captured {
  url: URL;
  method: string;
  headers: Headers;
  body: string | null;
}

type Handler = (request: Request, captured: Captured) => Response | Promise<Response>;
type Matcher = (url: URL, method: string) => boolean;

/** Replaces the global `fetch`; routes by origin and records every call. */
export class FetchStub {
  readonly calls: Captured[] = [];
  private readonly routes: Array<{ origin: string; match: Matcher; handler: Handler }> = [];

  constructor() {
    vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => this.dispatch(input, init));
  }

  on(origin: string, handler: Handler, match: Matcher = () => true): this {
    this.routes.push({ origin: new URL(origin).origin, match, handler });
    return this;
  }

  /** Route that answers with a JSON description of what it received. */
  echo(origin: string, extraHeaders: Record<string, string> = {}, status = 200): this {
    return this.on(origin, (_request, captured) =>
      Response.json(
        {
          method: captured.method,
          url: captured.url.toString(),
          headers: Object.fromEntries(captured.headers),
          body: captured.body,
        },
        { status, headers: extraHeaders },
      ),
    );
  }

  callsTo(origin: string): Captured[] {
    const wanted = new URL(origin).origin;
    return this.calls.filter((c) => c.url.origin === wanted);
  }

  restore(): void {
    vi.unstubAllGlobals();
  }

  private async dispatch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const body = request.method === "GET" || request.method === "HEAD" ? null : await request.clone().text();
    const captured: Captured = { url, method: request.method, headers: new Headers(request.headers), body };
    this.calls.push(captured);
    const route = this.routes.find((r) => r.origin === url.origin && r.match(url, request.method));
    if (!route) throw new TypeError(`FetchStub: no route for ${request.method} ${url}`);
    return route.handler(request, captured);
  }
}

/** A complete, valid api-key configuration; tests override what they need. */
export function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    ORIGIN_URL: ORIGIN,
    ALLOWED_ORIGINS: "http://localhost:8080,https://app.test",
    AUTH_MODE: "api-key",
    GATEWAY_API_KEY: API_KEY,
    ORIGIN_SERVICE_TOKEN_ID: SERVICE_TOKEN_ID,
    ORIGIN_SERVICE_TOKEN_SECRET: SERVICE_TOKEN_SECRET,
    ALLOW_INSECURE_DEV: "0",
    RATE_LIMIT_PERIOD_SECONDS: "60",
    TYPESAFE_AUTOBLOCK: "0",
    ...overrides,
  };
}

export interface GatewayRequestInit extends RequestInit {
  /** `null` sends no API key header. */
  apiKey?: string | null;
  origin?: string;
}

/** Request to the gateway as Cloudflare would deliver it (CF-Connecting-IP set). */
export function gatewayRequest(path: string, init: GatewayRequestInit = {}): Request {
  const { apiKey = API_KEY, origin, ...rest } = init;
  const headers = new Headers(rest.headers);
  headers.set("CF-Connecting-IP", CLIENT_IP);
  if (apiKey !== null && !headers.has("X-Airweave-Gateway-Key")) headers.set("X-Airweave-Gateway-Key", apiKey);
  if (origin) headers.set("Origin", origin);
  return new Request(`${GATEWAY}${path}`, { ...rest, headers });
}

/**
 * Empties the evidence table and the denylist. The Workers pool no longer
 * isolates storage per test, so files that touch D1/KV call this in beforeEach.
 */
export async function resetStorage(): Promise<void> {
  await testEnv.EVIDENCE_DB.batch([
    testEnv.EVIDENCE_DB.prepare("DELETE FROM evidence_events"),
    testEnv.EVIDENCE_DB.prepare("DELETE FROM sqlite_sequence WHERE name = 'evidence_events'"),
  ]);
  const { keys } = await testEnv.DENYLIST.list();
  await Promise.all(keys.map((k) => testEnv.DENYLIST.delete(k.name)));
}

/** Runs the Worker and waits for everything queued with ctx.waitUntil. */
export async function run(request: Request, env: Env): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

export interface EchoBody {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

export interface AccessIssuer {
  jwks: { keys: Array<Record<string, unknown>> };
  sign(claims: JWTPayload, opts?: { issuer?: string; audience?: string; exp?: number | string; kid?: string }): Promise<string>;
  /** Signs with a different key under the same kid: a forged token. */
  signForged(claims: JWTPayload): Promise<string>;
}

/** A fake Cloudflare Access issuer: an RSA key pair and the JWKS document for it. */
export async function makeAccessIssuer(teamDomain = TEAM_DOMAIN): Promise<AccessIssuer> {
  const kid = "test-kid-1";
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const forged = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
  const build = (claims: JWTPayload, opts: { issuer?: string; audience?: string; exp?: number | string; kid?: string } = {}) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: opts.kid ?? kid })
      .setIssuedAt()
      .setIssuer(opts.issuer ?? teamDomain)
      .setAudience(opts.audience ?? POLICY_AUD)
      .setExpirationTime(opts.exp ?? "10m");
  return {
    jwks: { keys: [jwk] },
    sign: (claims, opts) => build(claims, opts).sign(privateKey),
    signForged: (claims) => build(claims).sign(forged.privateKey),
  };
}

/** Routes TEAM_DOMAIN/cdn-cgi/access/certs on the stub to the issuer's JWKS. */
export function serveJwks(stub: FetchStub, issuer: AccessIssuer, teamDomain = TEAM_DOMAIN): void {
  stub.on(
    teamDomain,
    () => Response.json(issuer.jwks),
    (url) => url.pathname === "/cdn-cgi/access/certs",
  );
}
