/**
 * Authentication of the caller, selected by `AUTH_MODE`:
 *
 *   access-jwt  verify the `Cf-Access-Jwt-Assertion` header issued by Cloudflare
 *               Access (JWKS at TEAM_DOMAIN/cdn-cgi/access/certs, iss = TEAM_DOMAIN,
 *               aud = POLICY_AUD).
 *   api-key     compare `X-Airweave-Gateway-Key` to the GATEWAY_API_KEY secret in
 *               constant time.
 *   off         no authentication. Only honoured when ALLOW_INSECURE_DEV = "1";
 *               otherwise the gateway answers 500 so a misconfiguration can never
 *               silently expose the backend.
 *
 * The returned principal carries a `key` that is stable per caller and free of
 * secrets; it is what the rate limiter and the denylist are keyed on.
 */
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Env } from "./env";
import { clientIp, jsonError, sha256Hex, timingSafeEqual } from "./util";

export const ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion";
export const API_KEY_HEADER = "X-Airweave-Gateway-Key";
/** Added to every response when AUTH_MODE=off is in effect, so nobody mistakes it for a protected deployment. */
export const GATEWAY_AUTH_HEADER = "X-Airweave-Gateway-Auth";

export type AuthMode = "access-jwt" | "api-key" | "off";
export type PrincipalKind = "access-jwt" | "api-key" | "anonymous";

export interface Principal {
  kind: PrincipalKind;
  /** Human-readable identity for evidence rows (email, subject, or a key fingerprint). */
  id: string;
  /** Stable, secret-free key for rate limiting and the denylist. */
  key: string;
}

export type AuthResult = { ok: true; principal: Principal } | { ok: false; response: Response };

/** Principal used before authentication has happened (hard-blocked requests). */
export function anonymousPrincipal(request: Request): Principal {
  return { kind: "anonymous", id: "unauthenticated", key: `ip:${clientIp(request)}` };
}

export function authMode(env: Env): string {
  return (env.AUTH_MODE ?? "access-jwt").trim().toLowerCase();
}

// One remote JWKS per team domain, shared across requests in this isolate so the
// certs endpoint is fetched once and refreshed on unknown `kid`s (jose handles
// the cooldown and cache lifetime).
const jwksByDomain = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jwksFor(teamDomain: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksByDomain.get(teamDomain);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`), {
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
      timeoutDuration: 5_000,
    });
    jwksByDomain.set(teamDomain, jwks);
  }
  return jwks;
}

function normalizeTeamDomain(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

function identityFromClaims(payload: JWTPayload): string | undefined {
  const email = payload["email"];
  if (typeof email === "string" && email) return email;
  if (typeof payload.sub === "string" && payload.sub) return payload.sub;
  // Access service tokens carry `common_name` instead of a user identity.
  const commonName = payload["common_name"];
  return typeof commonName === "string" && commonName ? commonName : undefined;
}

async function authenticateAccessJwt(request: Request, env: Env, requestId: string): Promise<AuthResult> {
  if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
    return {
      ok: false,
      response: jsonError(
        500,
        "gateway_misconfigured",
        "AUTH_MODE=access-jwt requires TEAM_DOMAIN and POLICY_AUD",
        requestId,
      ),
    };
  }
  const token = request.headers.get(ACCESS_JWT_HEADER);
  if (!token) {
    return {
      ok: false,
      response: jsonError(401, "missing_access_token", `${ACCESS_JWT_HEADER} header is required`, requestId),
    };
  }
  const teamDomain = normalizeTeamDomain(env.TEAM_DOMAIN);
  try {
    const { payload } = await jwtVerify(token, jwksFor(teamDomain), {
      issuer: teamDomain,
      audience: env.POLICY_AUD,
    });
    const id = identityFromClaims(payload);
    if (!id) {
      return {
        ok: false,
        response: jsonError(403, "invalid_access_token", "Token carries no identity claim", requestId),
      };
    }
    return { ok: true, principal: { kind: "access-jwt", id, key: `jwt:${id}` } };
  } catch {
    return {
      ok: false,
      response: jsonError(403, "invalid_access_token", "Access token failed verification", requestId),
    };
  }
}

async function authenticateApiKey(request: Request, env: Env, requestId: string): Promise<AuthResult> {
  if (!env.GATEWAY_API_KEY) {
    return {
      ok: false,
      response: jsonError(
        500,
        "gateway_misconfigured",
        "AUTH_MODE=api-key requires the GATEWAY_API_KEY secret",
        requestId,
      ),
    };
  }
  const provided = request.headers.get(API_KEY_HEADER);
  if (!provided) {
    return {
      ok: false,
      response: jsonError(401, "missing_api_key", `${API_KEY_HEADER} header is required`, requestId),
    };
  }
  if (!timingSafeEqual(provided, env.GATEWAY_API_KEY)) {
    return { ok: false, response: jsonError(403, "invalid_api_key", "API key rejected", requestId) };
  }
  // The key itself never leaves this function; downstream only sees its digest.
  const digest = await sha256Hex(provided);
  return {
    ok: true,
    principal: { kind: "api-key", id: `apikey:${digest.slice(0, 16)}`, key: `apikey:${digest}` },
  };
}

function authenticateOff(request: Request, env: Env, requestId: string): AuthResult {
  if (env.ALLOW_INSECURE_DEV !== "1") {
    return {
      ok: false,
      response: jsonError(
        500,
        "gateway_misconfigured",
        'AUTH_MODE=off is only allowed when ALLOW_INSECURE_DEV="1"; refusing to proxy unauthenticated traffic',
        requestId,
      ),
    };
  }
  return { ok: true, principal: { kind: "anonymous", id: "anonymous", key: `ip:${clientIp(request)}` } };
}

export async function authenticate(request: Request, env: Env, requestId: string): Promise<AuthResult> {
  switch (authMode(env)) {
    case "access-jwt":
      return authenticateAccessJwt(request, env, requestId);
    case "api-key":
      return authenticateApiKey(request, env, requestId);
    case "off":
      return authenticateOff(request, env, requestId);
    default:
      return {
        ok: false,
        response: jsonError(
          500,
          "gateway_misconfigured",
          `Unknown AUTH_MODE "${env.AUTH_MODE}"; expected access-jwt, api-key or off`,
          requestId,
        ),
      };
  }
}
