/**
 * CORS handling: an exact-match allowlist from `ALLOWED_ORIGINS`, preflight
 * responses, and a helper that stamps the right headers on any response.
 *
 * Upstream `Access-Control-*` headers are discarded so the gateway allowlist is
 * the only thing that decides what a browser may read.
 */
import type { Env } from "./env";
import { ALLOWED_METHODS, jsonError } from "./util";

const DEFAULT_ALLOWED_HEADERS = [
  "Authorization",
  "Content-Type",
  "Accept",
  "X-Organization-ID",
  "X-Airweave-Session-ID",
  "X-Airweave-Gateway-Key",
  "Cf-Access-Jwt-Assertion",
].join(", ");

const EXPOSED_HEADERS = ["X-Request-Id", "X-Airweave-RateLimit", "Retry-After"].join(", ");

const PREFLIGHT_MAX_AGE_SECONDS = 600;

export interface CorsDecision {
  /** The request's `Origin` header, or null for non-browser callers. */
  origin: string | null;
  /** Whether `origin` matched the allowlist (`*` matches everything). */
  allowed: boolean;
  /** True when the match came from a `*` entry; credentials are not allowed then. */
  wildcard: boolean;
}

function normalizeOrigin(value: string): string {
  return value.trim().replace(/\/+$/, "").toLowerCase();
}

/** `ALLOWED_ORIGINS` is a comma-separated list; entries are normalised to lower-case, no trailing slash. */
export function parseAllowedOrigins(env: Env): string[] {
  return (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map(normalizeOrigin)
    .filter((o) => o.length > 0);
}

export function decideCors(request: Request, env: Env): CorsDecision {
  const origin = request.headers.get("Origin");
  if (origin === null) return { origin, allowed: false, wildcard: false };
  const allowed = parseAllowedOrigins(env);
  if (allowed.includes("*")) return { origin, allowed: true, wildcard: true };
  return { origin, allowed: allowed.includes(normalizeOrigin(origin)), wildcard: false };
}

/** Adds `Origin` to `Vary` unless it is already listed (upstreams and our own passes may have set it). */
function varyOnOrigin(headers: Headers): void {
  const current = headers.get("Vary");
  if (current === null) {
    headers.set("Vary", "Origin");
    return;
  }
  const tokens = current.split(",").map((t) => t.trim().toLowerCase());
  if (tokens.includes("*") || tokens.includes("origin")) return;
  headers.set("Vary", `${current}, Origin`);
}

/** Headers to add for an allowed origin; preflight requests get the extra `Access-Control-Allow-*` set. */
function applyCorsHeaders(headers: Headers, decision: CorsDecision, request: Request): void {
  // Strip whatever the upstream said; the gateway allowlist is authoritative.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("access-control-")) headers.delete(name);
  }
  varyOnOrigin(headers);
  if (!decision.allowed || decision.origin === null) return;

  headers.set("Access-Control-Allow-Origin", decision.wildcard ? "*" : decision.origin);
  headers.set("Access-Control-Expose-Headers", EXPOSED_HEADERS);
  if (!decision.wildcard) headers.set("Access-Control-Allow-Credentials", "true");

  if (request.method === "OPTIONS") {
    headers.set("Access-Control-Allow-Methods", [...ALLOWED_METHODS].join(", "));
    const requested = request.headers.get("Access-Control-Request-Headers");
    headers.set("Access-Control-Allow-Headers", requested ?? DEFAULT_ALLOWED_HEADERS);
    headers.set("Access-Control-Max-Age", String(PREFLIGHT_MAX_AGE_SECONDS));
  }
}

/**
 * Returns a copy of `response` with CORS headers applied. Responses that came
 * out of `fetch()` have immutable headers, hence the copy.
 */
export function withCorsHeaders(response: Response, decision: CorsDecision, request: Request): Response {
  const copy = new Response(response.body, response);
  applyCorsHeaders(copy.headers, decision, request);
  return copy;
}

/** Answer a preflight. Disallowed origins get a 403 with no `Access-Control-Allow-Origin`. */
export function preflightResponse(decision: CorsDecision, request: Request, requestId: string): Response {
  if (decision.origin !== null && !decision.allowed) {
    return withCorsHeaders(
      jsonError(403, "origin_not_allowed", "Origin is not in ALLOWED_ORIGINS", requestId),
      decision,
      request,
    );
  }
  const headers = new Headers({ Allow: [...ALLOWED_METHODS].join(", ") });
  const response = new Response(null, { status: 204, headers });
  applyCorsHeaders(response.headers, decision, request);
  return response;
}
