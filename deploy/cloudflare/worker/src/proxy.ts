/**
 * Forwarding to the origin (the Cloudflare Tunnel hostname).
 *
 * Header hygiene on the way in:
 *   - hop-by-hop headers and `Host` are dropped (fetch sets its own)
 *   - every incoming `cf-access-*` header is dropped, so a caller can never smuggle
 *     a service-token header or a forged JWT assertion to the origin
 *   - the gateway API key and any client-supplied X-Request-Id / X-Forwarded-* /
 *     X-Airweave-Suspicion are dropped and replaced with the gateway's own values
 *   - client-IP headers (X-Forwarded-For, X-Real-IP, Forwarded) are dropped and
 *     X-Forwarded-For is set to CF-Connecting-IP alone, so the address the backend
 *     logs is the one Cloudflare saw and never one the caller chose
 *   - the origin service token (CF-Access-Client-Id/Secret) is added from secrets
 *
 * The response body is streamed back untouched (SSE included); only hop-by-hop
 * headers are removed and X-Request-Id is added.
 */
import type { Env } from "./env";
import { jsonError, logEvent } from "./util";

export const REQUEST_ID_HEADER = "X-Request-Id";
export const SUSPICION_HEADER = "X-Airweave-Suspicion";

/** RFC 7230 §6.1 hop-by-hop headers, plus ones fetch() manages itself. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "expect",
]);

/** Client-supplied headers that must never reach the origin as-is. */
const STRIPPED_REQUEST_HEADERS = new Set([
  "x-airweave-gateway-key",
  "x-request-id",
  "x-forwarded-host",
  "x-forwarded-proto",
  // Client-IP headers: the origin only ever sees CF-Connecting-IP (set below).
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
  "x-airweave-suspicion",
]);

/** Cookies set by Cloudflare Access on the origin hostname (CF_Authorization, CF_AppSession, ...). */
const ACCESS_COOKIE = /^\s*cf_/i;

/** Drops Access cookies from a client `Cookie` header; returns null when nothing is left. */
export function stripAccessCookies(cookieHeader: string): string | null {
  const kept = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && !ACCESS_COOKIE.test(part));
  return kept.length > 0 ? kept.join("; ") : null;
}

export interface ProxyOptions {
  requestId: string;
  /** Soft signals to forward as `X-Airweave-Suspicion` (never sent to the client). */
  suspicion?: string[];
}

/** Parses ORIGIN_URL; returns null when it is missing or not an absolute http(s) URL. */
export function parseOriginUrl(env: Env): URL | null {
  if (!env.ORIGIN_URL) return null;
  try {
    const url = new URL(env.ORIGIN_URL);
    return url.protocol === "https:" || url.protocol === "http:" ? url : null;
  } catch {
    return null;
  }
}

function joinPath(base: string, path: string): string {
  const trimmedBase = base.replace(/\/+$/, "");
  return trimmedBase + (path.startsWith("/") ? path : `/${path}`);
}

/** The upstream URL: ORIGIN_URL (optionally with a base path) + original path + query. */
export function buildUpstreamUrl(origin: URL, incoming: URL): URL {
  const upstream = new URL(origin.toString());
  upstream.pathname = joinPath(origin.pathname, incoming.pathname);
  upstream.search = incoming.search;
  upstream.hash = "";
  return upstream;
}

function connectionListedHeaders(headers: Headers): Set<string> {
  const listed = new Set<string>();
  const connection = headers.get("Connection");
  if (!connection) return listed;
  for (const name of connection.split(",")) listed.add(name.trim().toLowerCase());
  return listed;
}

export function buildUpstreamHeaders(request: Request, env: Env, incoming: URL, options: ProxyOptions): Headers {
  const headers = new Headers();
  const connectionListed = connectionListedHeaders(request.headers);
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || connectionListed.has(lower)) continue;
    if (lower.startsWith("cf-access-")) continue;
    if (STRIPPED_REQUEST_HEADERS.has(lower)) continue;
    if (lower === "cookie") {
      // A client-supplied Access session cookie must not reach the origin hostname,
      // where it would be evaluated alongside the Worker's service token.
      const kept = stripAccessCookies(value);
      if (kept !== null) headers.append(name, kept);
      continue;
    }
    headers.append(name, value);
  }

  headers.set(REQUEST_ID_HEADER, options.requestId);
  headers.set("X-Forwarded-Host", incoming.host);
  headers.set("X-Forwarded-Proto", incoming.protocol.replace(/:$/, ""));
  // Only the address Cloudflare saw; a client-supplied chain was stripped above
  // and is never trusted. Without CF-Connecting-IP the header is omitted.
  const connectingIp = request.headers.get("CF-Connecting-IP");
  if (connectingIp) headers.set("X-Forwarded-For", connectingIp);
  if (options.suspicion && options.suspicion.length > 0) {
    headers.set(SUSPICION_HEADER, options.suspicion.join(","));
  }
  if (env.ORIGIN_SERVICE_TOKEN_ID && env.ORIGIN_SERVICE_TOKEN_SECRET) {
    headers.set("CF-Access-Client-Id", env.ORIGIN_SERVICE_TOKEN_ID);
    headers.set("CF-Access-Client-Secret", env.ORIGIN_SERVICE_TOKEN_SECRET);
  }
  return headers;
}

function stripResponseHeaders(upstream: Headers, requestId: string): Headers {
  const headers = new Headers();
  const connectionListed = connectionListedHeaders(upstream);
  for (const [name, value] of upstream) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || connectionListed.has(lower)) continue;
    // Access answers the Worker's service token with a CF_Authorization session
    // cookie for the origin hostname; relayed to the client it would let them call
    // the origin directly and bypass the Worker.
    if (lower === "set-cookie" && ACCESS_COOKIE.test(value)) continue;
    headers.append(name, value);
  }
  headers.set(REQUEST_ID_HEADER, requestId);
  return headers;
}

export async function proxyToOrigin(request: Request, env: Env, options: ProxyOptions): Promise<Response> {
  const origin = parseOriginUrl(env);
  if (!origin) {
    return jsonError(500, "gateway_misconfigured", "ORIGIN_URL must be an absolute http(s) URL", options.requestId);
  }
  const incoming = new URL(request.url);
  const upstreamUrl = buildUpstreamUrl(origin, incoming);
  const method = request.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl.toString(), {
      method,
      headers: buildUpstreamHeaders(request, env, incoming, options),
      body: hasBody ? request.body : null,
      // 3xx answers belong to the client, not to the gateway.
      redirect: "manual",
    });
  } catch (err) {
    logEvent("error", "origin_unreachable", { request_id: options.requestId, error: String(err) });
    return jsonError(502, "origin_unreachable", "The Airweave origin did not answer", options.requestId);
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: stripResponseHeaders(upstream.headers, options.requestId),
  });
}
