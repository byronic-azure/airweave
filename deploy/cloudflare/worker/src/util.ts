/**
 * Small, dependency-free helpers shared by the gateway modules.
 *
 * Nothing here touches bindings or the network, so every function is safe to
 * call from the hot path and trivial to unit test.
 */

export const SERVICE_NAME = "airweave-edge-gateway";

/** Kept in sync with package.json by test/healthz.test.ts. */
export const VERSION = "0.1.0";

/** HTTP methods the gateway is willing to proxy. Anything else is a hard 400. */
export const ALLOWED_METHODS: ReadonlySet<string> = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD",
]);

const encoder = new TextEncoder();

/** Lower-case hex encoding of a byte buffer. */
export function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** SHA-256 of a string (UTF-8) or byte array, as lower-case hex. */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

/**
 * Constant-time string comparison for secrets (API keys, tokens).
 *
 * Both inputs are compared byte-for-byte over the longer length, and the
 * length difference is folded into the result, so neither the position of the
 * first mismatch nor the length of the expected value leaks through timing.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  const n = Math.max(x.length, y.length);
  let diff = x.length ^ y.length;
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/**
 * Deterministic JSON serialisation: object keys sorted, `undefined` members
 * dropped, no insignificant whitespace. Used for hashing evidence rows so the
 * same logical record always produces the same digest.
 */
export function canonicalJSON(value: unknown): string {
  if (value === null || value === undefined) return "null";
  switch (typeof value) {
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("canonicalJSON: non-finite number");
      return JSON.stringify(value);
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalJSON(v)).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
    }
    default:
      throw new TypeError(`canonicalJSON: unsupported type ${typeof value}`);
  }
}

/** Best-effort client address: Cloudflare sets CF-Connecting-IP on every request. */
export function clientIp(request: Request): string {
  return (
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Real-IP") ??
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

/** JSON response with sane defaults (never cached). */
export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { ...init, headers });
}

/** Uniform error body: `{ error, message, request_id }` plus any extra fields. */
export function jsonError(
  status: number,
  error: string,
  message: string,
  requestId: string,
  extra: Record<string, unknown> = {},
  init: ResponseInit = {},
): Response {
  return jsonResponse({ error, message, request_id: requestId, ...extra }, { ...init, status });
}

/** Parse a positive number from an env string, falling back to `fallback`. */
export function envNumber(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

/** Structured console line; keeps logs grep-able in `wrangler tail`. */
export function logEvent(level: "log" | "warn" | "error", event: string, fields: Record<string, unknown>): void {
  console[level](JSON.stringify({ event, service: SERVICE_NAME, ...fields }));
}
