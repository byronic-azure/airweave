/**
 * Bindings and configuration the gateway reads from `env`.
 *
 * Everything is optional at the type level so that a missing binding or variable
 * degrades to a documented behaviour instead of a crash: see the per-field notes
 * and deploy/cloudflare/worker/README.md. Secrets are set with
 * `wrangler secret put <NAME>` (or `.dev.vars` locally) and never live in wrangler.jsonc.
 */

/** Minimal surface of the Workers rate limiting binding (`[[unsafe.bindings]] type = "ratelimit"`). */
export interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  // --- proxy target --------------------------------------------------------
  /** Cloudflare Tunnel public hostname, e.g. `https://airweave-origin.example.com`. Required. */
  ORIGIN_URL?: string;
  /** Access service token presented to the tunnel's Access application. Secret. */
  ORIGIN_SERVICE_TOKEN_ID?: string;
  /** Access service token secret. Secret. */
  ORIGIN_SERVICE_TOKEN_SECRET?: string;

  // --- CORS ----------------------------------------------------------------
  /** Comma-separated list of allowed browser origins (exact match, or `*`). */
  ALLOWED_ORIGINS?: string;

  // --- authentication ------------------------------------------------------
  /** `access-jwt` (default) | `api-key` | `off`. */
  AUTH_MODE?: string;
  /** Cloudflare Access team domain, e.g. `https://example.cloudflareaccess.com`. */
  TEAM_DOMAIN?: string;
  /** Application Audience (AUD) tag of the Access application in front of the gateway. */
  POLICY_AUD?: string;
  /** Shared key for `AUTH_MODE = "api-key"`. Secret. */
  GATEWAY_API_KEY?: string;
  /** Must be exactly `"1"` for `AUTH_MODE = "off"` to be accepted. */
  ALLOW_INSECURE_DEV?: string;

  // --- rate limiting -------------------------------------------------------
  /** Optional Workers rate limiting binding. Absent -> `X-Airweave-RateLimit: disabled`. */
  RATE_LIMITER?: RateLimitBinding;
  /** Retry-After hint on 429s; keep in sync with the binding's `simple.period`. Default 60. */
  RATE_LIMIT_PERIOD_SECONDS?: string;

  // --- evidence log --------------------------------------------------------
  /** Optional D1 database holding the hash-chained `evidence_events` table. */
  EVIDENCE_DB?: D1Database;

  // --- TypeSafe verify-and-escalate ----------------------------------------
  /** Enables TypeSafe judgements for flagged requests when set. Secret. */
  TYPESAFE_API_KEY?: string;
  /** `"1"` to let high-confidence probe judgements add the principal to DENYLIST. */
  TYPESAFE_AUTOBLOCK?: string;
  /** Minimum `is_probe` probability for autoblock. Default 0.95. */
  TYPESAFE_BLOCK_THRESHOLD?: string;
  /** Lifetime of an autoblock entry in seconds. Default 900 (KV minimum is 60). */
  TYPESAFE_BLOCK_TTL_SECONDS?: string;
  /** Optional KV namespace of denied principal keys; checked on the hot path when bound. */
  DENYLIST?: KVNamespace;
}
