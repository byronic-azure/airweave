/**
 * Per-principal rate limiting through the Workers rate limiting binding.
 *
 * The binding is optional: without it the gateway skips limiting and marks every
 * response with `X-Airweave-RateLimit: disabled`. A binding error fails open (the
 * request proceeds) and is logged, because a broken limiter should not take the
 * API down.
 */
import type { Env, RateLimitBinding } from "./env";
import { envNumber, jsonError, logEvent } from "./util";

export const RATE_LIMIT_HEADER = "X-Airweave-RateLimit";

export type RateLimitOutcome = "ok" | "limited" | "disabled";

export async function checkRateLimit(binding: RateLimitBinding | undefined, key: string): Promise<RateLimitOutcome> {
  if (!binding) return "disabled";
  try {
    const { success } = await binding.limit({ key });
    return success ? "ok" : "limited";
  } catch (err) {
    logEvent("warn", "ratelimit_error", { message: "rate limiter failed; allowing request", error: String(err) });
    return "ok";
  }
}

/** Seconds to advertise in `Retry-After`; should match the binding's `simple.period`. */
export function retryAfterSeconds(env: Env): number {
  const n = Math.round(envNumber(env.RATE_LIMIT_PERIOD_SECONDS, 60));
  return Math.min(Math.max(n, 1), 3600);
}

export function rateLimitedResponse(env: Env, requestId: string): Response {
  const retryAfter = retryAfterSeconds(env);
  return jsonError(
    429,
    "rate_limited",
    `Too many requests; retry after ${retryAfter}s`,
    requestId,
    { retry_after: retryAfter },
    { headers: { "Retry-After": String(retryAfter), [RATE_LIMIT_HEADER]: "exceeded" } },
  );
}
