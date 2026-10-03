/**
 * TypeSafe System One ("Jev") verify-and-escalate.
 *
 * Never on the hot path: only requests that were already hard-blocked,
 * rate-limited or soft-flagged are judged, from inside `ctx.waitUntil`, after
 * the client has its response. The model sees a sanitised summary of the request
 * (method, path, query parameter *names*, user agent, the heuristic signals, the
 * principal kind and the status we returned) and never a body, a secret, a
 * token or a query value.
 *
 * Answers are calibrated probabilities, not proof. The default is label-only:
 * the judgement is stored next to the evidence row for a human to review.
 * Autoblock is opt-in (TYPESAFE_AUTOBLOCK = "1"), needs the DENYLIST KV binding,
 * and only fires when `is_probe` reaches TYPESAFE_BLOCK_THRESHOLD (default 0.95),
 * for TYPESAFE_BLOCK_TTL_SECONDS (default 900). Thresholds live in env, not code.
 */
import type { Env } from "./env";
import { envNumber, logEvent } from "./util";

export const TYPESAFE_ENDPOINT = "https://api.typesafe.ai/v1/systemone";
export const TYPESAFE_MODEL = "jev-latest";
const TYPESAFE_TIMEOUT_MS = 8_000;
const MAX_QUERY_KEYS = 32;
const MAX_USER_AGENT_LENGTH = 256;
/** KV refuses expirationTtl below 60 seconds. */
const MIN_TTL_SECONDS = 60;

export interface TypeSafeState {
  method: string;
  path: string;
  query_keys: string[];
  user_agent: string | null;
  flagged_signals: string[];
  principal_kind: string;
  status_returned: number;
}

/** The question set sent with every judgement. Ids are local; the model never sees them. */
export const TYPESAFE_QUESTIONS = {
  is_probe: {
    type: "noul",
    instructions:
      "Is this HTTP request an automated vulnerability probe or abuse attempt " +
      "rather than a legitimate API client call?",
    criteria: {
      true:
        "The request carries traversal sequences, injection payloads, scanner user agents, or targets " +
        "paths that only exist to be probed; a legitimate client of this API would not send it.",
      false:
        "The request looks like an ordinary API call: a plausible path, ordinary parameter names and a " +
        "conventional client user agent, even if one heuristic fired by coincidence.",
    },
  },
  category: {
    type: "choice",
    instructions: "What kind of request is this?",
    criteria: {
      benign: "Ordinary API traffic that was flagged by coincidence.",
      traversal: "An attempt to escape the intended path with ../ or an encoded equivalent.",
      injection: "SQL, shell or template injection payloads in the path or query.",
      enumeration: "Scanning for hidden endpoints, admin panels, backup files or identifiers.",
      credential_abuse: "Repeated or malformed authentication attempts, token stuffing or key guessing.",
      other: null,
    },
  },
} as const;

export interface TypeSafeAnswers {
  is_probe?: { noul?: number };
  category?: { choice?: string; probabilities?: Record<string, number>; confidence?: number };
}

export interface TypeSafeJudgement {
  model?: string;
  answers?: TypeSafeAnswers;
  usage?: unknown;
  /** Set instead of `answers` when the call failed; kept so evidence shows the attempt. */
  error?: string;
}

/** Builds the sanitised state. Query values and bodies are deliberately not representable here. */
export function buildTypeSafeState(
  request: Request,
  url: URL,
  signals: string[],
  principalKind: string,
  statusReturned: number,
): TypeSafeState {
  const queryKeys = [...new Set(url.searchParams.keys())].slice(0, MAX_QUERY_KEYS);
  const userAgent = request.headers.get("User-Agent");
  return {
    method: request.method.toUpperCase(),
    path: url.pathname,
    query_keys: queryKeys,
    user_agent: userAgent ? userAgent.slice(0, MAX_USER_AGENT_LENGTH) : null,
    flagged_signals: [...signals],
    principal_kind: principalKind,
    status_returned: statusReturned,
  };
}

/** Calls TypeSafe. Returns null when TYPESAFE_API_KEY is not set; never throws. */
export async function judgeWithTypeSafe(env: Env, state: TypeSafeState): Promise<TypeSafeJudgement | null> {
  if (!env.TYPESAFE_API_KEY) return null;
  try {
    const response = await fetch(TYPESAFE_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.TYPESAFE_API_KEY}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ state, model: TYPESAFE_MODEL, questions: TYPESAFE_QUESTIONS }),
      signal: AbortSignal.timeout(TYPESAFE_TIMEOUT_MS),
    });
    if (!response.ok) {
      logEvent("warn", "typesafe_http_error", { status: response.status });
      return { error: `typesafe_http_${response.status}` };
    }
    const body = (await response.json()) as { model?: string; answers?: TypeSafeAnswers; usage?: unknown };
    return { model: body.model, answers: body.answers, usage: body.usage };
  } catch (err) {
    logEvent("warn", "typesafe_call_failed", { error: String(err) });
    return { error: "typesafe_unreachable" };
  }
}

/** The `is_probe` probability from a judgement, or null when absent/invalid. */
export function probeProbability(judgement: TypeSafeJudgement | null): number | null {
  const p = judgement?.answers?.is_probe?.noul;
  return typeof p === "number" && Number.isFinite(p) ? p : null;
}

export function autoblockThreshold(env: Env): number {
  const t = envNumber(env.TYPESAFE_BLOCK_THRESHOLD, 0.95);
  return Math.min(Math.max(t, 0), 1);
}

export function autoblockTtlSeconds(env: Env): number {
  return Math.max(Math.round(envNumber(env.TYPESAFE_BLOCK_TTL_SECONDS, 900)), MIN_TTL_SECONDS);
}

export interface AutoblockDecision {
  enabled: boolean;
  threshold: number;
  probability: number | null;
  apply: boolean;
}

/** Pure gating: autoblock flag on, DENYLIST bound, and is_probe at or above the threshold. */
export function decideAutoblock(env: Env, judgement: TypeSafeJudgement | null): AutoblockDecision {
  const enabled = env.TYPESAFE_AUTOBLOCK === "1" && env.DENYLIST !== undefined;
  const threshold = autoblockThreshold(env);
  const probability = probeProbability(judgement);
  return { enabled, threshold, probability, apply: enabled && probability !== null && probability >= threshold };
}

/**
 * Writes the principal key to DENYLIST with the configured TTL. Never throws;
 * returns whether the entry was actually written, so the evidence row can record
 * the outcome rather than the intent.
 */
export async function applyAutoblock(
  env: Env,
  principalKey: string,
  decision: AutoblockDecision,
  requestId: string,
): Promise<boolean> {
  if (!decision.apply || !env.DENYLIST) return false;
  const ttl = autoblockTtlSeconds(env);
  try {
    await env.DENYLIST.put(
      principalKey,
      JSON.stringify({ request_id: requestId, is_probe: decision.probability, at: new Date().toISOString() }),
      { expirationTtl: ttl },
    );
    logEvent("warn", "autoblock_applied", { request_id: requestId, principal_key: principalKey, ttl });
    return true;
  } catch (err) {
    logEvent("error", "autoblock_failed", { request_id: requestId, error: String(err) });
    return false;
  }
}

/** Hot-path check: one KV get when the binding exists, otherwise nothing. Fails open. */
export async function isDenied(env: Env, principalKey: string): Promise<boolean> {
  if (!env.DENYLIST) return false;
  try {
    return (await env.DENYLIST.get(principalKey)) !== null;
  } catch (err) {
    logEvent("warn", "denylist_read_failed", { error: String(err) });
    return false;
  }
}
