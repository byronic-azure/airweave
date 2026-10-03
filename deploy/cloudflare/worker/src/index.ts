/**
 * airweave-edge-gateway
 *
 * Request pipeline (see deploy/cloudflare/worker/README.md):
 *
 *   GET /healthz            -> 200, no auth
 *   OPTIONS *               -> CORS preflight (allowlist from ALLOWED_ORIGINS)
 *   hard heuristics         -> 400 + evidence (traversal, null byte, bad method)
 *   authenticate            -> 401/403/500 per AUTH_MODE (+ evidence when soft-flagged)
 *   denylist (optional KV)  -> 403 (+ evidence when soft-flagged)
 *   rate limit (optional)   -> 429 + evidence
 *   GET /evidence/verify    -> chain verification (auth required)
 *   proxy to ORIGIN_URL     -> streamed response; soft signals -> evidence
 *
 * Evidence writes and TypeSafe judgements run in `ctx.waitUntil`, after the
 * client already has its response, and only for flagged requests. Escalations of
 * rejected requests (400, 401/403) are bounded per principal key by the rate
 * limiter and the denylist, so an unauthenticated flood cannot run up TypeSafe
 * calls and D1 appends without limit.
 */
import { GATEWAY_AUTH_HEADER, anonymousPrincipal, authMode, authenticate, type Principal } from "./auth";
import { decideCors, preflightResponse, withCorsHeaders, type CorsDecision } from "./cors";
import type { Env } from "./env";
import { recordEvidence, verifyChain, type Verdict } from "./evidence";
import { inspectRequest } from "./heuristics";
import { REQUEST_ID_HEADER, proxyToOrigin } from "./proxy";
import { RATE_LIMIT_HEADER, checkRateLimit, rateLimitedResponse } from "./ratelimit";
import { applyAutoblock, buildTypeSafeState, decideAutoblock, isDenied, judgeWithTypeSafe } from "./typesafe";
import { SERVICE_NAME, VERSION, clientIp, jsonError, jsonResponse, logEvent } from "./util";

/** Query strings are kept on evidence rows (they are the evidence) but capped. */
const MAX_EVIDENCE_PATH_LENGTH = 1024;

interface RequestContext {
  requestId: string;
  url: URL;
  cors: CorsDecision;
  rateLimitDisabled: boolean;
  authOff: boolean;
}

interface Escalation {
  principal: Principal;
  signals: string[];
  verdict: Verdict;
  reason: string;
  statusReturned: number;
}

/** Judge (optional), apply autoblock, then record evidence. Runs inside ctx.waitUntil. */
async function escalate(request: Request, env: Env, rc: RequestContext, e: Escalation): Promise<void> {
  const judgement = env.TYPESAFE_API_KEY
    ? await judgeWithTypeSafe(env, buildTypeSafeState(request, rc.url, e.signals, e.principal.kind, e.statusReturned))
    : null;
  const autoblock = decideAutoblock(env, judgement);
  // The KV write goes first so the hash-chained row records what actually
  // happened to the denylist (`applied`), not only what was decided (`requested`).
  const applied = await applyAutoblock(env, e.principal.key, autoblock, rc.requestId);
  await recordEvidence(env, {
    requestId: rc.requestId,
    principal: e.principal.id,
    clientIp: clientIp(request),
    method: request.method.toUpperCase(),
    path: (rc.url.pathname + rc.url.search).slice(0, MAX_EVIDENCE_PATH_LENGTH),
    reason: e.reason,
    verdict: e.verdict,
    judgement:
      judgement === null
        ? undefined
        : { ...judgement, autoblock: { requested: autoblock.apply, applied, threshold: autoblock.threshold } },
  });
}

/**
 * Whether a rejected request may still be escalated. The same optional bindings
 * that gate proxied traffic gate escalations, keyed on the same principal key:
 * a denylisted or rate-limited key gets its 4xx but no TypeSafe call and no D1
 * append, with one log line standing in for the evidence row. Without the
 * bindings every rejection is escalated. `checkDenylist` is false when the caller
 * already knows the principal is denied.
 */
async function escalationAllowed(
  env: Env,
  principal: Principal,
  requestId: string,
  checkDenylist: boolean,
): Promise<boolean> {
  const suppressed = (why: string): false => {
    logEvent("warn", "escalation_suppressed", { request_id: requestId, principal_key: principal.key, why });
    return false;
  };
  if (checkDenylist && (await isDenied(env, principal.key))) return suppressed("principal_denied");
  if ((await checkRateLimit(env.RATE_LIMITER, principal.key)) === "limited") return suppressed("rate_limited");
  return true;
}

/** Escalates a rejected request in the background, within the principal's escalation budget. */
async function escalateRejection(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  rc: RequestContext,
  e: Escalation,
  checkDenylist: boolean,
): Promise<void> {
  if (await escalationAllowed(env, e.principal, rc.requestId, checkDenylist)) {
    ctx.waitUntil(escalate(request, env, rc, e));
  }
}

function softEscalation(principal: Principal, soft: string[], statusReturned: number): Escalation {
  return { principal, signals: soft, verdict: "flagged", reason: `soft:${soft.join(",")}`, statusReturned };
}

/** Stamps the per-response headers every reply carries, including CORS. */
function finalize(response: Response, request: Request, rc: RequestContext): Response {
  const out = withCorsHeaders(response, rc.cors, request);
  out.headers.set(REQUEST_ID_HEADER, rc.requestId);
  if (rc.rateLimitDisabled) out.headers.set(RATE_LIMIT_HEADER, "disabled");
  if (rc.authOff) out.headers.set(GATEWAY_AUTH_HEADER, "off");
  return out;
}

async function handle(request: Request, env: Env, ctx: ExecutionContext, rc: RequestContext): Promise<Response> {
  const { url, requestId } = rc;
  const method = request.method.toUpperCase();

  if (url.pathname === "/healthz" && (method === "GET" || method === "HEAD")) {
    return jsonResponse({ ok: true, service: SERVICE_NAME, version: VERSION });
  }
  if (method === "OPTIONS") return preflightResponse(rc.cors, request, requestId);

  const inspection = inspectRequest(request, url);
  if (inspection.hard.length > 0) {
    const escalation: Escalation = {
      principal: anonymousPrincipal(request),
      signals: [...inspection.hard, ...inspection.soft],
      verdict: "blocked",
      reason: `hard:${inspection.hard.join(",")}`,
      statusReturned: 400,
    };
    await escalateRejection(request, env, ctx, rc, escalation, true);
    return jsonError(400, "bad_request", "Request rejected by gateway rules", requestId, {
      reasons: inspection.hard,
    });
  }

  const auth = await authenticate(request, env, requestId);
  if (!auth.ok) {
    // A scanner rarely carries credentials: soft signals on a request that could
    // not authenticate are still evidence, keyed by client IP like a hard block.
    if (inspection.soft.length > 0) {
      const escalation = softEscalation(anonymousPrincipal(request), inspection.soft, auth.response.status);
      await escalateRejection(request, env, ctx, rc, escalation, true);
    }
    return auth.response;
  }
  const { principal } = auth;

  if (await isDenied(env, principal.key)) {
    logEvent("warn", "principal_denied", { request_id: requestId, principal: principal.id });
    if (inspection.soft.length > 0) {
      await escalateRejection(request, env, ctx, rc, softEscalation(principal, inspection.soft, 403), false);
    }
    return jsonError(403, "principal_denied", "This principal is temporarily denied", requestId);
  }

  const limit = await checkRateLimit(env.RATE_LIMITER, principal.key);
  if (limit === "limited") {
    ctx.waitUntil(
      escalate(request, env, rc, {
        principal,
        signals: ["rate_limit_exceeded", ...inspection.soft],
        verdict: "rate_limited",
        reason: "rate_limit_exceeded",
        statusReturned: 429,
      }),
    );
    return rateLimitedResponse(env, requestId);
  }

  if (url.pathname === "/evidence/verify" && (method === "GET" || method === "HEAD")) {
    if (!env.EVIDENCE_DB) {
      return jsonError(503, "evidence_db_not_configured", "EVIDENCE_DB binding is not set", requestId);
    }
    try {
      return jsonResponse(await verifyChain(env.EVIDENCE_DB));
    } catch (err) {
      if (!/no such table/i.test(String(err))) throw err;
      return jsonError(
        503,
        "evidence_db_not_migrated",
        "Run `wrangler d1 migrations apply airweave-edge-evidence` (add --local for wrangler dev)",
        requestId,
      );
    }
  }

  const response = await proxyToOrigin(request, env, { requestId, suspicion: inspection.soft });
  if (inspection.soft.length > 0) {
    ctx.waitUntil(escalate(request, env, rc, softEscalation(principal, inspection.soft, response.status)));
  }
  return response;
}

// workerd only accepts handlers or entrypoint classes as named exports of the
// entry module, so this file deliberately exports nothing but the handler.
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const rc: RequestContext = {
      requestId: crypto.randomUUID(),
      url: new URL(request.url),
      cors: decideCors(request, env),
      rateLimitDisabled: env.RATE_LIMITER === undefined,
      authOff: authMode(env) === "off" && env.ALLOW_INSECURE_DEV === "1",
    };
    try {
      return finalize(await handle(request, env, ctx, rc), request, rc);
    } catch (err) {
      logEvent("error", "unhandled_error", { request_id: rc.requestId, error: String(err) });
      return finalize(jsonError(500, "gateway_error", "Unexpected gateway error", rc.requestId), request, rc);
    }
  },
} satisfies ExportedHandler<Env>;
