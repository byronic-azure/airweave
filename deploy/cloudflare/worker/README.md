# airweave-edge-gateway (Cloudflare Worker)

Edge gateway that sits in front of the Cloudflare Tunnel to a local Airweave
backend. The main write-up (architecture, tunnel, Kubernetes side) lives in
`deploy/cloudflare/README.md`; this file only covers the Worker.

```
client -> Worker (auth, rate limit, heuristics) -> ORIGIN_URL (tunnel hostname,
          Access application that only admits the Worker's service token)
       -> cloudflared in Docker Desktop Kubernetes -> Airweave backend :8001
```

## Request pipeline

1. `GET /healthz` answers `{ok, service, version}` with no authentication.
2. CORS: exact-match allowlist from `ALLOWED_ORIGINS`; preflights get 204 (403
   for an origin outside the list); every response carries `Vary: Origin`, and
   upstream `Access-Control-*` headers are replaced by the gateway's own.
3. Hard heuristics, before authentication (plain and single-encoded `..` are already
   resolved by Cloudflare before the Worker runs): path traversal (`..`, `..;`, and
   percent/double-encoded forms), null bytes, methods outside
   GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD. These answer 400 and record evidence,
   within the per-IP escalation budget described under "Evidence log".
4. Authentication per `AUTH_MODE` (below). Missing credentials give 401,
   rejected ones 403, a misconfiguration 500. A soft-flagged request that fails
   here is still recorded, under the anonymous (client IP) principal.
5. Denylist: one KV read when `DENYLIST` is bound; a listed principal gets 403
   (a soft-flagged one is still recorded).
6. Rate limit through the Workers rate limiting binding, keyed by the principal
   (JWT email/subject, SHA-256 of the API key, or the client IP in dev mode).
   Over the limit: 429 with `Retry-After` and an evidence row. Without the
   binding every response carries `X-Airweave-RateLimit: disabled`.
7. `GET /evidence/verify` (authenticated) walks the evidence chain.
8. Everything else is proxied to `ORIGIN_URL` + path + query with the body
   streamed both ways. Soft signals (injection-looking path/query, scanner user
   agents, very long URLs/headers, CRLF or malformed encoding) never block: they
   are forwarded to the origin as `X-Airweave-Suspicion`, recorded as evidence,
   and optionally judged by TypeSafe. The client never sees that header.

Every response carries `X-Request-Id`; the same id is sent upstream so backend
logs and evidence rows can be joined.

### Header hygiene toward the origin

Hop-by-hop headers, `Host`, and every incoming `cf-access-*` header are dropped
(so nobody can smuggle a service token or a forged assertion through the
gateway), as are the gateway API key and client-supplied `X-Request-Id`,
`X-Forwarded-*`, `X-Real-IP`, `Forwarded` and `X-Airweave-Suspicion`. The Worker
then adds `CF-Access-Client-Id/Secret` from its secrets, `X-Request-Id`,
`X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Forwarded-For` set to
`CF-Connecting-IP` alone (omitted when that header is absent), so the client IP
the backend logs is the one Cloudflare saw, never one the caller chose.
`CF_*` cookies are dropped in both directions: a client-supplied Access cookie
never reaches the origin, and the `CF_Authorization` session cookie Access mints
for the origin hostname (unless "Strict service token authentication" is on) is
never relayed to the client, where it would be a bearer credential for the
origin that bypasses the Worker.

## Authentication modes

| `AUTH_MODE`  | What is checked                                                                                                                                 |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `access-jwt` | Default. `Cf-Access-Jwt-Assertion` is verified with jose against `TEAM_DOMAIN/cdn-cgi/access/certs`, issuer `TEAM_DOMAIN`, audience `POLICY_AUD`. |
| `api-key`    | `X-Airweave-Gateway-Key` is compared to the `GATEWAY_API_KEY` secret in constant time.                                                           |
| `off`        | No check. Only honoured when `ALLOW_INSECURE_DEV` is exactly `1`; otherwise every request gets a 500 explaining the misconfiguration. Responses carry `X-Airweave-Gateway-Auth: off`. |

`access-jwt` is for a gateway hostname that is itself an Access application
(browser users log in through Access, which injects the assertion). `api-key`
is for machine clients that cannot do the Access flow.

Because Access answers before the Worker runs, the Access application on the
gateway hostname needs two settings in `access-jwt` mode (neither applies to
`api-key`): **Bypass OPTIONS requests to origin** under Advanced settings → CORS
settings, or Access answers every cross-origin preflight with 403 and
`ALLOWED_ORIGINS` never gets a say; and an exemption for `/healthz`, which is
otherwise a 302 to the login page for anonymous callers: a path-scoped
application `api.<zone>/healthz` with one Bypass policy, or a Service Auth policy
whose token the health check sends (`check.sh` forwards `CF_ACCESS_CLIENT_ID` /
`CF_ACCESS_CLIENT_SECRET`). Details in `deploy/cloudflare/README.md`, step 5.

## Configuration

Plain values live in `wrangler.jsonc` `"vars"`; secrets are set with
`wrangler secret put` (locally: `.dev.vars`, see `.dev.vars.example`).
`../scripts/edge.sh up --zone <zone>` provisions every binding and secret below,
writes the account values into `wrangler.jsonc` and deploys; see
`deploy/cloudflare/README.md`, "One command".

| Name                          | Kind    | Purpose                                                                 |
|-------------------------------|---------|-------------------------------------------------------------------------|
| `ORIGIN_URL`                  | var     | Tunnel public hostname, e.g. `https://airweave-origin.<zone>`.          |
| `ALLOWED_ORIGINS`             | var     | Comma-separated browser origins (`*` allows all, without credentials).  |
| `AUTH_MODE`                   | var     | `access-jwt`, `api-key` or `off`.                                       |
| `TEAM_DOMAIN`, `POLICY_AUD`   | var     | Access team domain and the gateway application's AUD tag.               |
| `ALLOW_INSECURE_DEV`          | var     | `1` to permit `AUTH_MODE=off`. Never in production.                     |
| `RATE_LIMIT_PERIOD_SECONDS`   | var     | `Retry-After` hint; keep equal to the binding's `simple.period`.        |
| `TYPESAFE_AUTOBLOCK`          | var     | `1` enables autoblock (default label-only).                             |
| `TYPESAFE_BLOCK_THRESHOLD`    | var     | Minimum `is_probe` probability for autoblock (default 0.95).            |
| `TYPESAFE_BLOCK_TTL_SECONDS`  | var     | Denylist entry lifetime (default 900, KV minimum 60).                   |
| `ORIGIN_SERVICE_TOKEN_ID`     | secret  | Access service token for the tunnel's Access application.               |
| `ORIGIN_SERVICE_TOKEN_SECRET` | secret  | Its secret.                                                             |
| `GATEWAY_API_KEY`             | secret  | Shared key for `AUTH_MODE=api-key`.                                     |
| `TYPESAFE_API_KEY`            | secret  | Enables TypeSafe judgements when set.                                   |
| `RATE_LIMITER`                | binding | `ratelimits` entry (Workers Rate Limiting); optional.                   |
| `DENYLIST`                    | binding | KV namespace for autoblock; optional. `wrangler kv namespace create airweave-edge-denylist`. |
| `EVIDENCE_DB`                 | binding | D1 database for the evidence log; optional. `wrangler d1 create airweave-edge-evidence`, then `wrangler d1 migrations apply airweave-edge-evidence --remote`. |

The placeholder ids in `wrangler.jsonc` (`REPLACE_ME`) work for local dev and
tests; `edge.sh up` replaces them, or paste real ids before `npm run deploy`.

## Evidence log

Blocked, rate-limited and soft-flagged requests (never ordinary traffic) are
appended to `evidence_events` from `ctx.waitUntil`, after the client has its
response. Rows are hash-chained: `hash = SHA-256(prev_hash + "\n" +
canonical JSON of the row without hash)`, starting from 64 zeros, with `seq`
chosen as head + 1 under a unique index on `prev_hash`, so two writers can never
fork the chain. Appends inside one isolate are serialised through a queue and a
writer in another isolate is absorbed by jittered retries, so a burst of flagged
requests lands as one row each; a row that still cannot be written is logged in
full (`evidence_write_failed`, `dropped: true`), never discarded silently.
`GET /evidence/verify` returns `{ok, count, head}` and, on a problem, `break_at`
plus a reason (`hash_mismatch`, `chain_break`, `sequence_gap`).

Escalations of rejected requests (400 from the hard rules, 401/403 carrying
soft signals) are bounded per principal key by the rate limiter and the
denylist, keyed exactly like proxied traffic (`ip:<CF-Connecting-IP>` before
authentication): over the budget the request is still rejected, but no TypeSafe
call and no D1 append happen and an `escalation_suppressed` log line stands in
for the row. Without those bindings every rejection is escalated.

The chain is a consistency check, not proof of integrity: `verifyChain`
recomputes every digest from the genesis value and localises an in-place edit,
a re-linked row or a gap, but it cannot see the tail being truncated (the next
append reuses the freed `seq`) or a full recompute by anyone with D1 write
access, since the chain carries no secret and no external anchor. Keep the head
`{seq, hash}` from `/evidence/verify` (or the `evidence_recorded` log lines)
outside D1 and compare on the next verify. Rows keep the path and query of the
offending request, so treat the database as sensitive. Without `EVIDENCE_DB`
the record is written to the console (`wrangler tail`) instead.

## TypeSafe (optional, verify-and-escalate)

When `TYPESAFE_API_KEY` is set, each flagged request is also sent to
TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`, model
`jev-latest`) from `ctx.waitUntil`. The state is a sanitised summary (method,
path, query parameter names, user agent, the signals, principal kind, status
returned); bodies, secrets, tokens and query values are never sent. Two
questions are asked: `is_probe` (a yes-probability) and `category` (benign,
traversal, injection, enumeration, credential_abuse, other). The raw answers
are stored in `judgement_json` on the evidence row.

TypeSafe answers are calibrated probabilities, not proof. The default is
label-only: a human reviews the evidence table. Autoblock is opt-in and gated
three ways: `TYPESAFE_AUTOBLOCK=1`, a bound `DENYLIST`, and `is_probe` at or
above `TYPESAFE_BLOCK_THRESHOLD`. It then denies the principal key for
`TYPESAFE_BLOCK_TTL_SECONDS`. The KV write happens before the evidence row is
sealed, and `judgement_json.autoblock` records `requested` (the gate fired) and
`applied` (the write succeeded) separately, so a failed write is never recorded
as a block. Hard-blocked and unauthenticated requests arrive before
authentication, so their key is the client IP: such an entry denies proxied
traffic only when the IP is the principal (`AUTH_MODE=off`), but it always
stops further rejected requests from that IP being escalated until the TTL
expires (see the escalation budget above). Access-JWT principals that carry a
user identity (an `email` claim) are never autoblocked, only labelled: a
cross-site GET carries the victim's Access cookie, so a third party could
otherwise get another user denied; the evidence row and judgement still land,
and an operator can write the key by hand. Access service tokens (assertions
with only `common_name`) stay eligible like `apikey:` principals, because a
browser cannot be made to send `CF-Access-Client-Id`/`-Secret` cross-site.

## Develop and test

`npm install`, `npm run dev` (applies the local D1 migrations first, then serves
http://localhost:8787/healthz), `npm test`, `npm run typecheck`, `npm run deploy`.
`npm test` also runs `node --test` over `scripts/test/`, which drives the
`edge.mjs` orchestrator against an in-memory Cloudflare API; `npm run typecheck`
checks `scripts/*.mjs` (JSDoc types) under `strict` as well as the Worker.
Tests run inside workerd through `@cloudflare/vitest-pool-workers` with a local D1
(migrations applied from `migrations/`) and KV; outbound `fetch` is stubbed, so no
network is needed.
`.npmrc` pins legacy peer resolution because wrangler 4 declares an optional peer
on `@cloudflare/workers-types` v5 while this package pins v4; the lockfile is
reproducible with `npm ci`.

## Notes and limits

- Rate limits are per Cloudflare location and approximate; use them as a
  safety valve, not as billing-grade accounting. A limiter error fails open.
- Soft signals are deliberately loose; a false positive costs one evidence row
  (and a TypeSafe call when enabled), never a blocked request.
- TypeSafe spend and D1 writes for rejected requests are bounded by the
  escalation budget (the rate limiter's `simple.limit` per period per principal
  key, and the denylist). Rate-limited (429) requests are budgeted under a
  separate `esc:<principal key>` limiter key, so a flood of 429s records at most
  `simple.limit` judgements and rows per period (the rest log
  `escalation_suppressed` with `why: escalation_budget`). Only proxied-but-flagged
  requests from an authenticated principal are still escalated one for one.
- `AUTH_ENABLED=true` must be set in Airweave's own `.env`. The tunnel bypasses
  any control that exists only in front of it, exactly as with the MicroK8s
  NodePort setup.
