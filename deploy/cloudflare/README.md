# Airweave behind Cloudflare Workers and a Cloudflare Tunnel

Expose an Airweave backend that runs on a developer laptop (docker compose under
Docker Desktop) through Cloudflare, without opening a single inbound port:

- a `cloudflared` Deployment in Docker Desktop's built-in Kubernetes dials out to a
  Cloudflare Tunnel and forwards traffic to the backend on port 8001;
- the tunnel's public hostname is locked by a Cloudflare Access application whose
  only policy admits one **Service Token**;
- the Worker `airweave-edge-gateway` holds that token and is the only way in. It
  authenticates callers, rate-limits them, screens requests with cheap heuristics,
  proxies to the tunnel, and records blocked or suspicious requests in a
  hash-chained evidence log (optionally judged by TypeSafe).

Everything lives under `deploy/cloudflare/`:

```
deploy/cloudflare/
├── README.md                this file: architecture, setup, security model
├── worker/                  the Worker (TypeScript, wrangler, vitest) + worker/README.md
│   └── scripts/edge.mjs     the one-command orchestrator behind scripts/edge.sh
├── k8s/
│   ├── base/                namespace, cloudflared Deployment, the two backend Services
│   └── overlays/
│       ├── token/           remotely-managed tunnel (default): Secret cloudflared-token
│       └── config/          locally-managed tunnel: config.yml, Secret cloudflared-credentials
└── scripts/
    ├── edge.sh              ONE COMMAND: provision, deploy, connect, smoke-test (up/plan/status/down)
    ├── up.sh                kubectl apply -k <overlay>, wait for the tunnel to connect
    ├── down.sh              remove the connector (keeps Secrets and namespace unless asked)
    ├── check.sh             pod Ready, /ready, gateway /healthz, Access on origin, backend
    ├── validate.sh          cluster-free validation (render, schema, ingress, shellcheck)
    └── check_manifests.py   structural checks used by validate.sh
```

The sibling `deploy/microk8s/` exposes the same backend through NodePorts and Brev
Secure Links instead; this directory is the alternative for laptops with no public
ingress at all. Naming is shared on purpose: namespace `airweave`, Service
`airweave-backend`, label `app.kubernetes.io/part-of=airweave`.

## Architecture

The shape is fixed; the knobs are the hostnames, the auth mode and where the
backend runs (mode A or B).

```
                              Internet client
                                     |
                      https://api.<zone>/...        Worker route or custom domain
                                     |              (access-jwt mode: an Access app
                                     v               in front of this hostname too)
   +---------------------------------------------------------------------+
   |  Cloudflare edge: Worker "airweave-edge-gateway"                    |
   |    GET /healthz (no auth)  ->  CORS allowlist  ->  hard rules (400)  |
   |    -> AUTH_MODE access-jwt | api-key | off  ->  DENYLIST (KV)        |
   |    -> RATE_LIMITER (429)  ->  proxy, response streamed back          |
   |    flagged requests only: EVIDENCE_DB (D1 hash chain), TypeSafe      |
   +----------------------------------+----------------------------------+
                                      |  fetch(ORIGIN_URL + path + query)
                                      |  + CF-Access-Client-Id / -Secret
                                      v
                   https://airweave-origin.<zone>   Access application:
                                      |             one policy, action "Service Auth",
                                      |             allows exactly one Service Token
                                      v
                             Cloudflare Tunnel
                                      |  outbound-only connection from the laptop
   ...................................|......... developer laptop ...................
   :                                  v                                             :
   :  Docker Desktop Kubernetes (kube context "docker-desktop"), namespace airweave  :
   :                                                                                :
   :    Deployment cloudflared  --tunnel route-->                                   :
   :        mode A: airweave-backend-host.airweave.svc.cluster.local:8001           :
   :                (ExternalName -> host.docker.internal -> compose port 8001)     :
   :        mode B: airweave-backend.airweave.svc.cluster.local:8001                :
   :                (ClusterIP, selector app: airweave-backend, backend in-cluster) :
   :                                  |                                             :
   :                                  v                                             :
   :    docker compose (./start.sh): Airweave backend, 8001:8001 on the host        :
   :    Airweave .env: AUTH_ENABLED=true                                            :
   :................................................................................:
```

Request path, in order (details in `worker/README.md`): `/healthz` → CORS preflight →
hard heuristics (traversal, null byte, bad method: 400 before any auth) → `AUTH_MODE`
→ denylist (one KV read, only when bound) → rate limit → `/evidence/verify` → proxy.
Evidence rows, TypeSafe judgements and autoblock run in `ctx.waitUntil` after the
client has its response, and only for blocked, rate-limited or soft-flagged requests.

## One command

`scripts/edge.sh up` performs every step of the manual setup below, in order, and is
safe to re-run: each step reads what already exists and changes only what differs.

```bash
# Prerequisites: Docker Desktop with Kubernetes enabled (step 1), Airweave running
# with AUTH_ENABLED=true (step 2), Node 22, and a zone on Cloudflare with Zero Trust on.
export CLOUDFLARE_API_TOKEN=...                                  # permissions below

deploy/cloudflare/scripts/edge.sh plan --zone example.com        # what `up` would do; changes nothing
deploy/cloudflare/scripts/edge.sh up   --zone example.com        # do it, then smoke-test the path
deploy/cloudflare/scripts/edge.sh status                         # re-check later; flags are remembered
deploy/cloudflare/scripts/edge.sh down --yes                     # remove what `up` created
```

Without bash (plain Windows), run `npm --prefix deploy/cloudflare/worker ci` once, then
`npm --prefix deploy/cloudflare/worker run edge -- up --zone example.com`.

What `up` does, in order (the last column is the manual step it replaces):

| Stage | What happens | Step |
|-------|--------------|------|
| Preflight | The kube context answers. In mode A the backend answers `/health/ready` and refuses an anonymous `/collections/count`; `up` stops if it does not (`AUTH_ENABLED=false` would publish an open API). | 1, 2 |
| Tunnel | Remotely-managed tunnel `airweave-origin`; ingress `airweave-origin.<zone>` → the in-cluster backend Service (rules for other hostnames are kept); proxied CNAME. A DNS record that points elsewhere is never overwritten. | 3 |
| Origin lock | Access service token, a reusable Service Auth policy that admits only it, and a self-hosted Access application on the origin hostname. Other policies on that application are reported. | 4 |
| Gateway auth | `--auth api-key` (default): a 256-bit `GATEWAY_API_KEY`. `--auth access-jwt`: an Allow policy from `--allow-email` / `--allow-email-domain`, an Access application on `api.<zone>`, a Bypass application on `api.<zone>/healthz`, and `TEAM_DOMAIN` / `POLICY_AUD` from them. | 5 |
| Bindings | KV namespace `airweave-edge-denylist` and D1 database `airweave-edge-evidence`, found by name or created; checks that `api.<zone>` is free for a Workers Custom Domain. | 6 |
| Config | Writes the account values (routes, vars, binding ids) into `worker/wrangler.jsonc` with comments and layout kept, so a later plain `npm run deploy` keeps working. | 7, 9 |
| Deploy | Remote D1 migrations, then one `wrangler deploy --secrets-file`: code and secrets go live as one version, through a 0600 file that is deleted afterwards. | 7, 8 |
| Connector | Secret `cloudflared-token` through `kubectl apply -f -` (stdin, never argv), overlay `k8s/overlays/token`, a restart when the token changed, and a wait for the rollout. | 3 |
| Verify | Tunnel healthy; the origin refuses a request without the token and serves one with it; the gateway answers `/healthz`, rejects anonymous calls and, in api-key mode, serves an authenticated request end to end and an intact `/evidence/verify`. | 10 |

**Credentials and state.** Cloudflare shows a service token secret once, so `up` keeps
it, the gateway key and the ids of everything it created in
`deploy/cloudflare/.edge/state.json` (mode 0600, gitignored). If that file is lost, the
next `up` rotates the token secret and issues a new gateway key instead of duplicating
resources. `down` deletes only what `up` created; the KV denylist and the D1 evidence
log survive unless you add `--delete-data`.

**API token permissions** (dash.cloudflare.com → My Profile → API Tokens → Create
custom token): Account → Cloudflare Tunnel: Edit, Access: Apps and Policies: Edit,
Access: Service Tokens: Edit, Access: Organizations, Identity Providers, and Groups:
Read (Edit with `--strict-service-tokens`), Workers Scripts: Edit, Workers KV Storage:
Edit, D1: Edit, Account Settings: Read; Zone (your zone) → Zone: Read, DNS: Edit,
Workers Routes: Edit. `wrangler` reuses the same token, so no `wrangler login` is needed.

**Choices worth knowing.** `--strict-service-tokens` turns on Access strict service
token authentication for the whole Zero Trust organization (Cloudflare's recommended
setting; without it Access hands the Worker a `CF_Authorization` cookie, which the
Worker drops). `--backend cluster` routes the tunnel to an in-cluster `airweave-backend`
Service (mode B). `--skip-k8s` leaves Kubernetes alone when cloudflared runs elsewhere.
`edge.sh help` lists every flag.

## Manual setup (what `edge.sh up` automates)

Use these steps to understand the moving parts, to set up one piece by hand, or when
the API token cannot be given the permissions above.

You need: Docker Desktop, Node 22 (`npx wrangler` is used throughout), a Cloudflare
zone (a domain whose DNS is on Cloudflare) and Zero Trust enabled on the account (the
free plan is enough). `<zone>` below is that domain; `<team>` is your Zero Trust team
name (`https://<team>.cloudflareaccess.com` is the **team domain**).

### 1. Docker Desktop: enable Kubernetes

1. Docker Desktop → Settings → Kubernetes → **Enable Kubernetes** → Apply. Docker
   Desktop installs `kubectl` and a kube context named `docker-desktop`.
2. Check it: `kubectl --context docker-desktop get nodes` shows one Ready node.

Every script here pins `--context docker-desktop` (override with `-c` or
`KUBE_CONTEXT`), so a stray current-context never receives the apply. From inside
pods, `host.docker.internal` resolves to the laptop, which is how mode A reaches the
compose backend.

### 2. Airweave with authentication on

1. `cp .env.example .env` (repo root) and set **`AUTH_ENABLED=true`** plus the Auth0
   values it requires (`AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_RULE_NAMESPACE`).
   See [Security model](#security-model) for why this is not optional.
2. `./start.sh` (or `./start.sh --skip-frontend`). `docker/docker-compose.yml`
   publishes the backend as `8001:8001` on the host.
3. Check it: `curl -s http://localhost:8001/health/ready`.

### 3. Cloudflare Tunnel and the cloudflared connector

Default: a **remotely-managed** tunnel (`k8s/overlays/token`). The tunnel's identity
is a token; its routes live in the dashboard.

1. Zero Trust → Networks → Tunnels → **Create a tunnel** → Cloudflared → name it
   `airweave-origin` → Save. From the install command shown, copy only the token
   (the long string after `--token`).
2. Put the token in the cluster, either as a gitignored file or directly:

   ```bash
   cp deploy/cloudflare/k8s/overlays/token/tunnel-token.example.yaml \
      deploy/cloudflare/k8s/overlays/token/tunnel-token.yaml      # gitignored; paste the token
   # or
   kubectl --context docker-desktop create namespace airweave
   kubectl --context docker-desktop -n airweave create secret generic cloudflared-token \
     --from-literal=TUNNEL_TOKEN='<token>'
   ```

3. Deploy and wait for the tunnel to connect (readiness = `/ready` on the pod's
   metrics port, which only passes with a live edge connection):

   ```bash
   deploy/cloudflare/scripts/up.sh token
   ```

4. Add the route: tunnel → **Public Hostname** → Add a public hostname. Subdomain
   `airweave-origin`, domain `<zone>`, type `HTTP`, URL

   | Mode | URL (the tunnel resolves it inside the cluster)                 |
   |------|------------------------------------------------------------------|
   | A    | `airweave-backend-host.airweave.svc.cluster.local:8001`          |
   | B    | `airweave-backend.airweave.svc.cluster.local:8001`               |

   (full form `http://airweave-backend-host.airweave.svc.cluster.local:8001`).
   Cloudflare creates the DNS record for `airweave-origin.<zone>` with the route.

Alternative: a **locally-managed** tunnel (`k8s/overlays/config`), fully declarative.
`cloudflared tunnel login`, `cloudflared tunnel create airweave-origin` (prints the
UUID and writes `~/.cloudflared/<UUID>.json`), `cloudflared tunnel route dns
airweave-origin airweave-origin.<zone>`; create Secret `cloudflared-credentials` from
that JSON (`--from-file=credentials.json=...`, or the gitignored copy of
`tunnel-credentials.example.yaml`); put the UUID and hostname into
`k8s/overlays/config/config.yml` (mode A rule active, mode B rule commented, final
`http_status:404` catch-all); then `deploy/cloudflare/scripts/up.sh config`. The
ConfigMap name carries a content hash, so editing `config.yml` and re-running `up.sh`
rolls the pod.

### 4. Lock the tunnel hostname to the Worker (Access + Service Token)

1. Zero Trust → Access → Service Auth → **Service Tokens** → Create: name
   `airweave-edge-gateway`, pick a duration. Copy the **Client ID** and **Client
   Secret** now; the secret is shown once. These become the Worker secrets
   `ORIGIN_SERVICE_TOKEN_ID` / `ORIGIN_SERVICE_TOKEN_SECRET` in step 7.
2. Zero Trust → Access → Applications → **Add an application** → Self-hosted. Name
   `airweave-origin`, application domain `airweave-origin.<zone>`.
3. One policy only: action **Service Auth**, include rule **Service Token** = the
   token from step 1. No Allow policy for users: nobody logs in to the origin.
4. Zero Trust → Access controls → Access settings → Manage service tokens → **Strict service token authentication**: turn it
   on. Organisations created on or after 2026-10-05 have it on already; older ones
   have it off, and in that mode Access answers every valid service-token request
   with a `Set-Cookie: CF_Authorization=<JWT>` session cookie for the origin
   hostname and honours that cookie on later requests. The Worker drops any `CF_*`
   cookie in both directions (origin → client and client → origin), but the
   setting is what makes such a cookie worthless if it ever leaked by another path.
5. Check it: `curl -sI https://airweave-origin.<zone>/health/ready` must answer
   302, 401 or 403 (Access refusing). A 200 means the origin bypasses the Worker.
   `check.sh -o https://airweave-origin.<zone>` performs exactly this test, and
   with `ORIGIN_SERVICE_TOKEN_ID`/`ORIGIN_SERVICE_TOKEN_SECRET` exported it also
   sends the token and fails if a `CF_Authorization` cookie comes back.

### 5. Decide who may call the gateway

Pick one `AUTH_MODE` for the Worker:

- **`access-jwt`** (default): the gateway hostname `api.<zone>` is itself an Access
  application. Add a second self-hosted application for `api.<zone>` with an
  **Allow** policy for your users (emails, IdP groups, or a second Service Token for
  machines). Access runs before the Worker, logs the user in, and attaches
  `Cf-Access-Jwt-Assertion` to every request; the Worker verifies it against
  `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` with issuer =
  `TEAM_DOMAIN` and audience = `POLICY_AUD`. Copy the **Application Audience (AUD)
  Tag** from that application's overview; the team domain is under Zero Trust →
  Settings → Custom Pages. Two settings on that application matter, because Access
  answers before the Worker ever runs:
  - **CORS.** Browsers send no cookies on a preflight, so Access answers every
    cross-origin `OPTIONS` with 403 and the Worker's `ALLOWED_ORIGINS` never gets a
    say. On the application: Advanced settings → Cross-Origin Resource Sharing
    (CORS) settings → **Bypass OPTIONS requests to origin**. The Worker then answers
    preflights itself (it never forwards `OPTIONS` upstream), which is the "CORS
    enforced at the origin" that Cloudflare asks for before enabling the bypass.
  - **`/healthz`.** An unauthenticated `curl https://api.<zone>/healthz` gets a 302
    to the login page, not the Worker's JSON. Either add a third self-hosted
    application scoped to the path `api.<zone>/healthz` with a single **Bypass**
    policy (Everyone), or keep the health check authenticated: add a policy of
    action **Service Auth** for a Service Token to the `api.<zone>` application and
    send that token as `CF-Access-Client-Id`/`CF-Access-Client-Secret`; `check.sh`
    forwards `CF_ACCESS_CLIENT_ID`/`CF_ACCESS_CLIENT_SECRET` from the environment.

  Neither applies to `api-key` mode, where nothing sits in front of the Worker.
- **`api-key`**: for machine clients that cannot do the Access flow. Clients send
  `X-Airweave-Gateway-Key`; the Worker compares it in constant time to the secret
  `GATEWAY_API_KEY` (`openssl rand -hex 32`). No Access application is needed on
  `api.<zone>` in this mode.
- **`off`**: only with `ALLOW_INSECURE_DEV = "1"`, for `wrangler dev` against a local
  backend. Every response is stamped `X-Airweave-Gateway-Auth: off`; without the
  flag the Worker answers 500 rather than proxying unauthenticated traffic.

### 6. Create the Worker bindings

```bash
cd deploy/cloudflare/worker
npm install
npx wrangler login
npx wrangler kv namespace create airweave-edge-denylist   # paste id into kv_namespaces[0].id
npx wrangler d1 create airweave-edge-evidence            # paste database_id into d1_databases[0]
npx wrangler d1 migrations apply airweave-edge-evidence --remote
```

The rate limiter needs no resource: the `ratelimits` entry `RATE_LIMITER` in
`wrangler.jsonc` (namespace_id `1001`, 100 requests per 60 s per principal) is created
on deploy. KV and D1 are optional: without `DENYLIST` autoblock is impossible,
without `EVIDENCE_DB` evidence goes to the console (`wrangler tail`). The
`REPLACE_ME` ids work for local dev and tests only.

### 7. Configure vars and secrets

Edit `"vars"` in `wrangler.jsonc`: `"ORIGIN_URL": "https://airweave-origin.<zone>"`,
`ALLOWED_ORIGINS` (browser origins allowed to call the gateway, exact match),
`AUTH_MODE`, and for access-jwt `TEAM_DOMAIN` + `POLICY_AUD`. Then the secrets, which
never go in a file (each command prompts for the value):

```bash
npx wrangler secret put ORIGIN_SERVICE_TOKEN_ID        # Client ID from step 4
npx wrangler secret put ORIGIN_SERVICE_TOKEN_SECRET    # Client Secret from step 4
npx wrangler secret put GATEWAY_API_KEY                # only for AUTH_MODE = "api-key"
npx wrangler secret put TYPESAFE_API_KEY               # optional, enables TypeSafe
```

For `wrangler dev`, copy `.dev.vars.example` to `.dev.vars` (gitignored) instead.

### 8. Deploy the Worker

```bash
npm run typecheck && npm test
npm run deploy
```

`wrangler.jsonc` sets `"workers_dev": false` and `"preview_urls": false`, so the
deploy publishes no `airweave-edge-gateway.<account>.workers.dev` hostname: that
hostname would sit outside the Access application, WAF and rate-limiting rules of
your zone, leaving the Worker's own checks as the only ones. Until step 9 attaches
a route the Worker is therefore deployed but unreachable, which is intended.

### 9. Put the Worker on `api.<zone>`

Either set `routes` in `wrangler.jsonc` before deploying:

```jsonc
"routes": [{ "pattern": "api.<zone>", "custom_domain": true }],          // custom domain: DNS is created for you
// "routes": [{ "pattern": "api.<zone>/*", "zone_name": "<zone>" }],    // route: needs a proxied DNS record
```

or in the dashboard: Workers & Pages → airweave-edge-gateway → Settings → Domains &
Routes → Add. A plain route only receives traffic once `api.<zone>` has a proxied
(orange-cloud) DNS record, e.g. `AAAA 100::`; a custom domain creates the record.

### 10. Verify the whole path

```bash
deploy/cloudflare/scripts/check.sh -u https://api.<zone> -o https://airweave-origin.<zone> -i A
curl -s https://api.<zone>/healthz                       # {"ok":true,"service":"airweave-edge-gateway","version":"0.1.0"}
curl -s -H "X-Airweave-Gateway-Key: $KEY" https://api.<zone>/health/ready        # api-key mode
curl -s -H "X-Airweave-Gateway-Key: $KEY" https://api.<zone>/evidence/verify     # {"ok":true,"count":0,"head":null}
```

In access-jwt mode `api.<zone>` is an Access application, so the plain `/healthz`
call above answers with a 302 to the login page unless you added the `/healthz`
Bypass application (step 5). Otherwise pass a service token the application's
policy allows: `CF_ACCESS_CLIENT_ID=<id> CF_ACCESS_CLIENT_SECRET=<secret>
deploy/cloudflare/scripts/check.sh -u https://api.<zone> ...` and
`curl -s -H "CF-Access-Client-Id: <id>" -H "CF-Access-Client-Secret: <secret>
https://api.<zone>/healthz`.

`check.sh` reports: the pod is Ready, `/ready` on the pod (through a port-forward,
`-p` to change the local port), the gateway's `/healthz`, that the origin refuses
unauthenticated requests, and (`-i A|B`) that a throw-away curl pod inside the
cluster reaches the backend through the Service the tunnel routes to.

## Every variable, secret and binding

Names are the ones used in `worker/src/env.ts`, `worker/wrangler.jsonc`, the
manifests and the scripts. Required unless marked optional.

### Worker: plain configuration (`worker/wrangler.jsonc` `"vars"`; `.dev.vars` may override locally)

| Name                        | Purpose                                                                                       |
|-----------------------------|-----------------------------------------------------------------------------------------------|
| `ORIGIN_URL`                | Tunnel hostname to proxy to, `https://airweave-origin.<zone>` (absolute http(s) URL; may carry a base path). |
| `ALLOWED_ORIGINS`           | Comma-separated browser origins allowed by CORS (exact match; `*` allows all without credentials). |
| `AUTH_MODE`                 | `access-jwt` (default), `api-key` or `off`.                                                   |
| `TEAM_DOMAIN`               | access-jwt: `https://<team>.cloudflareaccess.com`, the JWT issuer and JWKS host.              |
| `POLICY_AUD`                | access-jwt: Application Audience (AUD) tag of the Access application on `api.<zone>`.         |
| `ALLOW_INSECURE_DEV`        | Must be exactly `1` for `AUTH_MODE = "off"` to be honoured. Keep `0` everywhere but local dev. |
| `RATE_LIMIT_PERIOD_SECONDS` | `Retry-After` advertised on 429s (default 60); keep equal to the binding's `simple.period`.    |
| `TYPESAFE_AUTOBLOCK`        | `1` lets high-confidence TypeSafe judgements write to `DENYLIST` (default `0`, label-only).    |
| `TYPESAFE_BLOCK_THRESHOLD`  | Minimum `is_probe` probability for autoblock (default `0.95`).                                |
| `TYPESAFE_BLOCK_TTL_SECONDS`| Lifetime of a denylist entry (default `900`; KV minimum 60).                                  |

### Worker: secrets (`npx wrangler secret put <NAME>`; `.dev.vars` locally; never committed)

| Name                          | Purpose                                                                                |
|-------------------------------|----------------------------------------------------------------------------------------|
| `ORIGIN_SERVICE_TOKEN_ID`     | Access Service Token Client ID, sent upstream as `CF-Access-Client-Id`.                |
| `ORIGIN_SERVICE_TOKEN_SECRET` | Its Client Secret, sent upstream as `CF-Access-Client-Secret`.                         |
| `GATEWAY_API_KEY`             | api-key mode only: value compared in constant time to `X-Airweave-Gateway-Key`.        |
| `TYPESAFE_API_KEY`            | Optional: enables TypeSafe judgements of flagged requests.                             |

### Worker: bindings (`worker/wrangler.jsonc`)

| Binding        | Declared as                                                              | Optional? |
|----------------|--------------------------------------------------------------------------|-----------|
| `RATE_LIMITER` | `ratelimits` entry, `"namespace_id": "1001"`, `"simple": { "limit": 100, "period": 60 }` | Yes: absent adds `X-Airweave-RateLimit: disabled` to every response. |
| `DENYLIST`     | `kv_namespaces` entry with the `id` of namespace `airweave-edge-denylist` | Yes: absent disables autoblock and the hot-path check. |
| `EVIDENCE_DB`  | `d1_databases` entry: `"database_name": "airweave-edge-evidence"`, `database_id`, `"migrations_dir": "migrations"` | Yes: absent logs evidence to the console instead. |

### Kubernetes (namespace `airweave`; the two Secrets are never part of a kustomization)

| Object                                   | Key / mount                                                     | Overlay  | Created by |
|------------------------------------------|-----------------------------------------------------------------|----------|------------|
| Secret `cloudflared-token`               | key `TUNNEL_TOKEN` → container env `TUNNEL_TOKEN`                | `token`  | `tunnel-token.example.yaml` copy (gitignored) or `kubectl create secret` |
| Secret `cloudflared-credentials`         | key `credentials.json` → `/etc/cloudflared/creds/credentials.json` | `config` | `tunnel-credentials.example.yaml` copy or `--from-file` of `~/.cloudflared/<UUID>.json` |
| ConfigMap `cloudflared-config-<hash>`    | key `config.yml` → `/etc/cloudflared/config/config.yml` (a sibling of the Secret mount, never nested in it) | `config` | kustomize `configMapGenerator` from `overlays/config/config.yml` (no secrets) |

### Scripts (shell environment; the flag wins when both are given)

| Variable             | Flag | Script(s)                   | Purpose                                              |
|----------------------|------|-----------------------------|------------------------------------------------------|
| `CLOUDFLARE_API_TOKEN` | – | edge.sh                     | required by `edge.sh`; also handed to wrangler       |
| `EDGE_ZONE`          | `--zone` | edge.sh                 | the Cloudflare zone; remembered in the state file    |
| `CLOUDFLARE_ACCOUNT_ID` | `--account` | edge.sh          | needed only when the token sees several accounts     |
| `TYPESAFE_API_KEY`   | – | edge.sh                        | optional; uploaded as the Worker secret of that name |
| `KUBE_CONTEXT`       | `-c` | up.sh, down.sh, check.sh (`--context` for edge.sh) | kube context, default `docker-desktop` |
| `GATEWAY_URL`        | `-u` | check.sh                    | `https://api.<zone>`; `/healthz` must be 200 `ok:true` |
| `ORIGIN_URL`         | `-o` | check.sh                    | `https://airweave-origin.<zone>`; Access must refuse (same value as the Worker var) |
| `ORIGIN_SERVICE_TOKEN_ID`, `ORIGIN_SERVICE_TOKEN_SECRET` | – | check.sh | origin cookie check: the Worker's own token is sent to the tunnel hostname and the answer must carry no `Set-Cookie: CF_Authorization` (requires strict service token authentication, step 4) |
| `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET` | – | check.sh | access-jwt mode: service token sent as `CF-Access-Client-Id`/`-Secret` on the `/healthz` request, because Access on `api.<zone>` answers before the Worker; unnecessary with a `/healthz` Bypass policy or in api-key mode |
| `AIRWEAVE_TOOLS_BIN` | `-b` | validate.sh                 | directory with kubectl / kustomize / kubeconform / cloudflared / shellcheck |

### Airweave (`.env` at the repo root)

| Variable              | Value                                                                     |
|-----------------------|---------------------------------------------------------------------------|
| `AUTH_ENABLED`        | `true`, plus `AUTH0_DOMAIN`, `AUTH0_AUDIENCE`, `AUTH0_RULE_NAMESPACE`.     |

### Headers the gateway speaks

| Header                      | Direction            | Meaning                                                            |
|-----------------------------|----------------------|--------------------------------------------------------------------|
| `Cf-Access-Jwt-Assertion`   | client → Worker      | Access JWT verified in access-jwt mode (set by Access, not by you). |
| `X-Airweave-Gateway-Key`    | client → Worker      | API key in api-key mode; stripped before the origin.               |
| `X-Request-Id`              | both responses       | UUID per request, echoed to the client and sent upstream; joins backend logs with evidence rows. |
| `X-Airweave-RateLimit`      | Worker → client      | `disabled` when no binding; `exceeded` on a 429 (with `Retry-After`). |
| `X-Airweave-Gateway-Auth`   | Worker → client      | `off` when `AUTH_MODE=off` is in effect.                           |
| `X-Airweave-Suspicion`      | Worker → origin only | Comma-separated soft signals; never sent to the client.            |
| `CF-Access-Client-Id`, `CF-Access-Client-Secret` | Worker → origin only | The service token. Any incoming `cf-access-*` header is dropped first. |
| `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-For` | Worker → origin | Set by the Worker: host and scheme of the gateway request, and `X-Forwarded-For` = `CF-Connecting-IP` alone. Client-supplied `X-Forwarded-*`, `X-Real-IP` and `Forwarded` are dropped, so the address Airweave logs is the one Cloudflare saw. |

## Security model

**Why the tunnel hostname is Access + Service Token only.** `airweave-origin.<zone>`
is a public DNS name. Without Access, anyone who guessed it could call the backend
directly and skip the Worker's authentication, rate limit and heuristics. With an
Access application whose single policy is "Service Auth: this token", Cloudflare's
edge rejects every request that lacks a valid `CF-Access-Client-Id`/`-Secret` pair
before it reaches `cloudflared`, and the only holder of that pair is the Worker (two
`wrangler secret`s). The Worker also strips every incoming `cf-access-*` header, so a
client cannot smuggle its own token or a forged assertion through the gateway.
The Worker also drops every `CF_*` cookie in both directions: the `CF_Authorization`
session cookie Access mints for the origin hostname (without strict service token
authentication, step 4) would otherwise be relayed to the gateway client as a
bearer credential for the origin, and a client-supplied one never reaches Access.
`check.sh -o` verifies the lock from outside: the origin must answer 302/401/403 to
an unauthenticated request (a 200 there is a misconfiguration) and, given the origin
token, must answer without a `CF_Authorization` cookie. Rotate the token by
creating a new one, adding it to the policy, `wrangler secret put` both values,
then deleting the old token.

**Why `AUTH_ENABLED=true`.** The gateway authenticates *access to the edge*; Airweave
authenticates *who the user is*. With `AUTH_ENABLED=false` Airweave treats every
request as its first superuser, so anybody who passes the gateway (every allowed
Access user, or anyone holding the API key) would own the whole instance. The tunnel
also bypasses any control that exists only in front of the laptop (Brev Secure
Links, SSH port forwards), exactly the rule `deploy/microk8s/README.md` states for
NodePorts. Set it before the tunnel comes up.

**What the Worker enforces, and what it does not.** Hard rules are a small,
deterministic set (path traversal including encoded variants — note that Cloudflare
resolves plain and single-encoded `..` segments before the Worker runs, so the rule
covers the double-encoded, `..;`, backslash and invalid-escape-shielded forms that do
arrive —, null bytes, methods
outside GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD) and answer 400 before authentication.
Soft signals (SQL/shell-looking path or query, scanner user agents, very long URLs or
headers, CRLF, odd dot encodings) **never block**; they tag the request for evidence.
The gateway is not a WAF: Cloudflare's own WAF and managed rules can sit in front of
it, and Airweave's input validation remains the last line. CORS is decided by
`ALLOWED_ORIGINS` alone; `Access-Control-*` headers from the origin are replaced. In
access-jwt mode that needs the Access application on `api.<zone>` to bypass `OPTIONS`
(step 5); otherwise Access rejects every preflight before the Worker runs.

**The evidence log.** Blocked (400), rate-limited (429) and soft-flagged requests,
never normal traffic, each become one row of `evidence_events` in `EVIDENCE_DB`
(`worker/migrations/0001_evidence.sql`): `seq, event_id, ts, request_id, principal,
client_ip, method, path, reason, verdict, judgement_json, prev_hash, hash`. Rows are
chained: `hash = SHA-256 hex(prev_hash + "\n" + canonical JSON of every field except
hash)`, keys sorted, first row chained to 64 zeros, `seq` written as head + 1 with a
unique index on `prev_hash`. Appends from one isolate are serialised and a writer in
another isolate is absorbed by jittered retries, so a burst of flagged requests lands
as one row each; a row that still cannot be written is logged in full
(`evidence_write_failed`, `dropped: true`) rather than discarded. Escalations of
rejected requests (400 from the hard rules, 401/403 carrying soft signals) are
bounded per principal key by the rate limiter and the denylist, so a flood from one
IP costs at most `simple.limit` TypeSafe calls and D1 appends per period; the rest
show up as `escalation_suppressed` log lines. Rate-limited (429) requests, whose
own bucket is exhausted by definition, are budgeted under a separate
`esc:<principal key>` limiter key with the same `simple.limit` per period, so a
client retry storm or a page of cross-site loads under a victim's Access cookie
cannot run up TypeSafe calls or evidence rows without limit either.

**What the chain shows, and what it cannot.** `/evidence/verify` recomputes every
digest from the genesis value and localises an in-place edit (`hash_mismatch`), a
re-linked row (`chain_break`) or a hole (`sequence_gap`) to a `break_at` seq. It
cannot see the tail being truncated (delete the newest rows and the next append
reuses the freed `seq`), nor a full recompute by anyone with D1 write access
(`wrangler d1 execute`, the dashboard): the chain carries no secret and no external
anchor, so it is a consistency check, not proof of integrity. To close that gap, keep
the head `{seq, hash}` from each `/evidence/verify` (the `evidence_recorded` log lines
carry the same pair) somewhere outside D1, such as your monitoring, and alert when
`count` or `head.seq` goes down or the stored hash no longer sits at its `seq`.
Verify from outside:

```bash
curl -s -H "X-Airweave-Gateway-Key: $KEY" https://api.<zone>/evidence/verify
# {"ok":true,"count":42,"head":{"seq":42,"hash":"..."}}
# {"ok":false,"count":7,"head":{...},"break_at":7,"reason":"hash_mismatch"}   # or chain_break, sequence_gap
```

and read the rows with `npx wrangler d1 execute airweave-edge-evidence --remote
--command "SELECT seq, ts, verdict, reason, principal, path FROM evidence_events
ORDER BY seq DESC LIMIT 20"`. The chain can be re-checked without the Worker: export
with `npx wrangler d1 export airweave-edge-evidence --remote --output evidence.sql`,
load it into sqlite3, and recompute each hash as
`sha256(prev_hash + "\n" + json.dumps(row_without_hash, sort_keys=True,
separators=(",", ":"), ensure_ascii=False))`. Rows keep the offending path and query
(capped at 1024 characters), so treat the database as sensitive and decide your own
retention. Without the binding the same record is printed as JSON (`wrangler tail`).

**What TypeSafe decides, and what it does not.** When `TYPESAFE_API_KEY` is set, each
flagged request is additionally sent to TypeSafe System One
(`POST https://api.typesafe.ai/v1/systemone`, model `jev-latest`) from
`ctx.waitUntil`, never on the hot path. The model sees a sanitised state (method,
path, query parameter *names*, user agent, the heuristic signals, principal kind,
status returned) and never a body, a secret, a token or a query value. It answers two
questions: `is_probe` (a probability that the request is an automated probe or abuse
attempt) and `category` (benign, traversal, injection, enumeration, credential_abuse,
other, with per-option probabilities and a confidence). The raw answers are stored in
`judgement_json` on the evidence row, inside the hash. TypeSafe answers are
**calibrated probabilities, not proof**: by default nothing changes for the client,
and the intended workflow is a human reviewing the evidence table.

**Autoblock is opt-in and gated three ways.** Only when `TYPESAFE_AUTOBLOCK = "1"`
*and* `DENYLIST` is bound *and* `is_probe >= TYPESAFE_BLOCK_THRESHOLD` (default 0.95)
does the Worker write the principal key to KV for `TYPESAFE_BLOCK_TTL_SECONDS`
(default 900). Keys are `jwt:<email|sub|common_name>`, `apikey:<sha256 of the key>`,
or `ip:<CF-Connecting-IP>` (anonymous: hard-blocked requests and `AUTH_MODE=off`).
The hot path then costs one KV read per request and answers 403
`principal_denied`. Thresholds live in env, never in code. Hard-blocked and
unauthenticated requests are keyed by IP, so such an entry denies proxied traffic
only when the IP *is* the principal (`AUTH_MODE=off`); what it always does is stop
further rejected requests from that IP being escalated (no more TypeSafe calls or
evidence rows until the TTL expires), the budget described under the evidence log.
`jwt:` principals that carry a user identity (an `email` claim) are **never**
autoblocked, only labelled: the request that earns the judgement can be planted by
a third party, because a cross-site GET (a link, an `<img>`) carries the victim's
`CF_Authorization` cookie for `api.<zone>` and Access attaches their identity, and
a page of such loads trips the rate limit too. The evidence row and judgement still
land for human review; an operator who wants a user blocked writes the `jwt:` key
by hand (below). `apikey:` principals and Access service tokens (assertions carrying
only `common_name`, as recommended for machine clients in step 5) stay eligible,
since a browser cannot be made to attach the `X-Airweave-Gateway-Key` or
`CF-Access-Client-Id`/`-Secret` headers cross-site.
`judgement_json.autoblock` records `requested` (the gate fired) and `applied` (the
KV write succeeded) separately, because the KV write runs before the row is sealed
and a failed write must not be recorded as a block. Inspect or
lift a block with `npx wrangler kv key list --binding DENYLIST --remote` and
`npx wrangler kv key delete --binding DENYLIST --remote "jwt:alice@example.com"`.

## Mode A vs mode B

| | Mode A (default) | Mode B |
|---|---|---|
| Backend runs | docker compose on the laptop (`./start.sh`), 8001 published on the host | as a Deployment in the cluster, labelled `app: airweave-backend`, port 8001 |
| In-cluster name | Service `airweave-backend-host` (ExternalName → `host.docker.internal`) | Service `airweave-backend` (ClusterIP, selector `app: airweave-backend`) |
| Tunnel route target | `http://airweave-backend-host.airweave.svc.cluster.local:8001` | `http://airweave-backend.airweave.svc.cluster.local:8001` |
| `config.yml` (config overlay) | mode A rule, active by default | swap in the commented mode B rule |
| Check from inside the cluster | `check.sh -i A` | `check.sh -i B` |

Both Services are always applied; the unused one is harmless (an ExternalName has no
endpoints to break, a ClusterIP with no matching pods simply has none). Only the
tunnel route decides which is used, so switching modes is a route change, not a
redeploy. Mode B mirrors `deploy/microk8s/services.yaml` (same selector, ClusterIP
instead of NodePort); deploying the backend into the cluster is outside this
directory's scope.

## Troubleshooting

**cloudflared never becomes Ready / `/ready` is not 200.** `/ready` only passes with a
live edge connection. `kubectl --context docker-desktop -n airweave logs
deployment/cloudflared --tail=50`. Usual causes: a wrong or revoked token or
credentials, UDP 7844 (QUIC) blocked on the network (uncomment the env var
`TUNNEL_TRANSPORT_PROTOCOL=http2` in `k8s/base/deployment.yaml`: it reaches both
overlays, whereas a `--protocol http2` pair before `run` would also have to be copied
into `overlays/config/deployment-patch.yaml`, which replaces `command` wholesale;
`validate.sh` accepts either form), the laptop was asleep (the liveness probe
restarts the pod), no internet. `check.sh` shows the `/ready` body
(`{"status":200,"readyConnections":N,...}`) through a port-forward; use `-p` if port
12000 is taken.

**`host.docker.internal` does not resolve or connect (mode A).** It exists only under
Docker Desktop (and Docker Desktop's Kubernetes), not on a bare Linux Docker Engine.
Verify from inside the cluster with `check.sh -i A`, which curls
`http://airweave-backend-host.airweave.svc.cluster.local:8001/health/ready` from a
pod. If that fails while `curl localhost:8001/health/ready` works on the laptop, the
port is published on `127.0.0.1` only (compose must publish `8001:8001`, not
`127.0.0.1:8001:8001`) or compose is not up. Cloudflare answering 502/530 for the
route while the pod is Ready usually means the route URL is misspelt.

**403 (or a login redirect) from Access.** Three different things can say 403:

- The Worker's own JSON (`{"error": "...", "request_id": "..."}` with an
  `X-Request-Id` header): `invalid_access_token` (bad issuer/audience/expiry: check
  `TEAM_DOMAIN`, `POLICY_AUD`), `invalid_api_key`, `principal_denied` (autoblock; see
  the denylist commands above), `origin_not_allowed` (preflight from an origin missing
  in `ALLOWED_ORIGINS`; the match is exact, scheme + host + port).
- Access on `airweave-origin.<zone>` replying to the Worker's upstream call, which
  comes back as a 302 to `<team>.cloudflareaccess.com/cdn-cgi/access/login/...` or
  an Access 403 page: the service token is missing, expired, or not the one the
  policy allows. Re-check the two `ORIGIN_SERVICE_TOKEN_*` secrets and the policy;
  `wrangler tail` shows the upstream status.
- Access on `api.<zone>` (access-jwt mode) rejecting the user before the Worker runs:
  the user is not covered by the Allow policy.
- Access on `api.<zone>` answering a browser's preflight: a 403 on an `OPTIONS`
  request with no `X-Request-Id` and no `Access-Control-Allow-Origin` means the
  application does not bypass `OPTIONS` (step 5); the Worker never saw the request.
- Access on `api.<zone>` answering `/healthz` with a 302 to the login page, so
  `check.sh -u` reports `FAIL gateway ... -> 302`: pass a service token
  (`CF_ACCESS_CLIENT_ID`/`CF_ACCESS_CLIENT_SECRET`) or add the `/healthz` Bypass
  application (step 5).

**401** is a missing credential (`missing_access_token`, `missing_api_key`); **500
`gateway_misconfigured`** names the missing var (`TEAM_DOMAIN`/`POLICY_AUD`,
`GATEWAY_API_KEY`, `AUTH_MODE=off` without `ALLOW_INSECURE_DEV`, bad `ORIGIN_URL`);
**502 `origin_unreachable`** means the Worker's fetch to `ORIGIN_URL` threw (hostname
not routed/resolvable); a **530** is Cloudflare itself reporting the tunnel is down
and is passed through unchanged.

**429s.** The limit is 100 requests per 60 s *per principal* (`simple = { limit,
period }` on the `RATE_LIMITER` binding), counted per Cloudflare location and
approximate. The response carries `Retry-After` and `X-Airweave-RateLimit: exceeded`,
and an evidence row with verdict `rate_limited`. In api-key mode there is exactly one
`GATEWAY_API_KEY`, so every client shares one bucket (`apikey:<sha256>`); to separate
clients switch to access-jwt, where each user gets a `jwt:<sub>` bucket and each
machine client gets its own Access service token (`jwt:<common-name>`). To change the limit edit `simple.limit` /
`simple.period` in `wrangler.jsonc` (period must be 10 or 60), keep
`RATE_LIMIT_PERIOD_SECONDS` equal to the period, and redeploy. Removing the binding
disables limiting (every response then says `X-Airweave-RateLimit: disabled`).

**`/evidence/verify` answers 503.** `evidence_db_not_configured`: no `EVIDENCE_DB`
binding. `evidence_db_not_migrated`: run `npx wrangler d1 migrations apply
airweave-edge-evidence --remote` (`--local` for `wrangler dev`; `npm run dev` does
that for you).

## Run the checks

```bash
# Worker and orchestrator: types (Worker + checkJs over scripts/*.mjs), the vitest
# suite inside workerd, then node --test for edge.mjs against an in-memory Cloudflare API
cd deploy/cloudflare/worker
npm ci
npm run typecheck
npm test
npx wrangler deploy --dry-run --outdir /tmp/edge-gateway-dist   # bundle check, no account needed

# Manifests and scripts: render both overlays, schema-check, cloudflared ingress validate, shellcheck
deploy/cloudflare/scripts/validate.sh                    # SKIPs what it cannot run and says how to install it
deploy/cloudflare/scripts/validate.sh -b "$TOOLS" -s     # tools dir on PATH; -s makes a SKIP a failure
```

`validate.sh` needs nothing from a cluster. It runs `bash -n` and `shellcheck` on the
scripts, `check_manifests.py` (python3 + PyYAML), `kubectl kustomize` (or `kustomize
build`) on both overlays with must/must-not assertions, `kubeconform -strict` on the
renders and the example Secrets, and `cloudflared tunnel ingress validate` on
`overlays/config/config.yml`.

CI runs the same two groups in `.github/workflows/edge-gateway.yml` ("Edge Gateway")
on pull requests to `main` and pushes to `main` that touch `deploy/cloudflare/**`
(feature-branch pushes rely on the local commands above): Node 22 with
`npm ci` / `npm run typecheck` / `npm test` / `wrangler deploy --dry-run`, and
`validate.sh -s` with pinned, checksum-verified kubectl, kubeconform and cloudflared.
Against a real laptop, finish with
`deploy/cloudflare/scripts/check.sh -u https://api.<zone> -o https://airweave-origin.<zone> -i A`.

## Tear down

`deploy/cloudflare/scripts/edge.sh down` prints what it would remove; `down --yes`
removes everything `up` created (connector, Worker and its Custom Domain, Access
applications, policies and service token, DNS record, tunnel) and keeps the KV
denylist and D1 evidence log unless `--delete-data` is added. By hand:
`deploy/cloudflare/scripts/down.sh` removes the Deployment, the two Services and the
generated ConfigMaps and keeps the Secrets and the namespace (a mode B backend may
live there); `-s` also deletes the Secrets, `-N` deletes the whole namespace. Delete
or disable the tunnel under Zero Trust → Networks → Tunnels, the two Access
applications and the Service Token when they are no longer needed, and
`npx wrangler delete` the Worker.
