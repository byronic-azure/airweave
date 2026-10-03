#!/usr/bin/env bash
# Check the edge gateway path, as far as the URLs you pass allow:
#   pod       the cloudflared Deployment is Ready
#   ready     /ready on the pod's metrics port (via port-forward) reports live
#             edge connections
#   gateway   optional (-u): GET <gateway>/healthz through the Worker is 200 ok:true.
#             In access-jwt mode Access on api.<zone> answers before the Worker:
#             export CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET (a service token
#             the api.<zone> policy allows) and they are sent as CF-Access-Client-Id /
#             -Secret, or give /healthz its own Bypass policy (README, step 5)
#   origin    optional (-o): the tunnel hostname REFUSES a request that lacks the
#             Access service token (302/401/403); a 200 means the Worker can be bypassed
#   backend   optional (-i): a throw-away curl pod reaches the backend through the
#             in-cluster Service name the tunnel routes to (mode A or B)
#
# Usage:
#   ./check.sh [-c CONTEXT] [-u GATEWAY_URL] [-o ORIGIN_URL] [-p LOCAL_PORT] [-i A|B]
#
#   -c CONTEXT      kube context (default: $KUBE_CONTEXT, else docker-desktop)
#   -u GATEWAY_URL  Worker URL, e.g. https://api.example.com (default: $GATEWAY_URL)
#   -o ORIGIN_URL   tunnel hostname, e.g. https://airweave-origin.example.com (default: $ORIGIN_URL)
#   -p LOCAL_PORT   local port for the port-forward to the pod (default: 12000)
#   -i A|B          backend check: A = airweave-backend-host (compose on the laptop),
#                   B = airweave-backend (backend deployed in the cluster)
#
# Environment: KUBE_CONTEXT, GATEWAY_URL, ORIGIN_URL (defaults for the flags above),
# CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET (service token for the gateway check).
#
# Exits non-zero if any check that ran failed.
set -euo pipefail

NAMESPACE="airweave"
CONTEXT="${KUBE_CONTEXT:-docker-desktop}"
GATEWAY="${GATEWAY_URL:-}"
ORIGIN="${ORIGIN_URL:-}"
LOCAL_PORT="12000"
BACKEND_MODE=""
ACCESS_ID="${CF_ACCESS_CLIENT_ID:-}"
ACCESS_SECRET="${CF_ACCESS_CLIENT_SECRET:-}"
CURL_IMAGE="curlimages/curl:8.22.0"

usage() { sed -n '2,29p' "$0"; }
die() { echo "error: $*" >&2; exit 1; }

while getopts "c:u:o:p:i:h" opt; do
  case "$opt" in
    c) CONTEXT="$OPTARG" ;;
    u) GATEWAY="$OPTARG" ;;
    o) ORIGIN="$OPTARG" ;;
    p) LOCAL_PORT="$OPTARG" ;;
    i) BACKEND_MODE="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -eq 0 ] || { echo "error: unexpected argument: $1" >&2; usage >&2; exit 2; }
case "$BACKEND_MODE" in
  ""|A|B) ;;
  *) die "-i takes A or B, got '$BACKEND_MODE'" ;;
esac

command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
command -v curl >/dev/null 2>&1 || die "curl not found on PATH"
kubectl config get-contexts "$CONTEXT" >/dev/null 2>&1 \
  || die "kube context '$CONTEXT' does not exist (pass -c CONTEXT)"
KUBECTL=(kubectl --context "$CONTEXT")

FAILED=0
pass() { local what="$1"; shift; printf 'ok    %-8s %s\n' "$what" "$*"; }
fail() { local what="$1"; shift; printf 'FAIL  %-8s %s\n' "$what" "$*"; FAILED=$((FAILED + 1)); }

WORK="$(mktemp -d)"
PF_PID=""
cleanup() {
  if [ -n "$PF_PID" ]; then kill "$PF_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# -- pod ---------------------------------------------------------------------
ready="$("${KUBECTL[@]}" get deployment/cloudflared -n "$NAMESPACE" \
  -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
if [ "${ready:-0}" -ge 1 ] 2>/dev/null; then
  pass pod "deployment/cloudflared has $ready ready replica(s)"
else
  fail pod "deployment/cloudflared has no ready replica" \
    "(kubectl --context $CONTEXT -n $NAMESPACE logs deployment/cloudflared)"
fi

# -- ready -------------------------------------------------------------------
"${KUBECTL[@]}" port-forward -n "$NAMESPACE" deployment/cloudflared "$LOCAL_PORT:2000" \
  >"$WORK/port-forward.log" 2>&1 &
PF_PID=$!
code="000"
for _ in $(seq 1 30); do
  code="$(curl -sS -o "$WORK/ready.json" -w '%{http_code}' --max-time 2 \
    "http://127.0.0.1:$LOCAL_PORT/ready" 2>/dev/null || true)"
  [ "$code" != "000" ] && break
  kill -0 "$PF_PID" 2>/dev/null || break
  sleep 0.5
done
if [ "$code" = "200" ]; then
  pass ready "/ready -> 200 $(tr -d '\n' <"$WORK/ready.json")"
elif [ "$code" = "000" ]; then
  pf_err="$(tail -n 1 "$WORK/port-forward.log" 2>/dev/null || true)"
  fail ready "port-forward to :$LOCAL_PORT never answered ($pf_err); try -p <free port>"
else
  fail ready "/ready -> $code $(tr -d '\n' <"$WORK/ready.json" 2>/dev/null || true)" \
    "(no live edge connection)"
fi

# -- gateway -----------------------------------------------------------------
if [ -n "$GATEWAY" ]; then
  url="${GATEWAY%/}/healthz"
  # Access service token for a gateway hostname that is itself an Access
  # application (access-jwt mode); nothing is sent when the variables are unset.
  # The token goes through a 0600 file in $WORK (removed by the EXIT trap), never
  # on the curl command line where any local process could read it from ps.
  access=()
  if [ -n "$ACCESS_ID" ] && [ -n "$ACCESS_SECRET" ]; then
    (umask 077; printf 'CF-Access-Client-Id: %s\nCF-Access-Client-Secret: %s\n' \
      "$ACCESS_ID" "$ACCESS_SECRET" > "$WORK/access-headers")
    access=(-H "@$WORK/access-headers")
  fi
  code="$(curl -sS -o "$WORK/healthz.json" -w '%{http_code}' --max-time 15 \
    ${access[@]+"${access[@]}"} "$url" 2>"$WORK/curl.err" || true)"
  if [ "$code" = "200" ] && grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' "$WORK/healthz.json"; then
    with="without an Access token"
    [ "${#access[@]}" -gt 0 ] && with="with the Access service token"
    pass gateway "$url -> 200 $(tr -d '\n' <"$WORK/healthz.json") ($with)"
  else
    body="$(tr -d '\n' <"$WORK/healthz.json" 2>/dev/null | head -c 200 || true)"
    hint=""
    case "$code" in
      302|401|403)
        if [ "${#access[@]}" -eq 0 ]; then
          hint=" Access in front of the gateway (access-jwt mode)? Set CF_ACCESS_CLIENT_ID and"
          hint="$hint CF_ACCESS_CLIENT_SECRET to a service token the api.<zone> policy allows,"
          hint="$hint or add a Bypass policy for /healthz (README, step 5)."
        fi ;;
    esac
    fail gateway "$url -> ${code} ${body} $(cat "$WORK/curl.err")${hint}"
  fi
else
  echo "skip  gateway  no gateway URL (-u https://api.<zone> or GATEWAY_URL)"
fi

# -- origin ------------------------------------------------------------------
if [ -n "$ORIGIN" ]; then
  url="${ORIGIN%/}/health/ready"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$url" 2>"$WORK/curl.err" || true)"
  case "$code" in
    302|401|403) pass origin "$url -> $code without the service token (Access is enforcing)" ;;
    200) fail origin "$url -> 200 WITHOUT a service token: the origin bypasses the Worker." \
           "Add the Access application (Service Auth policy) on this hostname." ;;
    530) fail origin "$url -> 530: Cloudflare cannot reach the tunnel" \
           "(connector down or hostname not routed)" ;;
    000) fail origin "$url unreachable: $(cat "$WORK/curl.err")" ;;
    *) fail origin "$url -> $code (expected 302/401/403 from Access)" ;;
  esac
else
  echo "skip  origin   no origin URL (-o https://airweave-origin.<zone> or ORIGIN_URL)"
fi

# -- backend (in-cluster) ----------------------------------------------------
if [ -n "$BACKEND_MODE" ]; then
  if [ "$BACKEND_MODE" = "A" ]; then svc="airweave-backend-host"; else svc="airweave-backend"; fi
  url="http://$svc.$NAMESPACE.svc.cluster.local:8001/health/ready"
  pod="airweave-origin-check-$$"
  out="$("${KUBECTL[@]}" run "$pod" -n "$NAMESPACE" --rm -i --restart=Never --quiet \
    --image="$CURL_IMAGE" --pod-running-timeout=2m -- \
    curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "$url" 2>&1 || true)"
  if printf '%s\n' "$out" | grep -qx '200'; then
    pass backend "mode $BACKEND_MODE: $url -> 200 from inside the cluster"
  else
    hint="is docker compose up and publishing 8001?"
    [ "$BACKEND_MODE" = "B" ] && hint="is a Deployment labelled app: airweave-backend running in $NAMESPACE?"
    fail backend "mode $BACKEND_MODE: $url failed from inside the cluster" \
      "($(printf '%s' "$out" | tail -n 1)); $hint"
  fi
else
  echo "skip  backend  no in-cluster check requested (-i A for compose on the laptop, -i B for in-cluster)"
fi

echo
if [ "$FAILED" -gt 0 ]; then
  echo "$FAILED check(s) failed"
  exit 1
fi
echo "all checks that ran passed"
