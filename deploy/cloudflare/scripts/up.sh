#!/usr/bin/env bash
# Deploy the cloudflared connector for the Airweave edge gateway into Docker
# Desktop's Kubernetes and wait until the tunnel is connected.
#
# Usage:
#   ./up.sh [token|config] [-c CONTEXT] [-t TIMEOUT]
#
#   token       remotely-managed tunnel (default): Secret cloudflared-token,
#               routes configured in the Cloudflare dashboard
#   config      locally-managed tunnel: ConfigMap from config.yml plus
#               Secret cloudflared-credentials
#   -c CONTEXT  kube context (default: $KUBE_CONTEXT, else docker-desktop)
#   -t TIMEOUT  how long to wait for the rollout (default: 180s)
#
# Secrets are never part of the kustomization. Before applying, the script
# makes sure the overlay's Secret exists: it applies the gitignored copy next
# to the *.example.yaml template if you made one, otherwise it expects the
# Secret to be in the cluster already, otherwise it explains how to create it
# and exits. Every kubectl call is pinned to the chosen context so a stray
# current-context can never receive the apply.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(cd "$SCRIPT_DIR/../k8s" && pwd)"
NAMESPACE="airweave"
PLACEHOLDER="REPLACE_WITH_"

OVERLAY="token"
CONTEXT="${KUBE_CONTEXT:-docker-desktop}"
TIMEOUT="180s"

usage() { sed -n '2,20p' "$0"; }
die() { echo "error: $*" >&2; exit 1; }

if [ "$#" -gt 0 ] && [[ "$1" != -* ]]; then
  OVERLAY="$1"
  shift
fi
while getopts "c:t:h" opt; do
  case "$opt" in
    c) CONTEXT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -eq 0 ] || { echo "error: unexpected argument: $1" >&2; usage >&2; exit 2; }

case "$OVERLAY" in
  token|config) ;;
  *) die "overlay must be 'token' or 'config', got '$OVERLAY'" ;;
esac
OVERLAY_DIR="$K8S_DIR/overlays/$OVERLAY"

command -v kubectl >/dev/null 2>&1 \
  || die "kubectl not found on PATH (Docker Desktop installs one once Kubernetes is enabled)"
kubectl config get-contexts "$CONTEXT" >/dev/null 2>&1 \
  || die "kube context '$CONTEXT' does not exist. Enable Kubernetes in Docker Desktop" \
         "(Settings > Kubernetes) or pass -c CONTEXT."
KUBECTL=(kubectl --context "$CONTEXT")
"${KUBECTL[@]}" get --raw /readyz --request-timeout=15s >/dev/null 2>&1 \
  || die "cluster behind context '$CONTEXT' is not reachable; is Docker Desktop running?"

# ensure_secret NAME LOCAL_FILE EXAMPLE_FILE HOWTO_FN
# Applies LOCAL_FILE when present (refusing placeholders), accepts a Secret
# that already exists in the cluster, otherwise prints HOWTO_FN and exits.
ensure_secret() {
  local name="$1" local_file="$2" example_file="$3" howto="$4"
  if [ -f "$local_file" ]; then
    if grep -q "$PLACEHOLDER" "$local_file"; then
      die "$local_file still contains $PLACEHOLDER placeholders; fill it in" \
          "(template: $example_file)"
    fi
    "${KUBECTL[@]}" apply -f "$local_file" >/dev/null
    echo "ok    Secret $name applied from $(basename "$local_file")"
  elif "${KUBECTL[@]}" get secret "$name" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "ok    Secret $name already present in namespace $NAMESPACE"
  else
    echo "error: Secret $name is missing from namespace $NAMESPACE and" \
         "$local_file does not exist." >&2
    "$howto" >&2
    exit 1
  fi
}

howto_token() {
  cat <<EOT
Create it one of these ways, then re-run:
  a) kubectl --context $CONTEXT -n $NAMESPACE create secret generic cloudflared-token \\
       --from-literal=TUNNEL_TOKEN='<token from Zero Trust > Networks > Tunnels > Install connector>'
  b) cp $OVERLAY_DIR/tunnel-token.example.yaml $OVERLAY_DIR/tunnel-token.yaml
     (gitignored), paste the token, re-run this script.
EOT
}

howto_config() {
  cat <<EOT
Create it one of these ways, then re-run:
  a) kubectl --context $CONTEXT -n $NAMESPACE create secret generic cloudflared-credentials \\
       --from-file=credentials.json="\$HOME/.cloudflared/<tunnel UUID>.json"
     (the file written by: cloudflared tunnel create airweave-origin)
  b) cp $OVERLAY_DIR/tunnel-credentials.example.yaml $OVERLAY_DIR/tunnel-credentials.yaml
     (gitignored), paste the JSON, re-run this script.
EOT
}

# The config overlay is only useful once config.yml names a real tunnel.
if [ "$OVERLAY" = "config" ]; then
  cfg="$OVERLAY_DIR/config.yml"
  if grep -Eq '^tunnel: 0{8}-' "$cfg" \
      || grep -Eq '^[[:space:]]+- hostname: airweave-origin\.example\.com' "$cfg"; then
    die "edit $cfg first: set 'tunnel:' to your tunnel UUID and 'hostname:' to the public" \
        "hostname you routed to it (cloudflared tunnel route dns ...)."
  fi
fi

echo "==> Namespace $NAMESPACE (context $CONTEXT)"
"${KUBECTL[@]}" apply -f "$K8S_DIR/base/namespace.yaml"

echo "==> Secret for overlay '$OVERLAY'"
case "$OVERLAY" in
  token)
    ensure_secret cloudflared-token "$OVERLAY_DIR/tunnel-token.yaml" \
      "$OVERLAY_DIR/tunnel-token.example.yaml" howto_token ;;
  config)
    ensure_secret cloudflared-credentials "$OVERLAY_DIR/tunnel-credentials.yaml" \
      "$OVERLAY_DIR/tunnel-credentials.example.yaml" howto_config ;;
esac

echo "==> kubectl apply -k $OVERLAY_DIR"
"${KUBECTL[@]}" apply -k "$OVERLAY_DIR"

echo "==> Waiting for cloudflared to connect (rollout timeout $TIMEOUT)"
if ! "${KUBECTL[@]}" rollout status deployment/cloudflared -n "$NAMESPACE" --timeout="$TIMEOUT"; then
  cat >&2 <<EOT
error: cloudflared did not become Ready within $TIMEOUT (readiness = /ready on :2000,
which only passes once the tunnel has a live edge connection). Inspect with:
  kubectl --context $CONTEXT -n $NAMESPACE get pods -l app=cloudflared
  kubectl --context $CONTEXT -n $NAMESPACE logs deployment/cloudflared --tail=50
Common causes: wrong or revoked token/credentials, UDP 7844 (QUIC) blocked on this
network (uncomment env TUNNEL_TRANSPORT_PROTOCOL=http2 in k8s/base/deployment.yaml; it
reaches both overlays, whereas a "--protocol http2" pair on the command would also have
to be copied into overlays/config/deployment-patch.yaml), or no internet access.
EOT
  exit 1
fi

cat <<EOT

cloudflared is connected (overlay: $OVERLAY, context: $CONTEXT, namespace: $NAMESPACE).

Next steps
  1. Route the tunnel to the backend.
EOT
if [ "$OVERLAY" = "token" ]; then
  cat <<EOT
     Zero Trust > Networks > Tunnels > <tunnel> > Public Hostname, hostname airweave-origin.<zone>:
       mode A (compose on the laptop)   http://airweave-backend-host.airweave.svc.cluster.local:8001
       mode B (backend in this cluster) http://airweave-backend.airweave.svc.cluster.local:8001
EOT
else
  cat <<EOT
     Done declaratively: the ingress rules in $OVERLAY_DIR/config.yml
     (mode A rule active by default; swap in the mode B rule to target the in-cluster backend).
EOT
fi
cat <<EOT
  2. Lock the hostname to the Worker. Zero Trust > Access > Applications > Add application
     (self-hosted) for airweave-origin.<zone> with one policy of action "Service Auth" that
     allows a Service Token created under Access controls > Service credentials > Service Tokens.
     Then Zero Trust > Access controls > Access settings > Manage service tokens > turn on "Strict service token authentication"
     so Access never answers the Worker's token with a CF_Authorization cookie.
  3. Hand that token to the Worker so only it can pass the Access check:
       cd deploy/cloudflare/worker
       npx wrangler secret put ORIGIN_SERVICE_TOKEN_ID
       npx wrangler secret put ORIGIN_SERVICE_TOKEN_SECRET
     and set ORIGIN_URL = "https://airweave-origin.<zone>" in wrangler.toml.
  4. Airweave's .env MUST have AUTH_ENABLED=true (the tunnel bypasses anything that only
     protects the laptop, such as Brev Secure Links); restart docker compose afterwards.
  5. Verify the path:  $SCRIPT_DIR/check.sh -u https://api.<zone> -o https://airweave-origin.<zone>
     (access-jwt mode: export CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET first, or give
     /healthz a Bypass policy; Access on api.<zone> otherwise answers before the Worker)
EOT
