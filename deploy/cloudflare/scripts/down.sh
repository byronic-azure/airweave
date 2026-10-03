#!/usr/bin/env bash
# Remove the cloudflared connector and the Services the tunnel routes to from
# Docker Desktop's Kubernetes. Secrets and the namespace stay unless asked for,
# because "airweave" may also hold a mode-B backend.
#
# Usage:
#   ./down.sh [-c CONTEXT] [-s] [-N]
#
#   -c CONTEXT  kube context (default: $KUBE_CONTEXT, else docker-desktop)
#   -s          also delete the Secrets cloudflared-token and cloudflared-credentials
#   -N          delete the whole "airweave" namespace instead (everything in it)
#
# Deliberately not `kubectl delete -k`: the base includes the Namespace, and
# deleting that would take any in-cluster backend with it.
set -euo pipefail

NAMESPACE="airweave"
CONTEXT="${KUBE_CONTEXT:-docker-desktop}"
DELETE_SECRETS=0
DELETE_NAMESPACE=0

usage() { sed -n '2,14p' "$0"; }
die() { echo "error: $*" >&2; exit 1; }

while getopts "c:sNh" opt; do
  case "$opt" in
    c) CONTEXT="$OPTARG" ;;
    s) DELETE_SECRETS=1 ;;
    N) DELETE_NAMESPACE=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -eq 0 ] || { echo "error: unexpected argument: $1" >&2; usage >&2; exit 2; }

command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"
kubectl config get-contexts "$CONTEXT" >/dev/null 2>&1 \
  || die "kube context '$CONTEXT' does not exist (pass -c CONTEXT)"
KUBECTL=(kubectl --context "$CONTEXT")

if [ "$DELETE_NAMESPACE" -eq 1 ]; then
  echo "==> Deleting namespace $NAMESPACE and everything in it (context $CONTEXT)"
  "${KUBECTL[@]}" delete namespace "$NAMESPACE" --ignore-not-found --wait=true
  echo "done"
  exit 0
fi

if ! "${KUBECTL[@]}" get namespace "$NAMESPACE" >/dev/null 2>&1; then
  echo "namespace $NAMESPACE does not exist; nothing to do"
  exit 0
fi

echo "==> Removing the cloudflared connector from namespace $NAMESPACE (context $CONTEXT)"
"${KUBECTL[@]}" delete deployment/cloudflared -n "$NAMESPACE" --ignore-not-found
"${KUBECTL[@]}" delete service/airweave-backend-host service/airweave-backend \
  -n "$NAMESPACE" --ignore-not-found
# Generated ConfigMaps carry a content hash in their name; find them by label.
"${KUBECTL[@]}" delete configmap -n "$NAMESPACE" \
  -l app.kubernetes.io/name=cloudflared,app.kubernetes.io/part-of=airweave --ignore-not-found

if [ "$DELETE_SECRETS" -eq 1 ]; then
  echo "==> Removing tunnel Secrets"
  "${KUBECTL[@]}" delete secret cloudflared-token cloudflared-credentials \
    -n "$NAMESPACE" --ignore-not-found
else
  echo "kept Secrets cloudflared-token / cloudflared-credentials (use -s to delete them)"
fi
echo "kept namespace $NAMESPACE (use -N to delete it entirely)"
echo "Remember to delete or disable the tunnel in Zero Trust > Networks > Tunnels if it is no longer needed."
