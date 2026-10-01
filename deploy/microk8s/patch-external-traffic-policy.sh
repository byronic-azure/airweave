#!/usr/bin/env bash
# Set externalTrafficPolicy=Local on existing NodePort Services, then print the
# NodePort each one exposes (the port to use for Secure Links / TCP access).
#
# Usage:
#   ./patch-external-traffic-policy.sh [-n NAMESPACE] [-l SELECTOR | -A] [SERVICE ...]
#
#   -n NAMESPACE  namespace to act on (default: airweave)
#   -l SELECTOR   label selector for discovery (default: app.kubernetes.io/part-of=airweave)
#   -A            discover every NodePort Service in the namespace, ignoring labels
#
# With no SERVICE arguments, only NodePort Services matching the selector are
# patched, so unrelated Services in a shared namespace are left alone.
# Idempotent: Services already set to Local are left untouched. Each patch is
# read back; the script exits non-zero if any Service did not end up Local.
set -euo pipefail

NAMESPACE="airweave"
SELECTOR="app.kubernetes.io/part-of=airweave"
while getopts "n:l:Ah" opt; do
  case "$opt" in
    n) NAMESPACE="$OPTARG" ;;
    l) SELECTOR="$OPTARG" ;;
    A) SELECTOR="" ;;
    h) sed -n '2,15p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if command -v kubectl >/dev/null 2>&1; then
  KUBECTL=(kubectl)
elif command -v microk8s >/dev/null 2>&1; then
  KUBECTL=(microk8s kubectl)
else
  echo "error: neither kubectl nor microk8s found on PATH" >&2
  exit 1
fi

if [ "$#" -gt 0 ]; then
  services=("$@")
else
  selector_args=()
  if [ -n "$SELECTOR" ]; then
    selector_args=(-l "$SELECTOR")
  fi
  # Plain assignment so `set -e` aborts if discovery fails (missing namespace,
  # RBAC, unreachable cluster) instead of reporting "no Services found".
  discovered=$("${KUBECTL[@]}" get services -n "$NAMESPACE" "${selector_args[@]}" \
    -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"\n"}{end}')
  services=()
  if [ -n "$discovered" ]; then
    mapfile -t services <<< "$discovered"
  fi
fi

if [ "${#services[@]}" -eq 0 ]; then
  echo "No NodePort Services found in namespace '$NAMESPACE'${SELECTOR:+ matching '$SELECTOR'}."
  exit 0
fi

failed=()
for svc in "${services[@]}"; do
  if ! type=$("${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" -o jsonpath='{.spec.type}'); then
    echo "FAIL  $svc (could not read Service)"
    failed+=("$svc")
    continue
  fi
  if [ "$type" != "NodePort" ]; then
    echo "skip  $svc (type=$type, not NodePort)"
    continue
  fi
  policy=$("${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" \
    -o jsonpath='{.spec.externalTrafficPolicy}')
  if [ "$policy" = "Local" ]; then
    echo "ok    $svc (already Local)"
    continue
  fi
  if ! "${KUBECTL[@]}" patch service "$svc" --namespace "$NAMESPACE" \
      --type=merge --patch '{"spec":{"externalTrafficPolicy":"Local"}}' >/dev/null; then
    echo "FAIL  $svc (patch rejected, still ${policy:-unset})"
    failed+=("$svc")
    continue
  fi
  after=$("${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" \
    -o jsonpath='{.spec.externalTrafficPolicy}' || true)
  if [ "$after" = "Local" ]; then
    echo "patch $svc (${policy:-unset} -> Local, verified)"
  else
    echo "FAIL  $svc (patched but reads back as ${after:-unset})"
    failed+=("$svc")
  fi
done

echo
echo "Use the NODEPORT column (not the container port) for Secure Links / TCP access:"
printf '%-28s %-9s %-10s %s\n' SERVICE PROTOCOL NODEPORT TARGETPORT
for svc in "${services[@]}"; do
  "${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" -o jsonpath=\
'{range .spec.ports[*]}{"'"$svc"'"}{"\t"}{.protocol}{"\t"}{.nodePort}{"\t"}{.targetPort}{"\n"}{end}' \
    2>/dev/null | awk -F'\t' '$3 != "" {printf "%-28s %-9s %-10s %s\n", $1, $2, $3, $4}'
done

if [ "${#failed[@]}" -gt 0 ]; then
  echo >&2
  echo "error: ${#failed[@]} Service(s) not Local: ${failed[*]}" >&2
  echo "Do not forward traffic to these NodePorts; fix and re-run (safe to repeat)." >&2
  exit 1
fi
