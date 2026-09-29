#!/usr/bin/env bash
# Set externalTrafficPolicy=Local on existing NodePort Services, then print the
# NodePort each one exposes (the port to use for Secure Links / TCP access).
#
# Usage:
#   ./patch-external-traffic-policy.sh [-n NAMESPACE] [SERVICE ...]
#
# With no SERVICE arguments, every NodePort Service in the namespace is patched.
# Idempotent: Services already set to Local are left untouched.
set -euo pipefail

NAMESPACE="airweave"
while getopts "n:h" opt; do
  case "$opt" in
    n) NAMESPACE="$OPTARG" ;;
    h) sed -n '2,9p' "$0"; exit 0 ;;
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
  mapfile -t services < <("${KUBECTL[@]}" get services -n "$NAMESPACE" \
    -o jsonpath='{range .items[?(@.spec.type=="NodePort")]}{.metadata.name}{"\n"}{end}')
fi

if [ "${#services[@]}" -eq 0 ]; then
  echo "No NodePort Services found in namespace '$NAMESPACE'."
  exit 0
fi

for svc in "${services[@]}"; do
  type=$("${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" -o jsonpath='{.spec.type}')
  if [ "$type" != "NodePort" ]; then
    echo "skip  $svc (type=$type, not NodePort)"
    continue
  fi
  policy=$("${KUBECTL[@]}" get service "$svc" -n "$NAMESPACE" \
    -o jsonpath='{.spec.externalTrafficPolicy}')
  if [ "$policy" = "Local" ]; then
    echo "ok    $svc (already Local)"
  else
    "${KUBECTL[@]}" patch service "$svc" --namespace "$NAMESPACE" \
      --type=merge --patch '{"spec":{"externalTrafficPolicy":"Local"}}' >/dev/null
    echo "patch $svc (${policy:-unset} -> Local)"
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
