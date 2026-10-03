#!/usr/bin/env bash
# Validate the Cloudflare tunnel manifests without touching a cluster.
#
# Usage:
#   ./validate.sh [-b TOOLS_DIR] [-k K8S_VERSION] [-s]
#
#   -b TOOLS_DIR    extra directory holding kubectl / kustomize / kubeconform /
#                   cloudflared, prepended to PATH (also: $AIRWEAVE_TOOLS_BIN)
#   -k K8S_VERSION  Kubernetes version for kubeconform schemas (default: master)
#   -s              strict: a check that could not run counts as a failure
#
# Checks, each reported as PASS, FAIL or SKIP (with why it could not run):
#   syntax     bash -n on every script here, plus shellcheck when installed
#   structure  check_manifests.py (python3 + PyYAML): required keys, labels,
#              security context, probes, pinned image, example placeholders
#   selftest   test_check_manifests.py: the validator accepts the documented
#              edits (QUIC fallback) and rejects the known-bad layouts
#   render     kubectl kustomize (or kustomize build) of both overlays, then the
#              objects each overlay must and must not produce
#   schema     kubeconform on the rendered overlays and the example Secrets
#   ingress    cloudflared tunnel ingress validate on overlays/config/config.yml
#
# Exit status is non-zero when any check FAILS (with -s, also when one SKIPS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(cd "$SCRIPT_DIR/../k8s" && pwd)"
TOOLS_DIR="${AIRWEAVE_TOOLS_BIN:-}"
K8S_VERSION="master"
STRICT=0

usage() { sed -n '2,21p' "$0"; }

while getopts "b:k:sh" opt; do
  case "$opt" in
    b) TOOLS_DIR="$OPTARG" ;;
    k) K8S_VERSION="$OPTARG" ;;
    s) STRICT=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "$#" -eq 0 ] || { echo "error: unexpected argument: $1" >&2; usage >&2; exit 2; }
[ -n "$TOOLS_DIR" ] && PATH="$TOOLS_DIR:$PATH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASSED=0; FAILED=0; SKIPPED=0
report() { local status="$1" name="$2"; shift 2; printf '%-5s %-10s %s\n' "$status" "$name" "$*"; }
pass() { report PASS "$@"; PASSED=$((PASSED + 1)); }
fail() { report FAIL "$@"; FAILED=$((FAILED + 1)); }
skip() { report SKIP "$@"; SKIPPED=$((SKIPPED + 1)); }
# Print a tool's captured output indented, so failures are self-explanatory.
show() { sed 's/^/      /' "$1"; }

# -- syntax ------------------------------------------------------------------
bad=()
scripts=("$SCRIPT_DIR"/*.sh)
for script in "${scripts[@]}"; do
  bash -n "$script" 2>"$WORK/bash-n.err" || bad+=("$(basename "$script"): $(cat "$WORK/bash-n.err")")
done
if [ "${#bad[@]}" -eq 0 ]; then
  pass syntax "bash -n: ${#scripts[@]} script(s) parse"
else
  fail syntax "${bad[*]}"
fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -x "$SCRIPT_DIR"/*.sh >"$WORK/shellcheck.out" 2>&1; then
    pass shellcheck "no findings"
  else
    fail shellcheck "see below"; show "$WORK/shellcheck.out"
  fi
else
  skip shellcheck "shellcheck not installed (optional)"
fi

# -- structure ---------------------------------------------------------------
if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
  if python3 "$SCRIPT_DIR/check_manifests.py" "$K8S_DIR" >"$WORK/structure.out" 2>&1; then
    pass structure "$(tail -n 1 "$WORK/structure.out")"
  else
    fail structure "see below"; show "$WORK/structure.out"
  fi
  if python3 "$SCRIPT_DIR/test_check_manifests.py" >"$WORK/selftest.out" 2>&1; then
    pass selftest "$(tail -n 1 "$WORK/selftest.out")"
  else
    fail selftest "see below"; show "$WORK/selftest.out"
  fi
else
  skip structure "python3 with PyYAML not found (pip install pyyaml) - cannot run check_manifests.py"
  skip selftest "python3 with PyYAML not found - cannot run test_check_manifests.py"
fi

# -- render ------------------------------------------------------------------
RENDER=()
if command -v kubectl >/dev/null 2>&1; then
  RENDER=(kubectl kustomize)
elif command -v kustomize >/dev/null 2>&1; then
  RENDER=(kustomize build)
fi

# expect FILE PATTERN DESCRIPTION / reject FILE PATTERN DESCRIPTION
# collect assertion failures for one rendered overlay into $problems.
problems=()
expect() { grep -Eq "$2" "$1" || problems+=("missing $3"); }
reject() { ! grep -Eq "$2" "$1" || problems+=("unexpected $3"); }

check_render() {
  local overlay="$1" out="$2"
  problems=()
  expect "$out" '^kind: Namespace$' "Namespace"
  expect "$out" '^  name: airweave$' "namespace named airweave"
  expect "$out" '^kind: Deployment$' "Deployment"
  expect "$out" '^  name: cloudflared$' "Deployment named cloudflared"
  expect "$out" '^  namespace: airweave$' "namespace airweave on resources"
  expect "$out" '^  name: airweave-backend-host$' "Service airweave-backend-host"
  expect "$out" 'externalName: host\.docker\.internal' "ExternalName -> host.docker.internal"
  expect "$out" '^  name: airweave-backend$' "Service airweave-backend"
  expect "$out" 'app\.kubernetes\.io/part-of: airweave' "part-of label"
  expect "$out" 'image: cloudflare/cloudflared:[0-9]{4}\.[0-9]+\.[0-9]+' "pinned cloudflared image"
  expect "$out" '^ +- --no-autoupdate$' "--no-autoupdate"
  expect "$out" '^ +- 0\.0\.0\.0:2000$' "--metrics 0.0.0.0:2000"
  expect "$out" 'path: /ready' "/ready probe"
  expect "$out" 'runAsNonRoot: true' "runAsNonRoot"
  expect "$out" 'readOnlyRootFilesystem: true' "readOnlyRootFilesystem"
  reject "$out" '^kind: Secret$' "Secret in the render (secrets must stay out of the kustomization)"
  case "$overlay" in
    token)
      expect "$out" 'name: TUNNEL_TOKEN' "TUNNEL_TOKEN env"
      expect "$out" 'name: cloudflared-token' "secretKeyRef cloudflared-token"
      reject "$out" '^ +- --config$' "--config in the token overlay"
      reject "$out" '^kind: ConfigMap$' "ConfigMap in the token overlay"
      ;;
    config)
      expect "$out" '^kind: ConfigMap$' "ConfigMap"
      expect "$out" 'name: cloudflared-config-[0-9a-z]+' "hash-suffixed ConfigMap name"
      expect "$out" '^  config\.yml: \|' "config.yml key in the ConfigMap"
      expect "$out" '^ +- --config$' "--config flag"
      expect "$out" '^ +- /etc/cloudflared/config/config\.yml$' "config path"
      expect "$out" 'mountPath: /etc/cloudflared/config$' "ConfigMap mount at /etc/cloudflared/config"
      expect "$out" 'mountPath: /etc/cloudflared/creds$' "Secret mount at /etc/cloudflared/creds"
      reject "$out" 'mountPath: /etc/cloudflared$' "Secret nested inside the ConfigMap mount"
      expect "$out" 'secretName: cloudflared-credentials' "credentials Secret mount"
      reject "$out" 'TUNNEL_TOKEN' "TUNNEL_TOKEN in the config overlay"
      ;;
  esac
}

if [ "${#RENDER[@]}" -gt 0 ]; then
  for overlay in token config; do
    out="$WORK/$overlay.yaml"
    if ! "${RENDER[@]}" "$K8S_DIR/overlays/$overlay" >"$out" 2>"$WORK/$overlay.err"; then
      fail "render" "overlays/$overlay: ${RENDER[*]} failed"; show "$WORK/$overlay.err"
      rm -f "$out"
      continue
    fi
    check_render "$overlay" "$out"
    if [ "${#problems[@]}" -eq 0 ]; then
      pass render "overlays/$overlay: $(grep -c '^kind:' "$out") objects, all assertions hold (${RENDER[*]})"
    else
      fail render "overlays/$overlay: ${problems[*]}"
    fi
  done
else
  skip render "neither kubectl nor kustomize on PATH. Docker Desktop ships kubectl once Kubernetes" \
    "is enabled; or: curl -LO https://dl.k8s.io/release/\$(curl -Ls" \
    "https://dl.k8s.io/release/stable.txt)/bin/<os>/<arch>/kubectl"
fi

# -- schema ------------------------------------------------------------------
if command -v kubeconform >/dev/null 2>&1; then
  targets=()
  for overlay in token config; do
    [ -f "$WORK/$overlay.yaml" ] && targets+=("$WORK/$overlay.yaml")
  done
  targets+=("$K8S_DIR"/overlays/*/*.example.yaml)
  if [ "${#RENDER[@]}" -eq 0 ]; then
    # Without a renderer the base manifests are still plain objects worth checking.
    targets+=("$K8S_DIR"/base/namespace.yaml "$K8S_DIR"/base/deployment.yaml \
              "$K8S_DIR"/base/service-backend-host.yaml "$K8S_DIR"/base/service-backend.yaml)
  fi
  mkdir -p "$WORK/schemas"
  if kubeconform -strict -summary -kubernetes-version "$K8S_VERSION" -cache "$WORK/schemas" \
      "${targets[@]}" >"$WORK/kubeconform.out" 2>&1; then
    summary="$(grep -i '^Summary' "$WORK/kubeconform.out" || tail -n 1 "$WORK/kubeconform.out")"
    pass schema "kubeconform ($K8S_VERSION): $summary"
  elif grep -Eqi 'could not (download|find schema)|no such host|dial tcp|timeout|TLS|proxy|connection refused' \
      "$WORK/kubeconform.out"; then
    skip schema "kubeconform could not fetch schemas (offline?)"; show "$WORK/kubeconform.out"
  else
    fail schema "kubeconform reported invalid resources"; show "$WORK/kubeconform.out"
  fi
else
  skip schema "kubeconform not installed (https://github.com/yannh/kubeconform/releases)"
fi

# -- ingress -----------------------------------------------------------------
TUNNEL_CFG="$K8S_DIR/overlays/config/config.yml"
if command -v cloudflared >/dev/null 2>&1; then
  if cloudflared tunnel --config "$TUNNEL_CFG" ingress validate >"$WORK/ingress.out" 2>&1; then
    host="$(grep -Em1 '^[[:space:]]+- hostname:' "$TUNNEL_CFG" | sed -E 's/.*hostname:[[:space:]]*//')"
    rule="$(cloudflared tunnel --config "$TUNNEL_CFG" ingress rule \
      "https://${host:-unset}/health/ready" 2>&1 \
      | grep -E 'Matched rule|service:' | tr -s '[:space:]' ' ' || true)"
    version="$(cloudflared --version 2>/dev/null | awk '{print $3}')"
    pass ingress "cloudflared $version: config.yml OK; https://$host/ -> ${rule:-?}"
  else
    fail ingress "cloudflared rejected config.yml"; show "$WORK/ingress.out"
  fi
else
  skip ingress "cloudflared not installed (brew install cloudflared," \
    "or https://github.com/cloudflare/cloudflared/releases)"
fi

# -- summary -----------------------------------------------------------------
echo
echo "passed $PASSED, failed $FAILED, skipped $SKIPPED"
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
if [ "$STRICT" -eq 1 ] && [ "$SKIPPED" -gt 0 ]; then
  echo "strict mode: skipped checks count as failures" >&2
  exit 1
fi
