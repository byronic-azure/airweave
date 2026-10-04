#!/usr/bin/env bash
# One command for the whole edge stack: Cloudflare Tunnel + DNS + Access, the
# airweave-edge-gateway Worker (KV, D1, secrets, Custom Domain) and the cloudflared
# connector in Docker Desktop Kubernetes, then an end-to-end smoke test.
#
# Usage:
#   export CLOUDFLARE_API_TOKEN=...                  # permissions: ./edge.sh help
#   ./edge.sh up --zone example.com                  # provision / reconcile, deploy, test
#   ./edge.sh plan                                   # what `up` would change (changes nothing)
#   ./edge.sh status                                 # tunnel, connector, end-to-end checks
#   ./edge.sh down --yes                             # remove what `up` created
#
# Installs the Worker's npm dependencies on first use, then runs
# worker/scripts/edge.mjs (Node.js 22+). Without bash (plain Windows), run
#   npm --prefix deploy/cloudflare/worker ci
#   npm --prefix deploy/cloudflare/worker run edge -- up --zone example.com
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$SCRIPT_DIR/../worker" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

command -v node >/dev/null 2>&1 || die "Node.js 22+ is required (https://nodejs.org)"
major="$(node -p 'process.versions.node.split(".")[0]')"
[ "$major" -ge 22 ] 2>/dev/null || die "Node.js 22+ is required (found $(node --version))"

if [ ! -f "$WORKER_DIR/node_modules/wrangler/bin/wrangler.js" ] \
    || [ ! -f "$WORKER_DIR/node_modules/jsonc-parser/package.json" ]; then
  echo "==> Installing the Worker's dependencies (npm ci, first run only)"
  (cd "$WORKER_DIR" && npm ci --no-audit --no-fund)
fi

exec node "$WORKER_DIR/scripts/edge.mjs" "$@"
