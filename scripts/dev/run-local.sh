#!/usr/bin/env bash
# mcp-auth/scripts/dev/run-local.sh — flip the mcp-auth NPM proxy to this laptop and
# run the AS in the FOREGROUND (live logs), so you can exercise mcp-auth.example.com
# through the real CF→NPM→laptop path before deploying to Docker. Reverts NPM on exit.
#
# Usage:
#   ./scripts/dev/run-local.sh              flip + run AS (foreground)
#   ./scripts/dev/run-local.sh --no-flip    localhost only, no NPM change
#   ./scripts/dev/run-local.sh --ip <addr>  force the laptop IP NPM points to
#
# Reads scripts/dev/.env.dev (NPM creds + the AS runtime env). Ctrl-C tears down.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

FLIP=1
IP_OVERRIDE=""
usage() { grep '^# ' "$0" | sed 's/^# //'; }
log() { echo "[run-local] $*"; }
die() { echo "[run-local] $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-flip) FLIP=0 ;;
        --ip)      IP_OVERRIDE="${2:?--ip needs an address}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
    shift
done

[[ -f scripts/dev/.env.dev ]] || die "missing scripts/dev/.env.dev — copy .env.dev.example"
set -a
# shellcheck disable=SC1091
source scripts/dev/.env.dev
set +a

detect_ip() {
    if [[ -n "$IP_OVERRIDE" ]]; then echo "$IP_OVERRIDE"; return; fi
    local addrs
    addrs="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || \
             ifconfig 2>/dev/null | awk '/inet /{print $2}')"
    for prefix in ${LAPTOP_SUBNETS:-}; do
        for a in $addrs; do
            [[ "$a" == "$prefix"* ]] && { echo "$a"; return; }
        done
    done
    die "no interface IP matches LAPTOP_SUBNETS (${LAPTOP_SUBNETS:-unset}); available: $addrs"
}

cleaned=0
cleanup() {
    (( cleaned )) && return
    cleaned=1
    if (( FLIP )); then
        log "reverting NPM upstream → prod"
        ./scripts/dev/npm-flip.sh prod || log "WARN: revert failed — run npm-flip.sh prod manually"
    fi
}
trap cleanup EXIT

if (( FLIP )); then
    LAPTOP_IP="$(detect_ip)"
    log "laptop IP: $LAPTOP_IP"
    log "flipping mcp-auth NPM upstream → $LAPTOP_IP"
    ./scripts/dev/npm-flip.sh laptop "$LAPTOP_IP"
    PUBLIC="${MCP_PUBLIC_URL:-https://mcp-auth.example.com}"
else
    log "--no-flip: NPM untouched; AS reachable on its bind address only"
    PUBLIC="${MCP_PUBLIC_URL:-http://localhost:8092}"
fi

BIN="$(mktemp -t mcp-auth-dev.XXXXXX)"
log "building AS …"
go build -o "$BIN" ./cmd/server
log "AS up. Issuer/public URL: ${PUBLIC}"
log "  discovery:  ${PUBLIC}/.well-known/oauth-authorization-server"
log "  mint a token (no browser): go run ./cmd/mint -pass \"\$MCP_OAUTH_PASSWORD\""
log "  Ctrl-C to stop (NPM auto-reverts)."

# Foreground (NOT exec) so the EXIT trap runs the NPM revert on Ctrl-C.
"$BIN"
