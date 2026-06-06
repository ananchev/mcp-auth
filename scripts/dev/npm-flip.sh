#!/usr/bin/env bash
# mcp-auth/scripts/dev/npm-flip.sh — flip the mcp-auth NPM proxy upstream between
# prod and this laptop. Single proxy (mcp-auth.example.com).
#
# Mirrors the healthbridge flip's correctness properties: rollback stores the FULL
# writable proxy object, the flip mutates the top-level forward_host AND every
# per-location forward_host, and restore PUTs the saved object back wholesale.
#
# Commands:
#   npm-flip.sh laptop <ip>   flip the proxy (and its locations) to <ip>
#   npm-flip.sh prod          restore from the local rollback file
#   npm-flip.sh status        show the current upstream incl. per-location
#
# Reads scripts/dev/.env.dev (see .env.dev.example).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

set -a
# shellcheck disable=SC1091
source scripts/dev/.env.dev
set +a

: "${NPM_BASE_URL:?set NPM_BASE_URL in scripts/dev/.env.dev}"
: "${NPM_API_USER:?set NPM_API_USER in scripts/dev/.env.dev}"
: "${NPM_API_PASSWORD:?set NPM_API_PASSWORD in scripts/dev/.env.dev}"
: "${NPM_MCPAUTH_PROXY_ID:?set NPM_MCPAUTH_PROXY_ID in scripts/dev/.env.dev}"

LOCAL_ROLLBACK="/tmp/mcp-auth-npm-rollback.json"

die() { echo "npm-flip: $*" >&2; exit 1; }
log() { echo "npm-flip: $*"; }

get_token() {
    local resp token
    resp="$(curl -s -f -X POST "${NPM_BASE_URL}/api/tokens" \
        -H 'Content-Type: application/json' \
        -d "{\"identity\":\"${NPM_API_USER}\",\"secret\":\"${NPM_API_PASSWORD}\"}" 2>&1)" \
        || die "NPM auth request failed — check NPM_BASE_URL / NPM_API_USER / NPM_API_PASSWORD"
    token="$(echo "$resp" | jq -r '.token // empty')"
    [[ -n "$token" ]] || die "NPM auth: no token in response: $resp"
    echo "$token"
}

read_proxy() {
    curl -s -f "${NPM_BASE_URL}/api/nginx/proxy-hosts/${1}" \
        -H "Authorization: Bearer ${2}" || die "failed to read proxy host ${1}"
}

put_proxy() {
    curl -s -f -X PUT "${NPM_BASE_URL}/api/nginx/proxy-hosts/${1}" \
        -H "Authorization: Bearer ${2}" -H 'Content-Type: application/json' \
        -d "${3}" || die "failed to PUT proxy host ${1}"
}

writable_only() {
    echo "$1" | jq 'del(.id, .created_on, .modified_on, .owner_user_id,
                        .nginx_online, .nginx_err, .owner)'
}

flip_to_laptop_ip() {
    echo "$1" | jq --arg ip "$2" '
        .forward_host = $ip
        | .locations = ((.locations // []) | map(.forward_host = $ip))'
}

cmd_status() {
    local token proxy top locations
    token="$(get_token)"
    proxy="$(read_proxy "$NPM_MCPAUTH_PROXY_ID" "$token")"
    top="$(echo "$proxy" | jq -r '.forward_host')"
    locations="$(echo "$proxy" | jq -r \
        '[.locations // [] | .[] | "\(.path) → \(.forward_host):\(.forward_port)"] | join(", ")')"
    echo "proxy ${NPM_MCPAUTH_PROXY_ID}: forward_host=${top}  locations=[${locations:-none}]"
}

cmd_laptop() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || die "usage: npm-flip.sh laptop <ip>"
    local token raw writable flipped
    token="$(get_token)"
    raw="$(read_proxy "$NPM_MCPAUTH_PROXY_ID" "$token")"
    writable="$(writable_only "$raw")"
    echo "$writable" > "$LOCAL_ROLLBACK"
    log "rollback saved → $LOCAL_ROLLBACK"
    flipped="$(flip_to_laptop_ip "$writable" "$ip")"
    put_proxy "$NPM_MCPAUTH_PROXY_ID" "$token" "$flipped" > /dev/null
    log "proxy ${NPM_MCPAUTH_PROXY_ID} → ${ip}"
}

cmd_prod() {
    [[ -f "$LOCAL_ROLLBACK" ]] || die "no rollback at $LOCAL_ROLLBACK — run 'laptop <ip>' first"
    local token saved
    token="$(get_token)"
    saved="$(cat "$LOCAL_ROLLBACK")"
    put_proxy "$NPM_MCPAUTH_PROXY_ID" "$token" "$saved" > /dev/null
    log "proxy ${NPM_MCPAUTH_PROXY_ID} restored → $(echo "$saved" | jq -r '.forward_host')"
    rm -f "$LOCAL_ROLLBACK"
    log "rollback file removed"
}

case "${1:-}" in
    laptop) shift; cmd_laptop "$@" ;;
    prod)   cmd_prod ;;
    status) cmd_status ;;
    *) die "usage: laptop <ip> | prod | status" ;;
esac
