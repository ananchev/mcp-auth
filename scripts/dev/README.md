# mcp-auth — local dev (run + NPM flip)

Run the Authorization Server on your laptop and point `mcp-auth.example.com` at it via
NPM, so you can test the real CF→NPM→laptop path before deploying to Docker.

## One-time setup

1. In NPM, create a proxy host for **`mcp-auth.example.com`** (Cloudflare-proxied DNS
   record first), upstream temporarily anything — the flip overwrites it. Add the
   Cloudflare-IP allowlist + `deny all` like the other hosts. Note its proxy-host id.
2. `cp scripts/dev/.env.dev.example scripts/dev/.env.dev` and fill in:
   - `NPM_API_USER` / `NPM_API_PASSWORD` / `NPM_MCPAUTH_PROXY_ID`
   - `MCP_OAUTH_USER` / `MCP_OAUTH_PASSWORD`
   - `MCP_OAUTH_SIGNING_KEY` = `openssl rand -hex 32` — **use the same value in
     sleep-mcp** (`healthbridge/.env.dev`).
   - `LAPTOP_SUBNETS` to match your LAN/VPN.

## Run it (flipped)

```bash
./scripts/dev/run-local.sh        # flips NPM → laptop, builds + runs AS on :8092
# Ctrl-C reverts NPM to prod automatically.
```

Flip controls on their own:

```bash
./scripts/dev/npm-flip.sh status          # show current upstream
./scripts/dev/npm-flip.sh laptop 192.168.2.5
./scripts/dev/npm-flip.sh prod            # restore
```

## Validate

```bash
# discovery — every URL must be https://mcp-auth.example.com, grants include refresh_token
curl -s https://mcp-auth.example.com/.well-known/oauth-authorization-server | python3 -m json.tool

# mint a token without the browser (uses MCP_OAUTH_USER/PASSWORD/SIGNING_KEY)
go run ./cmd/mint -pass "$MCP_OAUTH_PASSWORD"
```

Then run sleep-mcp with the **same** signing key + `MCP_AUTH_SERVER_URL=https://mcp-auth.example.com`
and use that token against `https://mcp-healthbridge.example.com/mcp` (see
`healthbridge/docs/MCP_AUTH.md`). For local-only (no flip): `run-local.sh --no-flip`
with `MCP_PUBLIC_URL=http://localhost:8092` in `.env.dev`.
