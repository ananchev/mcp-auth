# Deploy & Networking — mcp-auth

Same topology as the HealthBridge services. mcp-auth is the shared OAuth
Authorization Server; Resource Servers (sleep-mcp, later cycling-coach) trust its
HS256 tokens and advertise it in their RFC 9728 metadata.

```
Internet
  │
  ▼  Cloudflare (DNS proxy / orange cloud) — hides origin IP, terminates TLS.
  │   NO Cloudflare Access, NO Tunnel.
  ▼  router :443 → NPM (reverse proxy, on a SEPARATE LAN box)
  │   • proxy host: mcp-auth.<your-domain> → http://<docker-host-LAN-IP>:8092
  │   • Cloudflare-IP allowlist + `deny all` in the location block (only CF-proxied
  │     traffic reaches the origin).
  ▼  Docker host on the LAN — this compose stack publishes :8092
  ▼  mcp-auth container (:8092), /data volume holds the refresh-token store
```

The host **must be single-label** under your domain (e.g. `mcp-auth.<domain>`) so
Cloudflare Universal SSL covers it — 2-level subdomains get a TLS handshake failure.

## Deploy

```bash
cd deploy
cp .env.example .env          # fill MCP_PUBLIC_URL, MCP_OAUTH_USER/PASSWORD,
                              # MCP_OAUTH_SIGNING_KEY (== each RS's key), AUTH_PORT
docker compose up -d --build
```

- `MCP_OAUTH_SIGNING_KEY` **must match** every Resource Server (sleep-mcp's
  `MCP_OAUTH_SIGNING_KEY`), or tokens won't validate.
- The `mcp-auth-data` volume persists `/data/refresh.json` across `down`/`up`, so
  clients aren't forced to re-authenticate after a redeploy.
- Env or volume changes need `docker compose up -d --force-recreate`; code changes
  need `--build`.

## NPM proxy host

Create a proxy host for `mcp-auth.<your-domain>`:
- Forward to `http://<docker-host-LAN-IP>:8092`.
- Add the Cloudflare-IP allowlist + `deny all` in the Advanced/custom location config
  (same pattern as the other hosts), so only Cloudflare-proxied traffic is accepted.
- If the Docker host runs a firewall, allow the NPM box to reach `:8092`.

The dev NPM-flip tooling (`scripts/dev/npm-flip.sh`, `run-local.sh`) flips this same
proxy host between the Docker host (prod) and the laptop (dev) — `PROD_FORWARD_HOST`
is the Docker host's LAN IP.

## Verify after deploy (from outside, as a browser would)

```bash
curl -s https://mcp-auth.<your-domain>/.well-known/oauth-authorization-server | python3 -m json.tool
# every URL == https://mcp-auth.<your-domain> (NOT localhost); grant_types include refresh_token
curl -s https://mcp-auth.<your-domain>/healthz   # {"status":"ok"}
```
