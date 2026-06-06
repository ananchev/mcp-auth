# mcp-auth — standalone OAuth 2.1 Authorization Server for MCP

A small, dependency-free (Go stdlib only) OAuth 2.1 **Authorization Server (AS)**
for Model Context Protocol servers. It issues HS256 JWTs that one or more **Resource
Servers (RS)** — e.g. HealthBridge `sleep-mcp`, the cycling-coach MCP — validate with
the same signing key + issuer.

This is the classic OAuth split: **one AS, many RS**. The AS does not protect any
resource itself; each RS advertises this AS in its own RFC 9728
`/.well-known/oauth-protected-resource` metadata.

Carved out of the proven cycling-coach embedded AS, plus one addition: **refresh
tokens** (rotating, file-backed) so clients renew silently instead of re-authenticating.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata (issuer, endpoints, grants) |
| POST | `/register` | RFC 7591 DCR stub (echoes `redirect_uris`) |
| GET/POST | `/oauth/authorize` | Authorization Code + PKCE (S256), password consent |
| POST | `/oauth/token` | grants: `authorization_code`, `refresh_token` (rotating) |
| GET | `/healthz` | liveness |

## Tokens

- **Access**: HS256 JWT, claims `{sub, iss, iat, exp}`, no audience binding — any RS
  trusting the issuer + signing key accepts it. TTL `MCP_OAUTH_TOKEN_TTL` (default 1h).
- **Refresh**: opaque, rotating, SHA-256-hashed in a file-backed store
  (`MCP_OAUTH_REFRESH_STORE`). Each use rotates; replaying a rotated token revokes the
  whole family. TTL `MCP_OAUTH_REFRESH_TTL` (default 30d).

## Configuration

See `.env.example`. Required in prod: `MCP_PUBLIC_URL`, `MCP_OAUTH_SIGNING_KEY`,
`MCP_OAUTH_USER`, `MCP_OAUTH_PASSWORD`, `MCP_OAUTH_ALLOWED_REDIRECTS`.

## Run

```bash
go test ./... && go build ./cmd/server
set -a; source .env; set +a
./server
```

Mint a token without the browser flow (for testing an RS):

```bash
set -a; source .env; set +a
go run ./cmd/mint -pass "$MCP_OAUTH_PASSWORD"
```

## Deploy

`docker build` then run with `/data` mounted (refresh store) and the env above. Front
with Cloudflare (DNS proxy) → NPM (Cloudflare-IP allowlist + `deny all`) →
`mcp-auth.example.com`. Single-label host under `example.com` so Cloudflare Universal SSL
covers it. After deploy, verify discovery from outside:

```bash
curl -s https://mcp-auth.example.com/.well-known/oauth-authorization-server | python3 -m json.tool
# every URL must equal the public origin (not localhost); grant_types include refresh_token
```

## Security notes

- HS256 is symmetric: the signing secret is shared with every RS, so any RS could also
  mint tokens. Acceptable for one operator's own services. If untrusted RS are ever
  added, switch to RS256 + JWKS (RS hold only the public key).
- Rate limiting + failed-password lockout per IP (`ratelimit.go`).
- No client registry: `/register` is a stub; `client_id` is not validated (PKCE +
  redirect allowlist are the protections).
