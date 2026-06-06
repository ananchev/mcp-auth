package internal

import "net/http"

// CORS wraps h with the cross-origin response headers that browser-based MCP
// clients (claude.ai web) require during discovery and the OAuth handshake.
//
// Without these headers the browser blocks claude.ai's fetches to the
// discovery / registration / token endpoints and the connector fails to add
// ("Couldn't reach the MCP server") even though the server is fully reachable
// for non-browser clients (curl, Claude Desktop/Code).
//
// Preflight OPTIONS requests are answered here directly with 204. CORS preflight
// requests by spec carry no credentials, so any auth challenge on them would
// abort the whole exchange.
//
// Authentication is via the Authorization: Bearer header, never cookies, so
// Access-Control-Allow-Credentials is intentionally not set; the request Origin
// is reflected (falling back to "*"). WWW-Authenticate must be exposed so the
// browser client can read the RFC 9728 resource_metadata pointer off a 401.
func CORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		hdr := w.Header()
		hdr.Set("Access-Control-Allow-Origin", origin)
		hdr.Add("Vary", "Origin")
		hdr.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		hdr.Set("Access-Control-Allow-Headers",
			"Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
		hdr.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		hdr.Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
