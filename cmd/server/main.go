// Command server runs the standalone OAuth 2.1 Authorization Server.
//
// It exposes ONLY the OAuth surface (discovery, DCR, authorize, token). Resource
// Servers (e.g. sleep-mcp) validate the HS256 tokens it issues and advertise this
// AS in their own RFC 9728 protected-resource metadata.
package main

import (
	"log/slog"
	"net/http"
	"os"

	"mcp-auth/internal"
)

func main() {
	cfg, err := internal.LoadConfig()
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	oauthSrv, err := internal.NewOAuthServer(cfg)
	if err != nil {
		slog.Error("oauth server init failed", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauthSrv.Metadata)
	mux.HandleFunc("POST /register", oauthSrv.Register)
	mux.HandleFunc("GET /oauth/authorize", oauthSrv.AuthorizeForm)
	mux.HandleFunc("POST /oauth/authorize", oauthSrv.AuthorizeSubmit)
	mux.HandleFunc("POST /oauth/token", oauthSrv.Token)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	slog.Info("mcp-auth authorization server starting",
		"addr", cfg.HTTPAddr,
		"public_url", cfg.PublicURL,
		"oauth_enabled", cfg.OAuthSigningKey != "",
	)

	if err := http.ListenAndServe(cfg.HTTPAddr, internal.CORS(mux)); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
