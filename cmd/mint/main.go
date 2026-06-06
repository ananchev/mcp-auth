// Command mint prints a signed access token using the configured credentials,
// without driving the browser OAuth flow. Handy for exercising a Resource Server
// locally (e.g. curl the MCP endpoint with the printed Bearer token).
//
//	Usage: MCP_OAUTH_SIGNING_KEY=… MCP_OAUTH_USER=… MCP_OAUTH_PASSWORD=… \
//	       MCP_PUBLIC_URL=https://mcp-auth.example.com go run ./cmd/mint -pass <password>
package main

import (
	"flag"
	"fmt"
	"os"

	"mcp-auth/internal"
)

func main() {
	pass := flag.String("pass", os.Getenv("MCP_OAUTH_PASSWORD"), "operator password (defaults to MCP_OAUTH_PASSWORD)")
	flag.Parse()

	cfg, err := internal.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	srv, err := internal.NewOAuthServer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		os.Exit(1)
	}
	tok, err := internal.IssueROPC(srv, cfg.OAuthUser, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}
	fmt.Println(tok)
}
