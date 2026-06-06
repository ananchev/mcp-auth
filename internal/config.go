package internal

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
//
// This is a standalone OAuth 2.1 Authorization Server (AS). It issues tokens
// for one or more Resource Servers (RS) that trust its signing key + issuer.
// It deliberately holds no resource/app config — resources advertise this AS
// in their own RFC 9728 protected-resource metadata.
type Config struct {
	HTTPAddr              string
	PublicURL             string
	OAuthUser             string
	OAuthPassword         string
	OAuthSigningKey       string
	OAuthTokenTTL         time.Duration
	OAuthRefreshTTL       time.Duration
	OAuthAllowedRedirects []string
	RefreshStorePath      string
}

// LoadConfig reads configuration from environment variables and validates it.
// In production (a signing key is set) the user/password must also be set, else
// the password consent form can never succeed.
func LoadConfig() (*Config, error) {
	c := &Config{
		HTTPAddr:              getEnv("MCP_HTTP_ADDR", ":8092"),
		PublicURL:             getEnv("MCP_PUBLIC_URL", "http://localhost:8092"),
		OAuthUser:             getEnv("MCP_OAUTH_USER", ""),
		OAuthPassword:         getEnv("MCP_OAUTH_PASSWORD", ""),
		OAuthSigningKey:       getEnv("MCP_OAUTH_SIGNING_KEY", ""),
		OAuthTokenTTL:         getEnvDuration("MCP_OAUTH_TOKEN_TTL", time.Hour),
		OAuthRefreshTTL:       getEnvDuration("MCP_OAUTH_REFRESH_TTL", 720*time.Hour),
		OAuthAllowedRedirects: getEnvCSV("MCP_OAUTH_ALLOWED_REDIRECTS"),
		RefreshStorePath:      getEnv("MCP_OAUTH_REFRESH_STORE", "/data/refresh.json"),
	}
	if c.OAuthSigningKey != "" && (c.OAuthUser == "" || c.OAuthPassword == "") {
		return nil, fmt.Errorf("MCP_OAUTH_USER and MCP_OAUTH_PASSWORD are required when MCP_OAUTH_SIGNING_KEY is set")
	}
	return c, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func getEnvCSV(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
