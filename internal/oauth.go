package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	authCodeTTL = 5 * time.Minute
	// tokenSubject is the single-user identity stamped into every token. This AS
	// authenticates one operator (MCP_OAUTH_USER); Resource Servers don't branch
	// on the subject, they only trust issuer + signature + expiry.
	tokenSubject = "user"
)

// OAuthServer is a standalone OAuth 2.1 Authorization Server.
//
// Supported grants:
//   - authorization_code + PKCE (S256) — for claude.ai and remote MCP clients.
//   - refresh_token (rotating, file-backed) — silent renewal without re-auth.
//
// It issues HS256 JWTs. Resource Servers validate them with the same signing key
// and issuer; this AS does not itself protect any resource.
type OAuthServer struct {
	publicURL        string
	username         string
	password         string
	signingKey       []byte
	tokenTTL         time.Duration
	allowedRedirects []string
	limiter          *ipLimiter
	refresh          *refreshStore

	mu    sync.Mutex
	codes map[string]*pendingCode
}

type pendingCode struct {
	redirectURI string
	challenge   string // base64url(SHA256(verifier))
	expiry      time.Time
}

// NewOAuthServer creates an OAuthServer from cfg, opening the file-backed refresh
// store (created on first write if absent).
func NewOAuthServer(cfg *Config) (*OAuthServer, error) {
	rs, err := newRefreshStore(cfg.RefreshStorePath, cfg.OAuthRefreshTTL)
	if err != nil {
		return nil, fmt.Errorf("open refresh store: %w", err)
	}
	return &OAuthServer{
		publicURL:        strings.TrimRight(cfg.PublicURL, "/"),
		username:         cfg.OAuthUser,
		password:         cfg.OAuthPassword,
		signingKey:       []byte(cfg.OAuthSigningKey),
		tokenTTL:         cfg.OAuthTokenTTL,
		allowedRedirects: cfg.OAuthAllowedRedirects,
		limiter:          newIPLimiter(20, time.Minute, 5, 15*time.Minute),
		refresh:          rs,
		codes:            make(map[string]*pendingCode),
	}, nil
}

// ── RFC 8414 metadata ────────────────────────────────────────────────────────

// Metadata serves GET /.well-known/oauth-authorization-server.
func (o *OAuthServer) Metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"issuer":                                o.publicURL,
		"authorization_endpoint":                o.publicURL + "/oauth/authorize",
		"token_endpoint":                        o.publicURL + "/oauth/token",
		"registration_endpoint":                 o.publicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// ── Dynamic Client Registration (RFC 7591 stub) ──────────────────────────────

// clientRegistrationRequest is the subset of RFC 7591 client metadata we read so
// it can be echoed back in the registration response.
type clientRegistrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	Scope        string   `json:"scope"`
}

// Register handles POST /register — a non-validating RFC 7591 stub that returns a
// fixed client_id (no client registry is maintained; client_id is not validated
// on token requests).
//
// RFC 7591 §3.2.1 requires the response to return the client's registered
// metadata. Strict clients (claude.ai) verify their redirect_uris round-trips
// here; if it is absent they treat registration as failed and abort before ever
// calling /oauth/authorize. So redirect_uris (plus client_name/scope) are echoed.
func (o *OAuthServer) Register(w http.ResponseWriter, r *http.Request) {
	if !o.limiter.allow(clientIP(r)) {
		oauthError(w, "too_many_requests", "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var req clientRegistrationRequest
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(body, &req) // tolerate empty/garbage bodies (stub)

	resp := map[string]any{
		"client_id":                  "mcp-oauth-client",
		"client_id_issued_at":        time.Now().Unix(),
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if len(req.RedirectURIs) > 0 {
		resp["redirect_uris"] = req.RedirectURIs
	}
	if req.ClientName != "" {
		resp["client_name"] = req.ClientName
	}
	if req.Scope != "" {
		resp["scope"] = req.Scope
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// ── Authorization Code flow ──────────────────────────────────────────────────

var authFormTmpl = template.Must(template.New("auth").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Authorize — MCP</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:80px auto;padding:0 20px}
h1{font-size:1.4rem;margin-bottom:.25rem}
p.sub{color:#555;font-size:.9rem;margin-bottom:1.5rem}
label{display:block;margin:.75rem 0 .25rem;font-weight:500}
input[type=password]{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{margin-top:1rem;padding:.6rem 1.4rem;font-size:1rem;background:#111;color:#fff;border:none;border-radius:4px;cursor:pointer}
.err{color:#c00;font-size:.9rem;margin-top:.5rem}
</style>
</head>
<body>
<h1>Authorize Access</h1>
<p class="sub">A client is requesting access to the requested MCP resource.</p>
<form method="POST">
<input type="hidden" name="redirect_uri"   value="{{.RedirectURI}}">
<input type="hidden" name="state"          value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<label for="pw">Password</label>
<input type="password" id="pw" name="password" autofocus required>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<button type="submit">Authorize</button>
</form>
</body>
</html>`))

type authFormData struct {
	RedirectURI   string
	State         string
	CodeChallenge string
	Error         string
}

// AuthorizeForm handles GET /oauth/authorize — validates params and renders the
// password consent form.
func (o *OAuthServer) AuthorizeForm(w http.ResponseWriter, r *http.Request) {
	if !o.limiter.allow(clientIP(r)) {
		oauthError(w, "too_many_requests", "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		oauthError(w, "unsupported_response_type", "only response_type=code is supported", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		oauthError(w, "invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || q.Get("code_challenge") == "" {
		oauthError(w, "invalid_request", "redirect_uri and code_challenge are required", http.StatusBadRequest)
		return
	}
	if !isAllowedRedirectURI(redirectURI, o.allowedRedirects) {
		oauthError(w, "invalid_request", "redirect_uri not allowed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	authFormTmpl.Execute(w, authFormData{ //nolint:errcheck
		RedirectURI:   redirectURI,
		State:         q.Get("state"),
		CodeChallenge: q.Get("code_challenge"),
	})
}

// AuthorizeSubmit handles POST /oauth/authorize — validates the password, issues
// an authorization code, and redirects to redirect_uri.
func (o *OAuthServer) AuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !o.limiter.allow(ip) {
		oauthError(w, "too_many_requests", "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	data := authFormData{
		RedirectURI:   r.FormValue("redirect_uri"),
		State:         r.FormValue("state"),
		CodeChallenge: r.FormValue("code_challenge"),
	}
	if !isAllowedRedirectURI(data.RedirectURI, o.allowedRedirects) {
		oauthError(w, "invalid_request", "redirect_uri not allowed", http.StatusBadRequest)
		return
	}
	if r.FormValue("password") != o.password {
		o.limiter.failure(ip)
		data.Error = "Incorrect password."
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		authFormTmpl.Execute(w, data) //nolint:errcheck
		return
	}
	o.limiter.success(ip)
	code, err := randomToken(32)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	o.mu.Lock()
	o.codes[code] = &pendingCode{
		redirectURI: data.RedirectURI,
		challenge:   data.CodeChallenge,
		expiry:      time.Now().Add(authCodeTTL),
	}
	o.mu.Unlock()

	target, err := url.Parse(data.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("code", code)
	if data.State != "" {
		q.Set("state", data.State)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// ── Token endpoint ───────────────────────────────────────────────────────────

// Token handles POST /oauth/token for authorization_code and refresh_token grants.
func (o *OAuthServer) Token(w http.ResponseWriter, r *http.Request) {
	if !o.limiter.allow(clientIP(r)) {
		oauthError(w, "too_many_requests", "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "cannot parse form", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		o.tokenAuthCode(w, r)
	case "refresh_token":
		o.tokenRefresh(w, r)
	default:
		oauthError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token", http.StatusBadRequest)
	}
}

func (o *OAuthServer) tokenAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || verifier == "" {
		oauthError(w, "invalid_request", "code and code_verifier are required", http.StatusBadRequest)
		return
	}
	o.mu.Lock()
	pending, ok := o.codes[code]
	if ok {
		delete(o.codes, code) // single-use
	}
	o.mu.Unlock()

	if !ok || time.Now().After(pending.expiry) {
		oauthError(w, "invalid_grant", "code not found or expired", http.StatusUnauthorized)
		return
	}
	if redirectURI != "" && redirectURI != pending.redirectURI {
		oauthError(w, "invalid_grant", "redirect_uri mismatch", http.StatusUnauthorized)
		return
	}
	if !verifyS256(verifier, pending.challenge) {
		oauthError(w, "invalid_grant", "PKCE verification failed", http.StatusUnauthorized)
		return
	}
	access, err := o.issueJWT(tokenSubject)
	if err != nil {
		oauthError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}
	refreshTok, err := o.refresh.issue(tokenSubject, "")
	if err != nil {
		oauthError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}
	writeToken(w, access, o.tokenTTL, refreshTok)
}

func (o *OAuthServer) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		oauthError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}
	subject, newRT, err := o.refresh.redeem(rt)
	if err != nil {
		oauthError(w, "invalid_grant", "refresh token invalid or expired", http.StatusUnauthorized)
		return
	}
	access, err := o.issueJWT(subject)
	if err != nil {
		oauthError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}
	writeToken(w, access, o.tokenTTL, newRT)
}

// ── JWT (HS256, no external dependency) ─────────────────────────────────────

func (o *OAuthServer) issueJWT(subject string) (string, error) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"sub": subject,
		"iss": o.publicURL,
		"iat": now.Unix(),
		"exp": now.Add(o.tokenTTL).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	claims := base64.RawURLEncoding.EncodeToString(payload)
	unsigned := hdr + "." + claims
	mac := hmac.New(sha256.New, o.signingKey)
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

// ── Helper for CLI / tests ───────────────────────────────────────────────────

// IssueROPC validates username+password and returns a signed access JWT without
// any HTTP round-trip. Used by the `mint` CLI and tests to obtain a token for a
// Resource Server without driving the browser flow.
func IssueROPC(o *OAuthServer, username, password string) (string, error) {
	if username != o.username || password != o.password {
		return "", fmt.Errorf("invalid credentials")
	}
	return o.issueJWT(tokenSubject)
}

// ── Package-level helpers ────────────────────────────────────────────────────

// isAllowedRedirectURI returns true when uri is in the configured allowlist or is
// any loopback URI (RFC 8252 §7.3: 127.0.0.1, localhost, ::1, any port).
func isAllowedRedirectURI(uri string, allowed []string) bool {
	for _, a := range allowed {
		if uri == a {
			return true
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() { // strips port and [] from IPv6
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// verifyS256 checks that SHA256(verifier) == base64url(challenge).
func verifyS256(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeToken(w http.ResponseWriter, access string, ttl time.Duration, refresh string) {
	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
	}
	if refresh != "" {
		resp["refresh_token"] = refresh
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

func oauthError(w http.ResponseWriter, code, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":             code,
		"error_description": desc,
	})
}
