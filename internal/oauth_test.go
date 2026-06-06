package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testKey = "test-signing-key-32-bytes-minimum"

func newTestOAuthServer(t *testing.T) *OAuthServer {
	t.Helper()
	srv, err := NewOAuthServer(&Config{
		PublicURL:             "https://mcp-auth.example.com",
		OAuthUser:             "operator",
		OAuthPassword:         "secret",
		OAuthSigningKey:       testKey,
		OAuthTokenTTL:         time.Hour,
		OAuthRefreshTTL:       720 * time.Hour,
		OAuthAllowedRedirects: []string{"https://claude.ai/api/mcp/auth_callback"},
		RefreshStorePath:      filepath.Join(t.TempDir(), "refresh.json"),
	})
	if err != nil {
		t.Fatalf("NewOAuthServer: %v", err)
	}
	return srv
}

func testPKCE() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(h[:])
}

// verifyHS256 recomputes the HMAC and returns the decoded claims (mirrors how a
// Resource Server validates the AS's tokens).
func verifyHS256(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("malformed token %q", token)
	}
	mac := hmac.New(sha256.New, []byte(testKey))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		t.Fatal("signature mismatch")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func obtainCode(t *testing.T, srv *OAuthServer, challenge, redirectURI string) string {
	t.Helper()
	form := url.Values{
		"redirect_uri":   {redirectURI},
		"state":          {"s"},
		"code_challenge": {challenge},
		"password":       {"secret"},
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.AuthorizeSubmit(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status = %d: %s", w.Code, w.Body.String())
	}
	parsed, _ := url.Parse(w.Header().Get("Location"))
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	return code
}

func postToken(t *testing.T, srv *OAuthServer, form url.Values) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Token(w, r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}

// ── Metadata ─────────────────────────────────────────────────────────────────

func TestMetadata_AdvertisesRefreshGrant(t *testing.T) {
	srv := newTestOAuthServer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	srv.Metadata(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["issuer"] != "https://mcp-auth.example.com" {
		t.Errorf("issuer = %v", body["issuer"])
	}
	grants, _ := body["grant_types_supported"].([]any)
	hasCode, hasRefresh := false, false
	for _, g := range grants {
		switch g {
		case "authorization_code":
			hasCode = true
		case "refresh_token":
			hasRefresh = true
		}
	}
	if !hasCode || !hasRefresh {
		t.Errorf("grant_types_supported = %v, want both authorization_code and refresh_token", grants)
	}
}

// ── DCR ──────────────────────────────────────────────────────────────────────

func TestRegister_EchoesRedirectURIs(t *testing.T) {
	srv := newTestOAuthServer(t)
	r := httptest.NewRequest(http.MethodPost, "/register",
		strings.NewReader(`{"redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"client_name":"claude"}`))
	w := httptest.NewRecorder()
	srv.Register(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	var body map[string]any
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	uris, _ := body["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Errorf("redirect_uris not echoed: %v", body["redirect_uris"])
	}
}

// ── Authorize validation ─────────────────────────────────────────────────────

func TestAuthorizeForm_RejectsDisallowedRedirect(t *testing.T) {
	srv := newTestOAuthServer(t)
	q := url.Values{
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {"x"},
		"redirect_uri":          {"https://evil.example.com/cb"},
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	srv.AuthorizeForm(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for disallowed redirect", w.Code)
	}
}

// ── Authorization code flow ──────────────────────────────────────────────────

func TestAuthCodeFlow_IssuesAccessAndRefresh(t *testing.T) {
	srv := newTestOAuthServer(t)
	verifier, challenge := testPKCE()
	redirect := "https://claude.ai/api/mcp/auth_callback"
	code := obtainCode(t, srv, challenge, redirect)

	status, body := postToken(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d: %v", status, body)
	}
	access, _ := body["access_token"].(string)
	refresh, _ := body["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %v", body)
	}
	claims := verifyHS256(t, access)
	if claims["iss"] != "https://mcp-auth.example.com" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= time.Now().Unix() {
		t.Errorf("exp not in the future: %v", claims["exp"])
	}
}

func TestAuthCodeFlow_BadPKCE(t *testing.T) {
	srv := newTestOAuthServer(t)
	_, challenge := testPKCE()
	redirect := "https://claude.ai/api/mcp/auth_callback"
	code := obtainCode(t, srv, challenge, redirect)

	status, body := postToken(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"wrong-verifier"},
		"redirect_uri":  {redirect},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for bad PKCE: %v", status, body)
	}
}

// ── Refresh token flow ───────────────────────────────────────────────────────

func issueViaAuthCode(t *testing.T, srv *OAuthServer) (access, refresh string) {
	t.Helper()
	verifier, challenge := testPKCE()
	redirect := "https://claude.ai/api/mcp/auth_callback"
	code := obtainCode(t, srv, challenge, redirect)
	_, body := postToken(t, srv, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
	})
	return body["access_token"].(string), body["refresh_token"].(string)
}

func TestRefreshFlow_RotatesAndIssuesNew(t *testing.T) {
	srv := newTestOAuthServer(t)
	_, refresh := issueViaAuthCode(t, srv)

	status, body := postToken(t, srv, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d: %v", status, body)
	}
	newAccess, _ := body["access_token"].(string)
	newRefresh, _ := body["refresh_token"].(string)
	if newAccess == "" || newRefresh == "" {
		t.Fatalf("refresh did not return new tokens: %v", body)
	}
	if newRefresh == refresh {
		t.Error("refresh token was not rotated")
	}
	verifyHS256(t, newAccess) // must be a valid signed JWT
}

func TestRefreshFlow_ReuseRevokesFamily(t *testing.T) {
	srv := newTestOAuthServer(t)
	_, refresh := issueViaAuthCode(t, srv)

	// First use rotates successfully.
	status, body := postToken(t, srv, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusOK {
		t.Fatalf("first refresh failed: %d %v", status, body)
	}
	newRefresh := body["refresh_token"].(string)

	// Replaying the OLD (already-rotated) token must fail …
	status, _ = postToken(t, srv, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	if status != http.StatusUnauthorized {
		t.Fatalf("reuse of rotated token status = %d, want 401", status)
	}
	// … and revoke the whole family, so the rotated token is dead too.
	status, _ = postToken(t, srv, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {newRefresh}})
	if status != http.StatusUnauthorized {
		t.Fatalf("family not revoked: rotated token still works (status %d)", status)
	}
}

func TestRefreshFlow_MissingToken(t *testing.T) {
	srv := newTestOAuthServer(t)
	status, _ := postToken(t, srv, url.Values{"grant_type": {"refresh_token"}})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing refresh_token", status)
	}
}
