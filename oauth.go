package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// pintr acts as both the OAuth 2.1 resource server and authorization server
// for MCP clients (per the MCP authorization spec: RFC 9728 protected
// resource metadata, RFC 8414 AS metadata, RFC 7591 dynamic registration,
// authorization-code + PKCE, RFC 8707 resource audience binding).
//
// Everything is stateless: client ids, authorization codes, and tokens are
// HMAC-signed JSON blobs keyed off the access key, so restarts don't
// invalidate sessions and nothing needs a database.

const (
	authCodeTTL     = 5 * time.Minute
	accessTokenTTL  = 24 * time.Hour
	refreshTokenTTL = 90 * 24 * time.Hour
)

type oauthProvider struct {
	publicURL string // canonical base, e.g. https://pintr.giuli.dev
	accessKey string // shared secret: consent-page key, legacy bearer, HMAC key source
	store     *authStore
}

func newOAuthProvider(publicURL, accessKey string, store *authStore) *oauthProvider {
	return &oauthProvider{
		publicURL: strings.TrimRight(publicURL, "/"),
		accessKey: accessKey,
		store:     store,
	}
}

func (p *oauthProvider) signingKey() []byte {
	sum := sha256.Sum256([]byte("pintr-oauth-signing:" + p.accessKey))
	return sum[:]
}

// --- signed blob helpers ---

func (p *oauthProvider) sign(payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, p.signingKey())
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (p *oauthProvider) verify(blob string, payload any) bool {
	body, sig, found := strings.Cut(blob, ".")
	if !found {
		return false
	}
	wantSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, p.signingKey())
	mac.Write([]byte(body))
	if !hmac.Equal(mac.Sum(nil), wantSig) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, payload) == nil
}

type clientBlob struct {
	Kind         string   `json:"k"` // "client"
	RedirectURIs []string `json:"r"`
	IssuedAt     int64    `json:"iat"`
}

type codeBlob struct {
	Kind          string `json:"k"` // "code"
	ClientID      string `json:"c"`
	RedirectURI   string `json:"u"`
	CodeChallenge string `json:"ch"`
	Resource      string `json:"res"`
	Expires       int64  `json:"exp"`
}

type tokenBlob struct {
	Kind     string `json:"k"` // "access" | "refresh"
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
}

// --- metadata endpoints ---

func (p *oauthProvider) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"resource":                 p.publicURL,
		"authorization_servers":    []string{p.publicURL},
		"bearer_methods_supported": []string{"header"},
	})
}

func (p *oauthProvider) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.publicURL,
		"authorization_endpoint":                p.publicURL + "/authorize",
		"token_endpoint":                        p.publicURL + "/token",
		"registration_endpoint":                 p.publicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// --- dynamic client registration (RFC 7591) ---

func (p *oauthProvider) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRedirectURI(uri) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect uris must be localhost or https")
			return
		}
	}

	clientID, err := p.sign(clientBlob{Kind: "client", RedirectURIs: req.RedirectURIs, IssuedAt: time.Now().Unix()})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              req.RedirectURIs,
		"client_name":                req.ClientName,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

func validRedirectURI(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	host := parsed.Hostname()
	isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	return parsed.Scheme == "http" && isLoopback
}

// --- authorization endpoint ---

func (p *oauthProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		query = r.PostForm
	}

	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	challenge := query.Get("code_challenge")
	resource := strings.TrimRight(query.Get("resource"), "/")

	var client clientBlob
	if !p.verify(clientID, &client) || client.Kind != "client" {
		http.Error(w, "unknown client_id (register first)", http.StatusBadRequest)
		return
	}
	if !redirectURIRegistered(redirectURI, client.RedirectURIs) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}

	redirectError := func(code, description string) {
		target, _ := url.Parse(redirectURI)
		params := target.Query()
		params.Set("error", code)
		params.Set("error_description", description)
		if state != "" {
			params.Set("state", state)
		}
		target.RawQuery = params.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	}

	if query.Get("response_type") != "code" {
		redirectError("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if challenge == "" || query.Get("code_challenge_method") != "S256" {
		redirectError("invalid_request", "PKCE with S256 is required")
		return
	}
	if resource == "" {
		resource = p.publicURL
	}
	if !strings.EqualFold(resource, p.publicURL) {
		redirectError("invalid_target", "resource must be "+p.publicURL)
		return
	}

	// GET renders the consent form; POST checks the access key and redirects
	// back to the client with a code.
	if r.Method != http.MethodPost {
		renderAuthorizePage(w, query, "")
		return
	}
	if subtle.ConstantTimeCompare([]byte(query.Get("access_key")), []byte(p.accessKey)) != 1 {
		renderAuthorizePage(w, query, "wrong access key")
		return
	}

	code, err := p.sign(codeBlob{
		Kind:          "code",
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		Resource:      resource,
		Expires:       time.Now().Add(authCodeTTL).Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	target, _ := url.Parse(redirectURI)
	params := target.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	target.RawQuery = params.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectURIRegistered(uri string, registered []string) bool {
	for _, candidate := range registered {
		if candidate == uri {
			return true
		}
	}
	return false
}

func renderAuthorizePage(w http.ResponseWriter, query url.Values, problem string) {
	var hidden strings.Builder
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "resource", "scope"} {
		if value := query.Get(key); value != "" {
			fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, key, html.EscapeString(value))
		}
	}
	notice := ""
	if problem != "" {
		notice = `<p class="err">` + html.EscapeString(problem) + `</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, pageShell, "authorize pintr", notice+`
<p>an mcp client wants to use this pintr server. paste the access key to allow it.</p>
<form method="post" action="/authorize">`+hidden.String()+`
<input type="password" name="access_key" placeholder="access key" autofocus>
<button type="submit">allow</button>
</form>`)
}

// --- token endpoint ---

func (p *oauthProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "body must be form-encoded")
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.tokenFromCode(w, r)
	case "refresh_token":
		p.tokenFromRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (p *oauthProvider) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	var code codeBlob
	if !p.verify(r.PostForm.Get("code"), &code) || code.Kind != "code" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "bad authorization code")
		return
	}
	if time.Now().Unix() > code.Expires {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if uri := r.PostForm.Get("redirect_uri"); uri != "" && uri != code.RedirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if clientID := r.PostForm.Get("client_id"); clientID != "" && clientID != code.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if verifier == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != code.CodeChallenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	p.issueTokens(w, code.Resource)
}

func (p *oauthProvider) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	var refresh tokenBlob
	if !p.verify(r.PostForm.Get("refresh_token"), &refresh) || refresh.Kind != "refresh" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "bad refresh token")
		return
	}
	if time.Now().Unix() > refresh.Expires {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	p.issueTokens(w, refresh.Audience)
}

func (p *oauthProvider) issueTokens(w http.ResponseWriter, audience string) {
	access, err := p.sign(tokenBlob{Kind: "access", Audience: audience, Expires: time.Now().Add(accessTokenTTL).Unix()})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refresh, err := p.sign(tokenBlob{Kind: "refresh", Audience: audience, Expires: time.Now().Add(refreshTokenTTL).Unix()})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refresh,
	})
}

// --- bearer validation for MCP requests ---

// authenticate accepts either the static access key (scripts, curl) or an
// access token this server issued for itself (RFC 8707 audience check).
func (p *oauthProvider) authenticate(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	bearer, found := strings.CutPrefix(header, "Bearer ")
	if !found {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(bearer), []byte(p.accessKey)) == 1 {
		return true
	}

	var token tokenBlob
	if !p.verify(bearer, &token) || token.Kind != "access" {
		return false
	}
	if time.Now().Unix() > token.Expires {
		return false
	}
	return strings.EqualFold(strings.TrimRight(token.Audience, "/"), p.publicURL)
}

func (p *oauthProvider) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.authenticate(r) {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata=%q`, p.publicURL+"/.well-known/oauth-protected-resource"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

const pageShell = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
body{background:#111;color:#eee;font-family:system-ui,sans-serif;display:flex;justify-content:center;padding:3rem 1rem}
main{max-width:32rem;width:100%%}
h1{font-size:1.2rem}
input,textarea{width:100%%;box-sizing:border-box;background:#1c1c1c;color:#eee;border:1px solid #333;border-radius:6px;padding:.6rem;margin:.4rem 0;font-family:inherit}
button{background:#2b6cb0;color:#fff;border:0;border-radius:6px;padding:.6rem 1.2rem;margin-top:.4rem;cursor:pointer}
.err{color:#f87171}.ok{color:#4ade80}
a{color:#63b3ed;word-break:break-all}
code{background:#1c1c1c;padding:.1rem .3rem;border-radius:4px}
</style></head><body><main><h1>pintr</h1>%s</main></body></html>`
