package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// pintr is both the OAuth 2.1 resource server and authorization server for MCP
// clients (MCP authorization spec: RFC 9728 protected resource metadata, RFC
// 8414 AS metadata, RFC 7591 dynamic registration, auth-code + PKCE, RFC 8707
// resource audience binding). The resource owner is a pintr user: the authorize
// step requires a logged-in dashboard session, and issued tokens carry the
// user id so MCP calls resolve to that user's linked Codex accounts.
//
// Codes and tokens are stateless HMAC-signed JSON blobs (key derived from the
// server secret), so restarts keep sessions valid without a token table.
// The token endpoint and bearer authentication live in oauth_token.go.

const (
	authCodeTTL     = 5 * time.Minute
	accessTokenTTL  = 24 * time.Hour
	refreshTokenTTL = 90 * 24 * time.Hour
)

type oauthProvider struct {
	publicURL   string // https://pintr.giuli.dev
	resourceURL string // canonical MCP resource: publicURL + "/mcp"
	store       *store

	mu        sync.Mutex
	usedCodes map[string]int64 // code jti -> expiry unix; makes codes single-use
}

func newOAuthProvider(publicURL string, st *store) *oauthProvider {
	base := strings.TrimRight(publicURL, "/")
	return &oauthProvider{publicURL: base, resourceURL: base + "/mcp", store: st, usedCodes: map[string]int64{}}
}

// consumeCode marks an authorization code's jti as used and reports whether it
// was already spent, so a stateless code can't be replayed within its TTL.
func (p *oauthProvider) consumeCode(jti string, expires int64) (alreadyUsed bool) {
	now := time.Now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, exp := range p.usedCodes {
		if exp < now {
			delete(p.usedCodes, id)
		}
	}
	if _, seen := p.usedCodes[jti]; seen {
		return true
	}
	p.usedCodes[jti] = expires
	return false
}

// --- signed blobs ---

func (p *oauthProvider) sign(payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, p.store.signingKey())
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
	mac := hmac.New(sha256.New, p.store.signingKey())
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
	Kind         string   `json:"k"`
	RedirectURIs []string `json:"r"`
	IssuedAt     int64    `json:"iat"`
}

type codeBlob struct {
	Kind          string `json:"k"`
	JTI           string `json:"jti"`
	UserID        string `json:"uid"`
	Epoch         int    `json:"ep"`
	ClientID      string `json:"c"`
	RedirectURI   string `json:"u"`
	CodeChallenge string `json:"ch"`
	Resource      string `json:"res"`
	Expires       int64  `json:"exp"`
}

type tokenBlob struct {
	Kind     string `json:"k"` // "access" | "refresh"
	UserID   string `json:"uid"`
	SID      string `json:"sid"` // oauth_sessions row (per-session revoke)
	Epoch    int    `json:"ep"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
}

// --- metadata ---

func (p *oauthProvider) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"resource":                 p.resourceURL,
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

// --- dynamic client registration ---

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

// --- authorize ---

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
		resource = p.resourceURL
	}
	if !strings.EqualFold(resource, p.resourceURL) {
		redirectError("invalid_target", "resource must be "+p.resourceURL)
		return
	}

	// The resource owner must be a logged-in pintr user.
	session, ok := sessionFromRequest(r, p.store)
	if !ok {
		next := "/authorize?" + r.URL.Query().Encode()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	// GET renders consent; POST (with a valid CSRF token) grants the code.
	if r.Method != http.MethodPost {
		renderConsent(w, session, r.URL.Query())
		return
	}
	if subtle.ConstantTimeCompare([]byte(query.Get("csrf")), []byte(session.CSRF)) != 1 {
		http.Error(w, "bad csrf token", http.StatusBadRequest)
		return
	}

	epoch, ok := p.store.tokenEpoch(r.Context(), session.User.ID)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jti, err := randomToken(12)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code, err := p.sign(codeBlob{
		Kind:          "code",
		JTI:           jti,
		UserID:        session.User.ID,
		Epoch:         epoch,
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
