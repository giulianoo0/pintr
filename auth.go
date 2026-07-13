package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OAuth constants mirror the public Codex CLI client (same values crevn uses).
const (
	oauthClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	oauthIssuer       = "https://auth.openai.com"
	oauthTokenURL     = oauthIssuer + "/oauth/token"
	oauthScope        = "openid profile email offline_access api.connectors.read api.connectors.invoke"
	oauthRedirectPath = "/auth/callback"
	oauthOriginator   = "codex_cli_rs"

	loginTimeout       = 5 * time.Minute
	tokenRefreshWindow = 5 * time.Minute
	tokenRefreshMaxAge = 8 * 24 * time.Hour
)

// The Codex OAuth client only allows these localhost callback ports.
var oauthCallbackPorts = []int{1455, 1457}

type storedAuth struct {
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccountID    string    `json:"account_id"`
	Email        string    `json:"email,omitempty"`
	PlanType     string    `json:"plan_type,omitempty"`
	Fedramp      bool      `json:"fedramp,omitempty"`
	LastRefresh  time.Time `json:"last_refresh"`
}

type authStore struct {
	path string

	mu   sync.Mutex
	auth *storedAuth
}

func defaultAuthPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	return filepath.Join(configDir, "pintr", "auth.json")
}

func newAuthStore(path string) *authStore {
	if strings.TrimSpace(path) == "" {
		path = defaultAuthPath()
	}
	return &authStore{path: path}
}

func (s *authStore) load() (*storedAuth, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	var auth storedAuth
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	if auth.AccessToken == "" || auth.RefreshToken == "" || auth.AccountID == "" {
		return nil, fmt.Errorf("auth file %s is missing tokens; run `pintr login`", s.path)
	}
	return &auth, nil
}

func (s *authStore) save(auth *storedAuth) error {
	raw, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

// fresh returns auth with a usable access token, refreshing it when it is
// expired or close to expiring.
func (s *authStore) fresh(ctx context.Context) (storedAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auth == nil {
		auth, err := s.load()
		if err != nil {
			return storedAuth{}, err
		}
		s.auth = auth
	}

	if !needsRefresh(s.auth, time.Now()) {
		return *s.auth, nil
	}
	return s.refreshLocked(ctx)
}

// forceRefresh refreshes the access token unconditionally (used after a 401).
func (s *authStore) forceRefresh(ctx context.Context) (storedAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auth == nil {
		auth, err := s.load()
		if err != nil {
			return storedAuth{}, err
		}
		s.auth = auth
	}
	return s.refreshLocked(ctx)
}

func (s *authStore) refreshLocked(ctx context.Context) (storedAuth, error) {
	updated, err := refreshStoredAuth(ctx, *s.auth)
	if err != nil {
		return storedAuth{}, err
	}
	if err := s.save(&updated); err != nil {
		return storedAuth{}, fmt.Errorf("saving refreshed auth: %w", err)
	}
	s.auth = &updated
	return updated, nil
}

// refreshStoredAuth exchanges the refresh token for a new access token. It does
// not persist anything — the caller decides where to store the result — so the
// file store and the DB store share this one implementation.
func refreshStoredAuth(ctx context.Context, auth storedAuth) (storedAuth, error) {
	body, err := json.Marshal(map[string]string{
		"client_id":     oauthClientID,
		"grant_type":    "refresh_token",
		"refresh_token": auth.RefreshToken,
	})
	if err != nil {
		return storedAuth{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenURL, bytes.NewReader(body))
	if err != nil {
		return storedAuth{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return storedAuth{}, fmt.Errorf("token refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return storedAuth{}, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var payload tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return storedAuth{}, fmt.Errorf("token refresh: decoding response: %w", err)
	}

	auth.apply(payload)
	auth.LastRefresh = time.Now().UTC()
	return auth, nil
}

func needsRefresh(auth *storedAuth, now time.Time) bool {
	claims := parseJWTClaims(auth.AccessToken)
	if claims.Exp > 0 {
		expiresAt := time.Unix(claims.Exp, 0)
		return !now.Add(tokenRefreshWindow).Before(expiresAt)
	}
	if auth.LastRefresh.IsZero() {
		return true
	}
	return now.Sub(auth.LastRefresh) > tokenRefreshMaxAge
}

type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
}

// apply merges a token response into the stored auth, keeping existing values
// for fields the server omitted (refresh responses often omit refresh_token).
func (a *storedAuth) apply(payload tokenResponse) {
	if payload.IDToken != "" {
		a.IDToken = payload.IDToken
	}
	if payload.AccessToken != "" {
		a.AccessToken = payload.AccessToken
	}
	if payload.RefreshToken != "" {
		a.RefreshToken = payload.RefreshToken
	}

	idClaims := parseJWTClaims(a.IDToken)
	accessClaims := parseJWTClaims(a.AccessToken)
	switch {
	case payload.AccountID != "":
		a.AccountID = payload.AccountID
	case idClaims.Auth.ChatGPTAccountID != "":
		a.AccountID = idClaims.Auth.ChatGPTAccountID
	case accessClaims.Auth.ChatGPTAccountID != "":
		a.AccountID = accessClaims.Auth.ChatGPTAccountID
	}
	if idClaims.Email != "" {
		a.Email = idClaims.Email
	}
	if idClaims.Auth.ChatGPTPlanType != "" {
		a.PlanType = idClaims.Auth.ChatGPTPlanType
	} else if accessClaims.Auth.ChatGPTPlanType != "" {
		a.PlanType = accessClaims.Auth.ChatGPTPlanType
	}
	a.Fedramp = idClaims.Auth.Fedramp || accessClaims.Auth.Fedramp
}

type jwtClaims struct {
	Exp   int64  `json:"exp"`
	Email string `json:"email"`
	Auth  struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
		ChatGPTPlanType  string `json:"chatgpt_plan_type"`
		Fedramp          bool   `json:"chatgpt_account_is_fedramp"`
	} `json:"https://api.openai.com/auth"`
}

func parseJWTClaims(token string) jwtClaims {
	var claims jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return claims
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims
	}
	_ = json.Unmarshal(payload, &claims) // best effort: missing claims stay zero
	return claims
}

// ensureLoggedIn loads existing auth or runs the interactive browser login.
func ensureLoggedIn(ctx context.Context, store *authStore) error {
	_, err := store.load()
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	fmt.Fprintln(os.Stderr, "pintr: no saved OpenAI auth, starting browser login...")
	_, err = runLogin(ctx, store)
	return err
}

// runLogin performs the Codex browser OAuth flow (PKCE + localhost callback)
// and persists the resulting tokens.
func runLogin(ctx context.Context, store *authStore) (*storedAuth, error) {
	verifier, challenge, err := newPKCEPair()
	if err != nil {
		return nil, err
	}
	state, err := randomToken(16)
	if err != nil {
		return nil, err
	}

	listener, port, err := listenOnCallbackPort()
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	redirectURI := fmt.Sprintf("http://localhost:%d%s", port, oauthRedirectPath)
	authorizeURL := buildAuthorizeURL(redirectURI, challenge, state)

	results := make(chan oauthCallback, 1)
	server := &http.Server{Handler: callbackHandler(state, results)}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	fmt.Fprintf(os.Stderr, "\nOpen this URL to sign in to OpenAI:\n\n  %s\n\n", authorizeURL)
	fmt.Fprintf(os.Stderr, "Waiting for the browser callback on http://localhost:%d%s ...\n", port, oauthRedirectPath)
	fmt.Fprintln(os.Stderr, "(on a remote machine, tunnel first: ssh -L 1455:127.0.0.1:1455 <host>)")
	openBrowser(authorizeURL)

	var code string
	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		code = result.code
	case <-time.After(loginTimeout):
		return nil, errors.New("login timed out before the browser callback completed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	auth, err := exchangeAuthorizationCode(ctx, code, redirectURI, verifier)
	if err != nil {
		return nil, err
	}
	if err := store.save(auth); err != nil {
		return nil, fmt.Errorf("saving auth: %w", err)
	}

	store.mu.Lock()
	store.auth = auth
	store.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Logged in as %s (plan: %s, account: %s)\n", orUnknown(auth.Email), orUnknown(auth.PlanType), auth.AccountID)
	return auth, nil
}

type oauthCallback struct {
	code string
	err  error
}

func callbackHandler(state string, results chan<- oauthCallback) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oauthRedirectPath {
			http.NotFound(w, r)
			return
		}

		query := r.URL.Query()
		settle := func(code string, err error, message string) {
			once.Do(func() {
				results <- oauthCallback{code: code, err: err}
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><html><body><p>%s</p></body></html>", message)
		}

		if errParam := query.Get("error"); errParam != "" {
			settle("", fmt.Errorf("OAuth failed: %s", errParam), "Sign-in failed. You can close this window.")
			return
		}
		if query.Get("state") != state {
			settle("", errors.New("OAuth state mismatch"), "Sign-in state did not match. You can close this window.")
			return
		}
		code := query.Get("code")
		if code == "" {
			settle("", errors.New("OAuth callback did not include an authorization code"), "Sign-in did not return a code. You can close this window.")
			return
		}
		settle(code, nil, "Sign-in completed. You can close this window.")
	})
}

func exchangeAuthorizationCode(ctx context.Context, code, redirectURI, verifier string) (*storedAuth, error) {
	form := url.Values{
		"client_id":     {oauthClientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("code exchange failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var payload tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("code exchange: decoding response: %w", err)
	}

	auth := &storedAuth{LastRefresh: time.Now().UTC()}
	auth.apply(payload)
	if auth.AccessToken == "" || auth.RefreshToken == "" || auth.AccountID == "" {
		return nil, errors.New("OAuth response did not include a usable account")
	}
	return auth, nil
}

func buildAuthorizeURL(redirectURI, challenge, state string) string {
	query := url.Values{
		"response_type":              {"code"},
		"client_id":                  {oauthClientID},
		"redirect_uri":               {redirectURI},
		"scope":                      {oauthScope},
		"code_challenge":             {challenge},
		"code_challenge_method":      {"S256"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
		"state":                      {state},
		"originator":                 {oauthOriginator},
	}
	return oauthIssuer + "/oauth/authorize?" + query.Encode()
}

func listenOnCallbackPort() (net.Listener, int, error) {
	var errs []string
	for _, port := range oauthCallbackPorts {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return listener, port, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, 0, fmt.Errorf("could not bind an OAuth callback port %v: %s", oauthCallbackPorts, strings.Join(errs, "; "))
}

func newPKCEPair() (verifier, challenge string, err error) {
	verifier, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomToken(byteLen int) (string, error) {
	raw := make([]byte, byteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func openBrowser(target string) {
	for _, opener := range [][]string{{"xdg-open"}, {"open"}} {
		path, err := exec.LookPath(opener[0])
		if err != nil {
			continue
		}
		if exec.Command(path, target).Start() == nil {
			return
		}
	}
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
