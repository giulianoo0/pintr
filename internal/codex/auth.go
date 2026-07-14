// Package codex talks to OpenAI on the user's behalf: the ChatGPT OAuth
// login and token refresh, the Codex image-generation endpoint, and the
// rate-limit (usage) endpoint.
package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/giulianoo0/pintr/internal/random"
)

// OAuth constants mirror the public Codex CLI client (same values crevn uses).
const (
	oauthClientID     = "app_EMoamEEZ73f0CkXaXp7hrann"
	oauthIssuer       = "https://auth.openai.com"
	oauthTokenURL     = oauthIssuer + "/oauth/token"
	oauthScope        = "openid profile email offline_access api.connectors.read api.connectors.invoke"
	oauthRedirectPath = "/auth/callback"
	oauthOriginator   = "codex_cli_rs"

	// LoginTimeout bounds both the local browser login and the hosted
	// paste-the-URL linking flow.
	LoginTimeout = 5 * time.Minute

	tokenRefreshWindow = 5 * time.Minute
	tokenRefreshMaxAge = 8 * 24 * time.Hour
)

// Auth is a ChatGPT login: the OAuth tokens plus the account identity parsed
// from them. It is what the stdio auth file and the hosted store persist.
type Auth struct {
	IDToken      string    `json:"id_token"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccountID    string    `json:"account_id"`
	Email        string    `json:"email,omitempty"`
	PlanType     string    `json:"plan_type,omitempty"`
	Fedramp      bool      `json:"fedramp,omitempty"`
	LastRefresh  time.Time `json:"last_refresh"`
}

// AuthStore is the file-backed token store used in stdio mode.
type AuthStore struct {
	path string

	mu   sync.Mutex
	auth *Auth
}

func defaultAuthPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = "."
	}
	return filepath.Join(configDir, "pintr", "auth.json")
}

func NewAuthStore(path string) *AuthStore {
	if strings.TrimSpace(path) == "" {
		path = defaultAuthPath()
	}
	return &AuthStore{path: path}
}

func (s *AuthStore) load() (*Auth, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	var auth Auth
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	if auth.AccessToken == "" || auth.RefreshToken == "" || auth.AccountID == "" {
		return nil, fmt.Errorf("auth file %s is missing tokens; run `pintr login`", s.path)
	}
	return &auth, nil
}

func (s *AuthStore) save(auth *Auth) error {
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
func (s *AuthStore) fresh(ctx context.Context) (Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auth == nil {
		auth, err := s.load()
		if err != nil {
			return Auth{}, err
		}
		s.auth = auth
	}

	if !needsRefresh(s.auth, time.Now()) {
		return *s.auth, nil
	}
	return s.refreshLocked(ctx)
}

// forceRefresh refreshes the access token unconditionally (used after a 401).
func (s *AuthStore) forceRefresh(ctx context.Context) (Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auth == nil {
		auth, err := s.load()
		if err != nil {
			return Auth{}, err
		}
		s.auth = auth
	}
	return s.refreshLocked(ctx)
}

func (s *AuthStore) refreshLocked(ctx context.Context) (Auth, error) {
	updated, err := refreshAuth(ctx, *s.auth)
	if err != nil {
		return Auth{}, err
	}
	if err := s.save(&updated); err != nil {
		return Auth{}, fmt.Errorf("saving refreshed auth: %w", err)
	}
	s.auth = &updated
	return updated, nil
}

// refreshAuth exchanges the refresh token for a new access token. It does not
// persist anything — the caller decides where to store the result — so the
// file store and the DB store share this one implementation.
func refreshAuth(ctx context.Context, auth Auth) (Auth, error) {
	body, err := json.Marshal(map[string]string{
		"client_id":     oauthClientID,
		"grant_type":    "refresh_token",
		"refresh_token": auth.RefreshToken,
	})
	if err != nil {
		return Auth{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthTokenURL, bytes.NewReader(body))
	if err != nil {
		return Auth{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Auth{}, fmt.Errorf("token refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Auth{}, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var payload tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Auth{}, fmt.Errorf("token refresh: decoding response: %w", err)
	}

	auth.apply(payload)
	auth.LastRefresh = time.Now().UTC()
	return auth, nil
}

func needsRefresh(auth *Auth, now time.Time) bool {
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
func (a *Auth) apply(payload tokenResponse) {
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

// ExchangeCode swaps an authorization code (plus its PKCE verifier) for a
// full Auth. Used by both the local browser login and the hosted linking flow.
func ExchangeCode(ctx context.Context, code, redirectURI, verifier string) (*Auth, error) {
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

	auth := &Auth{LastRefresh: time.Now().UTC()}
	auth.apply(payload)
	if auth.AccessToken == "" || auth.RefreshToken == "" || auth.AccountID == "" {
		return nil, errors.New("OAuth response did not include a usable account")
	}
	return auth, nil
}

// AuthorizeURL builds the OpenAI sign-in URL for the Codex OAuth flow.
func AuthorizeURL(redirectURI, challenge, state string) string {
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

// NewPKCE returns a fresh PKCE verifier and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	verifier, err = random.Token(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
