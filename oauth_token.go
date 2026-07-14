package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The OAuth token endpoint (code + refresh grants) and bearer authentication
// for the /mcp and /upload endpoints.

type ctxKey string

const ctxUserKey ctxKey = "pintr-user"

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
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if verifier == "" || subtle.ConstantTimeCompare([]byte(computed), []byte(code.CodeChallenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if p.consumeCode(code.JTI, code.Expires) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used")
		return
	}
	sid, err := p.store.createOAuthSession(r.Context(), code.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p.issueTokens(w, code.UserID, sid, code.Resource, code.Epoch)
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
	// Reject refresh tokens whose session was revoked (per-session or a global
	// "revoke all", which bumps the epoch), or whose user was deleted.
	if !p.store.oauthSessionValid(r.Context(), refresh.SID, refresh.UserID, refresh.Epoch) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "session revoked")
		return
	}
	p.issueTokens(w, refresh.UserID, refresh.SID, refresh.Audience, refresh.Epoch)
}

func (p *oauthProvider) issueTokens(w http.ResponseWriter, userID, sid, audience string, epoch int) {
	access, err := p.sign(tokenBlob{Kind: "access", UserID: userID, SID: sid, Epoch: epoch, Audience: audience, Expires: time.Now().Add(accessTokenTTL).Unix()})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refresh, err := p.sign(tokenBlob{Kind: "refresh", UserID: userID, SID: sid, Epoch: epoch, Audience: audience, Expires: time.Now().Add(refreshTokenTTL).Unix()})
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

// --- request auth for /mcp ---

// authenticatedUser resolves the caller from either an issued OAuth access
// token (audience-checked) or a personal access key.
func (p *oauthProvider) authenticatedUser(r *http.Request) (user, bool) {
	bearer, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		return user{}, false
	}
	if strings.HasPrefix(bearer, "pintr_") {
		return p.store.userForAccessKey(r.Context(), bearer)
	}

	var token tokenBlob
	if !p.verify(bearer, &token) || token.Kind != "access" {
		return user{}, false
	}
	if time.Now().Unix() > token.Expires {
		return user{}, false
	}
	if !strings.EqualFold(strings.TrimRight(token.Audience, "/"), p.resourceURL) {
		return user{}, false
	}
	// Confirm the session still exists (per-session or global revoke, and user
	// deletion, all invalidate it here).
	if !p.store.oauthSessionValid(r.Context(), token.SID, token.UserID, token.Epoch) {
		return user{}, false
	}
	return user{ID: token.UserID}, true
}

func (p *oauthProvider) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := p.authenticatedUser(r)
		if !ok {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata=%q`, p.publicURL+"/.well-known/oauth-protected-resource"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUserKey, u)))
	})
}

func userFromContext(ctx context.Context) (user, bool) {
	u, ok := ctx.Value(ctxUserKey).(user)
	return u, ok
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
