// Package runway talks to Runway's app API (api.runwayml.com) on behalf of a
// user, using the bearer token their browser session holds.
//
// Runway has no OAuth or public API key for these endpoints, so pintr cannot
// mint credentials: the user pastes the JWT their logged-in browser keeps in
// localStorage under RW_USER_TOKEN. Tokens are HS256, carry {id, email, exp},
// and live 30 days — there is no refresh endpoint, so an expired token is a
// re-paste, not a refresh. Nothing here ever logs the token.
package runway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIBase is the API origin. It is a variable so tests can point the client at
// an httptest server.
var APIBase = "https://api.runwayml.com"

const (
	// maxJSONBytes caps every JSON response we read, so a hostile or broken
	// upstream can't balloon server memory.
	maxJSONBytes = 4 << 20
	// requestTimeout bounds a single API call. Generation is polled across many
	// short calls rather than held open, so no call needs longer.
	requestTimeout = 60 * time.Second
)

// ErrUnauthorized means the token was rejected: expired (they live 30 days) or
// revoked by signing out of Runway. The fix is always to paste a fresh one.
var ErrUnauthorized = errors.New("runway rejected the token — it expired or was revoked; paste a fresh RW_USER_TOKEN in the pintr dashboard")

// ErrBusy is Runway's Explore-mode concurrency limit. How many generations may
// be in flight at once is Runway's business and has been observed to vary, so
// pintr does not hard-code a number — this error IS the limit, reported by
// Runway itself. Callers should surface it as "wait and retry", not as a
// failure of the request.
var ErrBusy = errors.New("runway is already running as many generations as this account may have in flight — wait for one to finish and try again")

// Client is a Runway API client bound to one user's token and team.
type Client struct {
	token  string
	teamID int64
	http   *http.Client
}

// NewClient builds a client for a token. teamID may be 0, in which case
// ResolveTeam must be called (or Team() stays 0 and calls that need it fail).
func NewClient(token string, teamID int64) *Client {
	return &Client{
		token:  strings.TrimSpace(token),
		teamID: teamID,
		http:   &http.Client{Timeout: requestTimeout},
	}
}

func (c *Client) Team() int64 { return c.teamID }

// Profile is the subset of GET /v1/profile pintr shows on the dashboard.
type Profile struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Plan     string `json:"plan"`
}

// Team is one workspace the token can act as.
type Team struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	TeamName string `json:"teamName"`
}

// TokenExpiry reads the exp claim out of the JWT without verifying the
// signature — only Runway can verify it. This is display metadata (so the
// dashboard can warn before a token lapses) and a cheap client-side sanity
// check, never an authorization decision.
func TokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("not a JWT (expected three dot-separated parts)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, errors.New("token payload is not valid base64url")
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, errors.New("token payload is not valid JSON")
	}
	if claims.Exp == 0 {
		return time.Time{}, errors.New("token has no exp claim")
	}
	return time.Unix(claims.Exp, 0).UTC(), nil
}

// GetProfile identifies the token's owner. It doubles as the token check when
// a user connects their account.
func (c *Client) GetProfile(ctx context.Context) (Profile, error) {
	var out struct {
		User Profile `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/profile", nil, &out); err != nil {
		return Profile{}, err
	}
	return out.User, nil
}

// ListTeams returns the workspaces the token can generate in. The first is
// used as the default asTeamId.
func (c *Client) ListTeams(ctx context.Context) ([]Team, error) {
	var out struct {
		Teams []Team `json:"teams"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/teams", nil, &out); err != nil {
		return nil, err
	}
	return out.Teams, nil
}

// do performs one JSON API call. body is marshaled when non-nil; out is
// unmarshaled when non-nil.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, APIBase+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	// Runway's API keys some behavior off the calling surface; "web" is the one
	// these endpoints are built for.
	req.Header.Set("X-Runway-Source-Application", "web")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errors.New("could not reach runway")
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBytes))
	if err != nil {
		return errors.New("could not read runway's response")
	}
	if err := statusError(resp.StatusCode, payload); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("runway returned an unexpected response for %s", path)
	}
	return nil
}

// statusError maps a non-2xx response to an error, preferring the API's own
// message. The response body is attacker-influenced only insofar as Runway is
// trusted, but it is still truncated before being surfaced.
func statusError(status int, payload []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	var apiErr struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(payload, &apiErr)
	detail := apiErr.Error
	if detail == "" {
		detail = apiErr.Message
	}
	detail = truncate(strings.TrimSpace(detail), 300)

	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusTooManyRequests:
		if detail != "" && strings.Contains(strings.ToLower(detail), "too many tasks") {
			return ErrBusy
		}
		if detail == "" {
			return ErrBusy
		}
		return fmt.Errorf("runway rate-limited the request: %s", detail)
	}
	if detail == "" {
		return fmt.Errorf("runway returned status %d", status)
	}
	return fmt.Errorf("runway error (%d): %s", status, detail)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
