// Package turnstile validates Cloudflare Turnstile tokens server-side
// (https://developers.cloudflare.com/turnstile/). It is optional: without
// both PINTR_TURNSTILE_SITE_KEY and PINTR_TURNSTILE_SECRET_KEY in the
// environment, New returns nil, no widget is rendered, and every Verify call
// passes.
package turnstile

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// SiteKey returns the public widget key, or "" when Turnstile is not
// configured. Templates use it to decide whether to render the widget.
func SiteKey() string { return strings.TrimSpace(os.Getenv("PINTR_TURNSTILE_SITE_KEY")) }

type Verifier struct {
	secret string
	client *http.Client
}

// New builds a verifier when both keys are configured, nil otherwise (a
// secret without a site key would block every form, since no widget would
// ever produce a token).
func New() *Verifier {
	secret := strings.TrimSpace(os.Getenv("PINTR_TURNSTILE_SECRET_KEY"))
	if secret == "" || SiteKey() == "" {
		if secret != "" || SiteKey() != "" {
			log.Print("turnstile: set BOTH PINTR_TURNSTILE_SITE_KEY and PINTR_TURNSTILE_SECRET_KEY — ignoring partial config")
		}
		return nil
	}
	return &Verifier{secret: secret, client: &http.Client{Timeout: 10 * time.Second}}
}

// Check reads the widget token from the request form and verifies it with
// Cloudflare. Nil-safe: a nil verifier (Turnstile disabled) always passes.
func (v *Verifier) Check(r *http.Request) bool {
	if v == nil {
		return true
	}
	return v.verify(r.Context(), r.FormValue("cf-turnstile-response"))
}

func (v *Verifier) verify(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	form := url.Values{"secret": {v.secret}, "response": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		log.Printf("turnstile: siteverify: %v", err)
		return false
	}
	defer resp.Body.Close()

	var payload struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}
	return payload.Success
}
