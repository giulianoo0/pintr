// Package analytics counts product events in Plausible through its Events
// API (https://plausible.io/docs/events-api). It is strictly anonymous and
// aggregate-only: an event is just a name — no user id, email, IP forwarding,
// prompt, or any other payload ever leaves the server. It is also entirely
// optional: without PINTR_PLAUSIBLE_DOMAIN in the environment New returns nil
// and every call is a no-op.
package analytics

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const eventsURL = "https://plausible.io/api/event"

type Tracker struct {
	domain string
	client *http.Client
}

// New builds a tracker for the site named by PINTR_PLAUSIBLE_DOMAIN (e.g.
// "pintr.giuli.dev"), or nil when the variable is unset.
func New() *Tracker {
	domain := strings.TrimSpace(os.Getenv("PINTR_PLAUSIBLE_DOMAIN"))
	if domain == "" {
		return nil
	}
	return &Tracker{domain: domain, client: &http.Client{Timeout: 5 * time.Second}}
}

// Event records one anonymous occurrence of name ("signup",
// "generate_image", …). Nil-safe and fire-and-forget: it never blocks or
// fails the caller.
func (t *Tracker) Event(name string) {
	if t == nil {
		return
	}
	payload, err := json.Marshal(map[string]string{
		"name":   name,
		"url":    "https://" + t.domain + "/",
		"domain": t.domain,
	})
	if err != nil {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, eventsURL, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		// A constant UA and no forwarded client address: every server-side
		// event is indistinguishable from the others, by design.
		req.Header.Set("User-Agent", "pintr-server")
		resp, err := t.client.Do(req)
		if err != nil {
			log.Printf("analytics: %s: %v", name, err)
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
	}()
}
