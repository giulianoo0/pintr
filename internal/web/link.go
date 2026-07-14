package web

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/random"
)

// Linking a ChatGPT account to a pintr user (browser paste flow): the user
// signs in at OpenAI, the callback lands on an unreachable localhost URL, and
// they paste that URL back here so we can exchange the code.

const setupRedirectURI = "http://localhost:1455/auth/callback"

type pendingLink struct {
	userID    string
	verifier  string
	createdAt time.Time
}

type linkStartPage struct {
	basePage
	AuthorizeURL string
	CSRF         string
	State        string
}

func (h *Handlers) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}

	verifier, challenge, err := codex.NewPKCE()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := random.Token(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	for key, entry := range h.pending {
		if time.Since(entry.createdAt) > codex.LoginTimeout {
			delete(h.pending, key)
		}
	}
	h.pending[state] = pendingLink{userID: session.User.ID, verifier: verifier, createdAt: time.Now()}
	h.mu.Unlock()

	renderTemplate(w, "linkstart", linkStartPage{
		basePage:     authedPage("link chatgpt"),
		AuthorizeURL: codex.AuthorizeURL(setupRedirectURI, challenge, state),
		CSRF:         session.CSRF,
		State:        state,
	})
}

func (h *Handlers) handleLinkFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}

	state := r.FormValue("state")
	h.mu.Lock()
	entry, exists := h.pending[state]
	delete(h.pending, state)
	h.mu.Unlock()

	linkErr := func(msg string) {
		renderMessage(w, authedPage("link chatgpt"), msg, "/dashboard", "back to dashboard")
	}
	if !exists || entry.userID != session.User.ID || time.Since(entry.createdAt) > codex.LoginTimeout {
		linkErr("that link attempt expired or was not yours. start over from the dashboard.")
		return
	}

	parsed, err := url.Parse(strings.TrimSpace(r.FormValue("callback_url")))
	if err != nil || parsed.Query().Get("code") == "" {
		linkErr("that url has no code in it. paste the full localhost url from the address bar.")
		return
	}
	if parsed.Query().Get("state") != state {
		linkErr("state mismatch. start over so a fresh login link is generated.")
		return
	}

	auth, err := codex.ExchangeCode(r.Context(), parsed.Query().Get("code"), setupRedirectURI, entry.verifier)
	if err != nil {
		log.Printf("link finish: code exchange: %v", err)
		linkErr("that code did not work — start over and paste a fresh callback url.")
		return
	}
	if err := codex.UpsertAccount(r.Context(), h.store, session.User.ID, auth); err != nil {
		log.Printf("link finish: upsert account: %v", err)
		linkErr("could not save the account. please try again.")
		return
	}
	h.analytics.Event("chatgpt_linked")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
