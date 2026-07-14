package main

import (
	"net/http"
	"sync"
)

// webHandlers serves the browser-facing app: landing page, signup/login, and
// the dashboard. Related handlers live in dashboard.go, link.go, and
// actions.go; session/CSRF plumbing in session.go; rendering in views.go.
type webHandlers struct {
	store         *store
	provider      *oauthProvider
	assets        *assetStore
	secureCookies bool

	mu      sync.Mutex
	pending map[string]pendingLink // OpenAI link attempts, keyed by state
}

func newWebHandlers(st *store, provider *oauthProvider, assets *assetStore, secure bool) *webHandlers {
	return &webHandlers{store: st, provider: provider, assets: assets, secureCookies: secure, pending: map[string]pendingLink{}}
}

func (h *webHandlers) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := sessionFromRequest(r, h.store); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	renderTemplate(w, "index", publicPage("pintr"))
}

type signupPage struct {
	basePage
	CSRF string
}

func (h *webHandlers) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTemplate(w, "signup", signupPage{basePage: publicPage("create account"), CSRF: h.issueFormCSRF(w)})
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}

	u, err := h.store.createUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		renderMessage(w, publicPage("create account"), err.Error(), "/signup", "try again")
		return
	}
	if err := h.setSession(w, r, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// No access key is minted at signup: most people connect through the MCP
	// OAuth flow, and can create a key from the dashboard if they want one.
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

type loginPage struct {
	basePage
	CSRF string
	Next string
}

func (h *webHandlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.FormValue("next"))
	if r.Method != http.MethodPost {
		renderTemplate(w, "login", loginPage{basePage: publicPage("log in"), CSRF: h.issueFormCSRF(w), Next: next})
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}

	u, err := h.store.authenticateUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		renderMessage(w, publicPage("log in"), err.Error(), "/login", "try again")
		return
	}
	if err := h.setSession(w, r, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (h *webHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Require POST + a valid CSRF token so a cross-site GET/POST can't force logout.
	session, ok := sessionFromRequest(r, h.store)
	if ok && !h.checkCSRF(w, r, session) {
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.store.deleteSession(r.Context(), cookie.Value)
	}
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}
