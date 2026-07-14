// Package web serves the browser-facing app: landing page, signup/login, the
// dashboard, the ChatGPT linking flow, and the decrypted-asset viewer.
// Session/CSRF plumbing lives in session.go, rendering in views.go.
package web

import (
	"net/http"
	"strings"
	"sync"

	"github.com/giulianoo0/pintr/internal/analytics"
	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/store"
	"github.com/giulianoo0/pintr/internal/turnstile"
)

type Handlers struct {
	store         *store.Store
	provider      *oauth.Provider
	assets        *assets.Store       // nil when storage is unconfigured
	analytics     *analytics.Tracker  // nil when analytics is unconfigured
	turnstile     *turnstile.Verifier // nil when Turnstile is unconfigured
	secureCookies bool

	mu      sync.Mutex
	pending map[string]pendingLink // OpenAI link attempts, keyed by state
}

func New(st *store.Store, provider *oauth.Provider, assetStore *assets.Store, tracker *analytics.Tracker, verifier *turnstile.Verifier, secureCookies bool) *Handlers {
	// Social embeds (Open Graph/Twitter) need absolute URLs; derive the public
	// base once for the absURL template func.
	publicBase = strings.TrimSuffix(provider.ResourceURL(), "/mcp")
	return &Handlers{
		store:         st,
		provider:      provider,
		assets:        assetStore,
		analytics:     tracker,
		turnstile:     verifier,
		secureCookies: secureCookies,
		pending:       map[string]pendingLink{},
	}
}

// Register wires every browser-facing route into mux.
func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/signup", h.handleSignup)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/logout", h.handleLogout)
	mux.HandleFunc("/dashboard", h.handleDashboard)
	mux.HandleFunc("/link/start", h.handleLinkStart)
	mux.HandleFunc("/link/finish", h.handleLinkFinish)
	mux.HandleFunc("/accounts/default", h.handleAccountDefault)
	mux.HandleFunc("/accounts/remove", h.handleAccountRemove)
	mux.HandleFunc("/keys/create", h.handleKeyCreate)
	mux.HandleFunc("/keys/remove", h.handleKeyRemove)
	mux.HandleFunc("/tokens/revoke", h.handleRevokeTokens)
	mux.HandleFunc("/sessions/remove", h.handleSessionRemove)
	mux.HandleFunc("/usage/refresh", h.handleUsageRefresh)
	mux.HandleFunc("/assets/purge", h.handleAssetsPurge)
	mux.HandleFunc("/account/delete", h.handleDeleteAccount)
	mux.HandleFunc("/upload", h.handleUpload)
	mux.HandleFunc("/view", h.handleView)
	mux.HandleFunc("/llms.txt", handleLLMs)
	mux.Handle("/static/", staticHandler())
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/robots.txt", handleRobots)
	mux.HandleFunc("/", h.handleIndex)
}

func (h *Handlers) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := h.SessionFromRequest(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	renderTemplate(w, "index", publicPage("pintr"))
}

type signupPage struct {
	basePage
	CSRF string
}

func (h *Handlers) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTemplate(w, "signup", signupPage{basePage: publicPage("create account"), CSRF: h.issueFormCSRF(w)})
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}
	if !h.turnstile.Check(r) {
		renderMessage(w, publicPage("create account"), "verification failed — please try again", "/signup", "try again")
		return
	}

	u, err := h.store.CreateUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		renderMessage(w, publicPage("create account"), err.Error(), "/signup", "try again")
		return
	}
	if err := h.setSession(w, r, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.analytics.Event("signup")
	// No access key is minted at signup: most people connect through the MCP
	// OAuth flow, and can create a key from the dashboard if they want one.
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

type loginPage struct {
	basePage
	CSRF string
	Next string
}

func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.FormValue("next"))
	if r.Method != http.MethodPost {
		renderTemplate(w, "login", loginPage{basePage: publicPage("log in"), CSRF: h.issueFormCSRF(w), Next: next})
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}
	if !h.turnstile.Check(r) {
		renderMessage(w, publicPage("log in"), "verification failed — please try again", "/login", "try again")
		return
	}

	u, err := h.store.AuthenticateUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
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

func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Require POST + a valid CSRF token so a cross-site GET/POST can't force logout.
	session, ok := h.SessionFromRequest(r)
	if ok && !h.checkCSRF(w, r, session) {
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		h.store.DeleteSession(r.Context(), cookie.Value)
	}
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}
