package main

import (
	"crypto/subtle"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "pintr_session"
	sessionTTL        = 30 * 24 * time.Hour
)

type webHandlers struct {
	store         *store
	provider      *oauthProvider
	assets        *assetStore
	secureCookies bool

	mu      sync.Mutex
	pending map[string]pendingLink // OpenAI link attempts, keyed by state
}

type pendingLink struct {
	userID    string
	verifier  string
	createdAt time.Time
}

func newWebHandlers(st *store, provider *oauthProvider, assets *assetStore, secure bool) *webHandlers {
	return &webHandlers{store: st, provider: provider, assets: assets, secureCookies: secure, pending: map[string]pendingLink{}}
}

// --- session helpers (shared with oauth.go) ---

func sessionFromRequest(r *http.Request, st *store) (sessionInfo, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return sessionInfo{}, false
	}
	return st.lookupSession(r.Context(), cookie.Value)
}

func (h *webHandlers) setSession(w http.ResponseWriter, r *http.Request, u user) error {
	cookie, _, err := h.store.createSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

func (h *webHandlers) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: h.secureCookies, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// requireSession returns the session or redirects to /login and reports false.
func (h *webHandlers) requireSession(w http.ResponseWriter, r *http.Request) (sessionInfo, bool) {
	session, ok := sessionFromRequest(r, h.store)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return sessionInfo{}, false
	}
	return session, true
}

// checkCSRF enforces the session-bound token on authenticated POSTs. It also
// requires POST, so state changes can't be driven by a cross-site GET.
func (h *webHandlers) checkCSRF(w http.ResponseWriter, r *http.Request, session sessionInfo) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(session.CSRF)) != 1 {
		http.Error(w, "bad csrf token", http.StatusBadRequest)
		return false
	}
	return true
}

// Pre-session CSRF for login/signup (no session exists yet): a double-submit
// cookie. The token is set as a cookie and echoed in the form; a cross-site
// forger can't read or set the victim's cookie, so it can't match.
const formCSRFCookie = "pintr_form_csrf"

func (h *webHandlers) issueFormCSRF(w http.ResponseWriter) string {
	token, _ := randomToken(16)
	http.SetCookie(w, &http.Cookie{
		Name: formCSRFCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: h.secureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 1800,
	})
	return token
}

func (h *webHandlers) checkFormCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(formCSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.FormValue("csrf"))) == 1
}

// --- pages ---

func (h *webHandlers) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, ok := sessionFromRequest(r, h.store); ok {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	renderPage(w, "pintr", navPublic(), `
<div class="hero">
  <h1 class="hero-title">Codex image generation, over MCP.</h1>
  <p class="lead">pintr turns your own ChatGPT login into an image generator any
  MCP client can call. Sign in, link one or more accounts, and generate — no API
  key, nothing to install.</p>
  <div class="cta"><a href="/signup" class="btn">create account</a> <a href="/login">log in</a></div>
</div>
<div class="cards">
  <div class="card"><h3>your own login</h3><p>sign in with ChatGPT through OAuth — no separate API key or billing to set up.</p></div>
  <div class="card"><h3>encrypted by default</h3><p>generated images and uploads are encrypted at rest; the keys are returned once and never stored.</p></div>
  <div class="card"><h3>any mcp client</h3><p>connect Claude Code, OpenCode, PI, or any MCP client over HTTPS.</p></div>
</div>`)
}

func (h *webHandlers) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		token := h.issueFormCSRF(w)
		renderPage(w, "create account", navPublic(), fmt.Sprintf(`
<h2>create account</h2>
<form method="post" action="/signup">
%s
<input type="email" name="email" placeholder="email" autofocus required>
<input type="password" name="password" placeholder="password (8+ chars)" required>
<button type="submit">create account</button>
</form>
<p><a href="/login">already have an account? log in</a></p>`, csrfField(token)))
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}

	u, err := h.store.createUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		renderPage(w, "create account", navPublic(), `<p class="err">`+html.EscapeString(err.Error())+`</p><p><a href="/signup">try again</a></p>`)
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

func (h *webHandlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.FormValue("next"))
	if r.Method != http.MethodPost {
		token := h.issueFormCSRF(w)
		renderPage(w, "log in", navPublic(), fmt.Sprintf(`
<h2>log in</h2>
<form method="post" action="/login">
%s
<input type="hidden" name="next" value="%s">
<input type="email" name="email" placeholder="email" autofocus required>
<input type="password" name="password" placeholder="password" required>
<button type="submit">log in</button>
</form>
<p><a href="/signup">create an account</a></p>`, csrfField(token), html.EscapeString(next)))
		return
	}
	if !h.checkFormCSRF(r) {
		http.Error(w, "please reload the form and try again", http.StatusBadRequest)
		return
	}

	u, err := h.store.authenticateUser(r.Context(), r.FormValue("email"), r.FormValue("password"))
	if err != nil {
		renderPage(w, "log in", navPublic(), `<p class="err">`+html.EscapeString(err.Error())+`</p><p><a href="/login">try again</a></p>`)
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

func (h *webHandlers) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	accounts, err := h.store.listCodexAccounts(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	keys, err := h.store.listAccessKeys(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	csrf := html.EscapeString(session.CSRF)
	resource := html.EscapeString(h.provider.resourceURL)

	// --- accounts pane ---
	var accountsPane strings.Builder
	if len(accounts) == 0 {
		accountsPane.WriteString(`<p class="err">no chatgpt account linked yet. image generation will fail until you add one.</p>`)
	} else {
		for _, a := range accounts {
			badge := ""
			if a.IsDefault {
				badge = ` <span class="ok">· default</span>`
			}
			actions := ""
			if !a.IsDefault {
				actions += fmt.Sprintf(`<form method="post" action="/accounts/default" style="display:inline">%s<input type="hidden" name="id" value="%s"><button type="submit" class="link">make default</button></form> · `,
					csrfField(csrf), html.EscapeString(a.ID))
			}
			actions += fmt.Sprintf(`<form method="post" action="/accounts/remove" style="display:inline" onsubmit="return confirm('remove this account?')">%s<input type="hidden" name="id" value="%s"><button type="submit" class="link danger">remove</button></form>`,
				csrfField(csrf), html.EscapeString(a.ID))

			usageHTML := `<div class="limits">limits unavailable</div>`
			account := dbAccount{store: h.store, userID: session.User.ID, rowID: a.ID, display: orUnknown(a.Email)}
			if usage, uerr := fetchAccountUsage(r.Context(), account); uerr == nil {
				usageHTML = renderUsage(usage)
			}

			fmt.Fprintf(&accountsPane, `<div class="acct"><div class="acct-hd"><b>%s</b> <span class="muted">%s%s</span></div>%s<div class="acct-ft">%s</div></div>`,
				html.EscapeString(orUnknown(a.Email)), html.EscapeString(orUnknown(a.PlanType)), badge, usageHTML, actions)
		}
	}
	fmt.Fprintf(&accountsPane, `<form method="post" action="/link/start">%s<button type="submit">link a chatgpt account</button></form>`, csrfField(csrf))

	// --- access keys pane ---
	var keysPane strings.Builder
	keysPane.WriteString(`<p class="muted">optional. most clients use the browser oauth flow (see connect). a key lets scripts or a client config authenticate with <code>Authorization: Bearer &lt;key&gt;</code>.</p>`)
	if len(keys) > 0 {
		keysPane.WriteString(`<table><tr><th>key</th><th>name</th><th>created</th><th></th></tr>`)
		for _, k := range keys {
			fmt.Fprintf(&keysPane, `<tr><td><code>%s…</code></td><td>%s</td><td>%s</td><td><form method="post" action="/keys/remove" style="display:inline">%s<input type="hidden" name="id" value="%s"><button type="submit" class="link danger">revoke</button></form></td></tr>`,
				html.EscapeString(k.Prefix), html.EscapeString(k.Name), html.EscapeString(shortDate(k.CreatedAt)),
				csrfField(csrf), html.EscapeString(k.ID))
		}
		keysPane.WriteString(`</table>`)
	}
	fmt.Fprintf(&keysPane, `<form method="post" action="/keys/create">%s<input type="text" name="name" placeholder="key name (optional)"><button type="submit">new access key</button></form>`, csrfField(csrf))
	fmt.Fprintf(&keysPane, `<p><form method="post" action="/tokens/revoke" onsubmit="return confirm('sign out all mcp clients? they will have to authorize again.')">%s<button type="submit" class="link danger">revoke all mcp tokens</button></form></p>`, csrfField(csrf))

	// --- connect pane ---
	connectPane := `<p>add pintr to your mcp client by url. on first connect your browser opens; you log in to pintr and click allow, and the client keeps its own token (auto-refreshed).</p>
<h3>Claude Code</h3>
<p><code>claude mcp add --transport http pintr ` + resource + `</code></p>
<h3>OpenCode, PI, and other mcp clients</h3>
<p>add a remote (http) mcp server pointing at <code>` + resource + `</code>.</p>
<h2>use an access key instead (no oauth)</h2>
<p>create a key in the access keys tab and pass it as a header (works in any client):</p>
<p><code>claude mcp add --transport http pintr ` + resource + ` --header "Authorization: Bearer pintr_YOURKEY"</code></p>`

	// --- data pane (account identity + assets + danger zone) ---
	var dataPane strings.Builder
	fmt.Fprintf(&dataPane, `<p class="whoami">signed in as <span class="email" title="hover to reveal">%s</span></p>`,
		html.EscapeString(session.User.Email))
	dataPane.WriteString(`<h2>generated assets</h2>`)
	if h.assets == nil {
		dataPane.WriteString(`<p>asset storage is not configured on this server.</p>`)
	} else {
		count, err := h.assets.countAssets(r.Context(), session.User.ID)
		if err != nil {
			log.Printf("dashboard: count assets: %v", err)
			dataPane.WriteString(`<p>your generated images are stored encrypted. decryption keys are only returned at generation time and never saved here, so images can't be viewed from this page.</p>`)
		} else {
			fmt.Fprintf(&dataPane, `<p>%d encrypted image(s) stored. decryption keys are only returned at generation time and never saved here, so images can't be viewed from this page.</p>`, count)
		}
		fmt.Fprintf(&dataPane, `<form method="post" action="/assets/purge" onsubmit="return confirm('permanently delete ALL your stored images? this cannot be undone.')">%s<button type="submit" class="link danger">delete all assets</button></form>`, csrfField(csrf))
	}
	fmt.Fprintf(&dataPane, `<h2 class="danger">danger zone</h2>
<p>delete your account and <b>everything</b> tied to it — linked chatgpt accounts, access keys, sessions, and all stored images. permanent, cannot be undone.</p>
<form method="post" action="/account/delete" onsubmit="return confirm('Delete your account and ALL data permanently? This cannot be undone.')">%s<button type="submit" class="danger-btn">delete my account</button></form>`, csrfField(csrf))

	// Radios first, then the header (with the sliding tabs + logout), then the
	// panes in <main> — so the CSS-only tabs (#radio:checked ~ header/main …)
	// can reach both the header indicator and the panes.
	var body strings.Builder
	body.WriteString(`<input class="dtab" type="radio" name="dtab" id="t-accounts" checked>
<input class="dtab" type="radio" name="dtab" id="t-keys">
<input class="dtab" type="radio" name="dtab" id="t-connect">
<input class="dtab" type="radio" name="dtab" id="t-data">`)
	fmt.Fprintf(&body, `<header><a href="/" class="logo">%s<span>pintr</span></a>
<nav class="tabs"><span class="slider"></span><label for="t-accounts">accounts</label><label for="t-keys">keys</label><label for="t-connect">connect</label><label for="t-data">data</label></nav>
<form method="post" action="/logout" class="logout">%s<button type="submit" class="link">log out</button></form></header>`,
		logoSVG, csrfField(csrf))
	fmt.Fprintf(&body, `<main><section class="tabpane" id="p-accounts">%s</section><section class="tabpane" id="p-keys">%s</section><section class="tabpane" id="p-connect">%s</section><section class="tabpane" id="p-data">%s</section></main>`,
		accountsPane.String(), keysPane.String(), connectPane, dataPane.String())

	renderDashboard(w, "pintr dashboard", body.String())
}

// --- linking a chatgpt account (browser paste flow) ---

func (h *webHandlers) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}

	verifier, challenge, err := newPKCEPair()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := randomToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	for key, entry := range h.pending {
		if time.Since(entry.createdAt) > loginTimeout {
			delete(h.pending, key)
		}
	}
	h.pending[state] = pendingLink{userID: session.User.ID, verifier: verifier, createdAt: time.Now()}
	h.mu.Unlock()

	authorizeURL := buildAuthorizeURL(setupRedirectURI, challenge, state)
	renderPage(w, "link chatgpt", navAuthed(), fmt.Sprintf(`
<h2>link a chatgpt account</h2>
<p>1. sign in to openai:</p>
<p><a href="%s" target="_blank" rel="noopener" class="btn">sign in with openai</a></p>
<p>2. your browser then tries to open a <code>localhost:1455</code> page and fails — that is expected. copy the full url from the address bar and paste it here:</p>
<form method="post" action="/link/finish">
%s
<input type="hidden" name="state" value="%s">
<textarea name="callback_url" rows="4" placeholder="http://localhost:1455/auth/callback?code=..." autofocus></textarea>
<button type="submit">finish linking</button>
</form>`, html.EscapeString(authorizeURL), csrfField(html.EscapeString(session.CSRF)), html.EscapeString(state)))
}

func (h *webHandlers) handleLinkFinish(w http.ResponseWriter, r *http.Request) {
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
		renderPage(w, "link chatgpt", navAuthed(), `<p class="err">`+html.EscapeString(msg)+`</p><p><a href="/dashboard">back to dashboard</a></p>`)
	}
	if !exists || entry.userID != session.User.ID || time.Since(entry.createdAt) > loginTimeout {
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

	auth, err := exchangeAuthorizationCode(r.Context(), parsed.Query().Get("code"), setupRedirectURI, entry.verifier)
	if err != nil {
		log.Printf("link finish: code exchange: %v", err)
		linkErr("that code did not work — start over and paste a fresh callback url.")
		return
	}
	if err := h.store.upsertCodexAccount(r.Context(), session.User.ID, auth); err != nil {
		log.Printf("link finish: upsert account: %v", err)
		linkErr("could not save the account. please try again.")
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- account & key mutations ---

func (h *webHandlers) handleAccountDefault(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.setDefaultCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *webHandlers) handleAccountRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.deleteCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *webHandlers) handleKeyRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.deleteAccessKey(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

// handleRevokeTokens bumps the user's token epoch, immediately invalidating all
// issued OAuth access and refresh tokens (the kill-switch for a leak).
func (h *webHandlers) handleRevokeTokens(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.revokeTokens(r.Context(), session.User.ID)
	})
}

// handleUpload accepts a reference image (raw bytes, bearer-authenticated),
// encrypts and stores it, and returns a short handle. The handle goes into a
// generate_image call instead of the image bytes, keeping large data out of the
// model's context. The upload is deleted the moment it's used.
func (h *webHandlers) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.provider.authenticatedUser(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.assets == nil {
		http.Error(w, "asset storage is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20)) // 25 MiB cap
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if mime := http.DetectContentType(body); !strings.HasPrefix(mime, "image/") {
		http.Error(w, "body is not an image", http.StatusBadRequest)
		return
	}
	handle, err := h.assets.putUploadEncrypted(r.Context(), user.ID, body)
	if err != nil {
		log.Printf("upload for %s: %v", user.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"ref": handle})
}

// handleDeleteAccount permanently deletes the user and everything they own:
// stored images in S3, then the DB row (which cascades to sessions, access
// keys, and linked codex accounts).
func (h *webHandlers) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	// Delete stored assets first; if that fails, keep the account so nothing is
	// left half-deleted and the user can retry.
	if h.assets != nil {
		if _, err := h.assets.deleteAll(r.Context(), session.User.ID); err != nil {
			log.Printf("delete account: purge assets for %s: %v", session.User.ID, err)
			http.Error(w, "could not delete your stored images — account NOT deleted, please try again", http.StatusInternalServerError)
			return
		}
	}
	if err := h.store.deleteUser(r.Context(), session.User.ID); err != nil {
		log.Printf("delete account %s: %v", session.User.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.clearSessionCookie(w)
	log.Printf("deleted account %s (%s)", session.User.ID, session.User.Email)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleAssetsPurge deletes all of the user's stored (encrypted) images.
func (h *webHandlers) handleAssetsPurge(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		if h.assets == nil {
			return nil
		}
		deleted, err := h.assets.deleteAll(r.Context(), session.User.ID)
		if err != nil {
			log.Printf("purge assets for %s: %v", session.User.ID, err)
			return err
		}
		log.Printf("purged %d assets for %s", deleted, session.User.ID)
		return nil
	})
}

func (h *webHandlers) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	key, err := h.store.createAccessKey(r.Context(), session.User.ID, r.FormValue("name"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	renderPage(w, "new access key", navAuthed(), fmt.Sprintf(`
<h2>new access key</h2>
<p>copy it now — it is shown only once:</p>
<p><code>%s</code></p>
<p><a href="/dashboard">back to dashboard</a></p>`, html.EscapeString(key)))
}

// mutate runs a session-checked, CSRF-checked change and returns to the dashboard.
func (h *webHandlers) mutate(w http.ResponseWriter, r *http.Request, fn func(sessionInfo) error) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	if err := fn(session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- consent page (called from oauth.go) ---

func renderConsent(w http.ResponseWriter, session sessionInfo, query url.Values) {
	var hidden strings.Builder
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "resource", "scope"} {
		if value := query.Get(key); value != "" {
			fmt.Fprintf(&hidden, `<input type="hidden" name="%s" value="%s">`, key, html.EscapeString(value))
		}
	}
	renderPage(w, "authorize", navAuthed(), fmt.Sprintf(`
<h2>authorize mcp client</h2>
<p>an mcp client wants to connect to pintr as <b>%s</b>.</p>
<form method="post" action="/authorize">
%s%s
<button type="submit">allow</button>
</form>
<p><a href="/dashboard">cancel</a></p>`, html.EscapeString(session.User.Email), hidden.String(), csrfField(html.EscapeString(session.CSRF))))
}

// --- rendering helpers ---

func csrfField(csrf string) string {
	return `<input type="hidden" name="csrf" value="` + csrf + `">`
}

// renderUsage draws the account's remaining rate limits (5h / weekly / monthly,
// whichever OpenAI exposes) as small bars.
func renderUsage(usage accountUsage) string {
	if len(usage.Windows) == 0 {
		return `<div class="limits">no rate-limit data</div>`
	}
	var b strings.Builder
	b.WriteString(`<div class="limits">`)
	for _, w := range usage.Windows {
		hue := "#4ade80" // green
		switch {
		case w.RemainingPercent <= 10:
			hue = "#f87171" // red
		case w.RemainingPercent <= 30:
			hue = "#fbbf24" // amber
		}
		fmt.Fprintf(&b,
			`<div class="lim"><span class="lim-k">%s</span><span class="bar"><span style="width:%.0f%%;background:%s"></span></span><span class="lim-v">%.0f%% left</span></div>`,
			html.EscapeString(w.Label), w.RemainingPercent, hue, w.RemainingPercent)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// sanitizeNext only allows a clean same-origin path, preventing open redirects
// after login. Backslashes are rejected because browsers normalize them to "/",
// turning "/\evil.com" into the protocol-relative "//evil.com".
func sanitizeNext(next string) string {
	if next == "" || strings.ContainsAny(next, "\\") {
		return "/dashboard"
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/dashboard"
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

func shortDate(rfc3339 string) string {
	if t, err := time.Parse(time.RFC3339, rfc3339); err == nil {
		return t.Format("2006-01-02")
	}
	return rfc3339
}

func securePageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Authenticated, user-specific pages: don't let a proxy cache them, and
	// don't let another site frame them (clickjacking on the consent page).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
}

func renderPage(w http.ResponseWriter, title, headerRight, body string) {
	securePageHeaders(w)
	fmt.Fprintf(w, pageShell, html.EscapeString(title), headerRight, body)
}

// renderDashboard renders the tabbed dashboard; body is the full <input>s +
// <header> + <main> markup built by handleDashboard.
func renderDashboard(w http.ResponseWriter, title, body string) {
	securePageHeaders(w)
	fmt.Fprintf(w, dashShell, html.EscapeString(title), body)
}

const setupRedirectURI = "http://localhost:1455/auth/callback"

const styles = `*{box-sizing:border-box}
body{background:#0f0f10;color:#e7e7e7;font-family:'Geist',system-ui,-apple-system,sans-serif;margin:0;line-height:1.55}
header{max-width:64rem;margin:0 auto;padding:1.1rem 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.logo{display:inline-flex;align-items:center;gap:.5rem;text-decoration:none;color:#fff;font-weight:700;font-size:1.15rem;letter-spacing:-.01em}
.logo svg{display:block}
.nav{display:flex;align-items:center;gap:1.1rem;font-size:.9rem}
.nav a{color:#bdbdbd;text-decoration:none;display:inline-flex;align-items:center}
.nav a:hover{color:#fff}
.nav a.btn-sm{background:#2b6cb0;color:#fff;border-radius:6px;padding:.4rem .85rem}
main{max-width:64rem;margin:0 auto;padding:1.4rem 1.5rem 3rem}
.hero{margin:1.5rem 0 .5rem}
.hero-title{font-size:2rem;font-weight:750;letter-spacing:-.02em;margin:0 0 .6rem;line-height:1.15}
input.dtab{position:absolute;opacity:0;width:0;height:0;pointer-events:none}
.tabs{position:relative;display:flex;width:22rem;max-width:100%%;background:#141416;border:1px solid #262626;border-radius:9px;padding:3px}
.tabs .slider{position:absolute;top:3px;left:3px;bottom:3px;width:calc((100%% - 6px)/4);background:#2b6cb0;border-radius:6px;transition:transform .28s cubic-bezier(.4,0,.2,1);z-index:0}
.tabs label{position:relative;z-index:1;flex:1;text-align:center;padding:.34rem .8rem;font-size:.85rem;color:#c9c9c9;cursor:pointer;white-space:nowrap;border-radius:6px}
.tabs label:hover{color:#fff}
#t-accounts:checked~header .slider{transform:translateX(0)}
#t-keys:checked~header .slider{transform:translateX(100%%)}
#t-connect:checked~header .slider{transform:translateX(200%%)}
#t-data:checked~header .slider{transform:translateX(300%%)}
#t-accounts:checked~header label[for=t-accounts],#t-keys:checked~header label[for=t-keys],#t-connect:checked~header label[for=t-connect],#t-data:checked~header label[for=t-data]{color:#fff}
.tabpane{display:none}
#t-accounts:checked~main #p-accounts,#t-keys:checked~main #p-keys,#t-connect:checked~main #p-connect,#t-data:checked~main #p-data{display:block}
.logout{display:inline;margin:0}
.whoami{color:#888;font-size:.85rem}
.email{filter:blur(4.5px);transition:filter .15s ease;cursor:default}
.email:hover{filter:none}
h2{font-size:1rem;margin:2.2rem 0 .6rem;color:#bdbdbd}
h3{margin:0 0 .3rem;font-size:.95rem}
.lead{font-size:1.1rem;color:#d4d4d4;max-width:44rem}
input,textarea{width:100%%;box-sizing:border-box;background:#1a1a1c;color:#e7e7e7;border:1px solid #333;border-radius:6px;padding:.55rem;margin:.35rem 0;font-family:inherit;max-width:26rem}
button{background:#2b6cb0;color:#fff;border:0;border-radius:6px;padding:.55rem 1.1rem;margin-top:.35rem;cursor:pointer;font-size:.95rem}
a.btn{display:inline-block;background:#2b6cb0;color:#fff;border-radius:6px;padding:.55rem 1.1rem;text-decoration:none;font-size:.95rem}
button.link{background:none;color:#63b3ed;padding:0;margin:0;font-size:.85rem}
button.danger{color:#f87171}
table{width:100%%;border-collapse:collapse;margin:.5rem 0}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #262626;font-size:.9rem}
th{color:#888;font-weight:500}
.err{color:#f87171}.ok{color:#4ade80}
h2.danger{color:#f87171;margin-top:2.5rem}
.danger-btn{background:#7f1d1d;color:#fff}
.muted{color:#888;font-size:.85rem}
a{color:#63b3ed}
code{background:#1a1a1c;padding:.15rem .4rem;border-radius:4px;word-break:break-all}
.cards{display:flex;flex-wrap:wrap;gap:1rem;margin:1.6rem 0}
.card{flex:1 1 15rem;border:1px solid #262626;border-radius:10px;padding:1.1rem;background:#151517}
.card p{margin:0;color:#9a9a9a;font-size:.85rem}
.cta{display:flex;gap:1rem;align-items:center;margin-top:1.5rem}
.acct{border:1px solid #262626;border-radius:8px;padding:.7rem .85rem;margin:.5rem 0;background:#151517}
.acct-hd{margin-bottom:.4rem}
.acct-ft{margin-top:.5rem;font-size:.85rem}
.limits{display:flex;flex-wrap:wrap;gap:.3rem 1.2rem}
.lim{display:flex;align-items:center;gap:.5rem;font-size:.8rem;color:#bbb}
.lim-k{min-width:3.2rem;color:#888;text-transform:uppercase;letter-spacing:.03em;font-size:.72rem}
.lim-v{min-width:4.5rem}
.bar{display:inline-block;width:90px;height:6px;background:#2a2a2e;border-radius:3px;overflow:hidden}
.bar>span{display:block;height:100%%}`

const docHead = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>` + styles + `</style></head><body>`

// pageShell: public/simple pages — logo left, nav right. Verbs: title, nav, body.
const pageShell = docHead + `
<header><a href="/" class="logo">` + logoSVG + `<span>pintr</span></a><nav class="nav">%s</nav></header>
<main>%s</main></body></html>`

// dashShell: the dashboard — the whole body (radios + header-with-tabs + main)
// is built by handleDashboard. Verbs: title, body.
const dashShell = docHead + `%s</body></html>`

const logoSVG = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="5" fill="#2b6cb0"/><circle cx="9" cy="9.5" r="1.9" fill="#fff"/><path d="M4.5 17.5l4.3-4.3 3 3 3.4-3.9 4.3 5z" fill="#fff"/></svg>`

const ghSVG = `<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9.6.1.8-.3.8-.6v-2c-3.2.7-3.9-1.5-3.9-1.5-.5-1.3-1.3-1.7-1.3-1.7-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.6-.3-5.3-1.3-5.3-5.8 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2a11.5 11.5 0 016 0c2.3-1.5 3.3-1.2 3.3-1.2.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.5-2.7 5.5-5.3 5.8.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z"/></svg>`

func navGitHub() string {
	return `<a class="gh" href="https://github.com/giulianoo0/pintr" target="_blank" rel="noopener" title="source on github">` + ghSVG + `</a>`
}

// navPublic is the header's right side for logged-out pages; navAuthed for
// logged-in pages.
func navPublic() string {
	return navGitHub() + `<a href="/login">log in</a><a href="/signup" class="btn-sm">sign up</a>`
}

func navAuthed() string {
	return navGitHub() + `<a href="/dashboard">dashboard</a>`
}
