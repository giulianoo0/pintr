package main

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// setupHandler links the server to a ChatGPT account entirely from the
// browser. The Codex OAuth client only redirects to localhost:1455, which is
// the *visitor's* machine, so nothing catches the callback; instead the user
// pastes the localhost URL from their address bar back into this page and we
// exchange the code server-side.
type setupHandler struct {
	provider *oauthProvider

	mu      sync.Mutex
	pending map[string]pendingLogin // state -> PKCE verifier
}

type pendingLogin struct {
	verifier  string
	createdAt time.Time
}

const setupRedirectURI = "http://localhost:1455/auth/callback"

func newSetupHandler(provider *oauthProvider) *setupHandler {
	return &setupHandler{provider: provider, pending: map[string]pendingLogin{}}
}

func (h *setupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("access_key")), []byte(h.provider.accessKey)) != 1 {
		h.renderKeyForm(w, r.Method == http.MethodPost)
		return
	}

	switch r.PostFormValue("step") {
	case "start":
		h.renderLoginStep(w)
	case "finish":
		h.finishLogin(w, r)
	default:
		h.renderStatus(w)
	}
}

func (h *setupHandler) renderKeyForm(w http.ResponseWriter, wrongKey bool) {
	notice := ""
	if wrongKey {
		notice = `<p class="err">wrong access key</p>`
	}
	fmt.Fprintf(w, pageShell, "pintr setup", notice+`
<p>server setup. paste the access key to continue.</p>
<form method="post" action="/setup">
<input type="password" name="access_key" placeholder="access key" autofocus>
<button type="submit">continue</button>
</form>`)
}

func (h *setupHandler) renderStatus(w http.ResponseWriter) {
	status := `<p class="err">not linked to a chatgpt account yet.</p>`
	if auth, err := h.provider.store.load(); err == nil {
		status = fmt.Sprintf(`<p class="ok">linked to %s (plan: %s).</p>`,
			html.EscapeString(orUnknown(auth.Email)), html.EscapeString(orUnknown(auth.PlanType)))
	}
	fmt.Fprintf(w, pageShell, "pintr setup", status+h.keptKeyForm("start", "link chatgpt account"))
}

func (h *setupHandler) renderLoginStep(w http.ResponseWriter) {
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
	h.pending[state] = pendingLogin{verifier: verifier, createdAt: time.Now()}
	h.mu.Unlock()

	authorizeURL := buildAuthorizeURL(setupRedirectURI, challenge, state)
	fmt.Fprintf(w, pageShell, "pintr setup", `
<p>1. open this link and sign in to openai:</p>
<p><a href="`+html.EscapeString(authorizeURL)+`" target="_blank">`+html.EscapeString(authorizeURL)+`</a></p>
<p>2. after signing in, the browser tries to open a <code>localhost:1455</code> page and fails. that is expected. copy the full url from the address bar and paste it here:</p>
<form method="post" action="/setup">
<input type="hidden" name="step" value="finish">
<input type="hidden" name="state" value="`+html.EscapeString(state)+`">`+h.hiddenKey()+`
<textarea name="callback_url" rows="4" placeholder="http://localhost:1455/auth/callback?code=..."></textarea>
<button type="submit">finish linking</button>
</form>`)
}

func (h *setupHandler) finishLogin(w http.ResponseWriter, r *http.Request) {
	pasted := strings.TrimSpace(r.PostFormValue("callback_url"))
	parsed, err := url.Parse(pasted)
	if err != nil || parsed.Query().Get("code") == "" {
		fmt.Fprintf(w, pageShell, "pintr setup", `<p class="err">that url has no code in it. paste the full localhost url from the address bar.</p>`+h.keptKeyForm("start", "try again"))
		return
	}

	state := r.PostFormValue("state")
	if callbackState := parsed.Query().Get("state"); callbackState != state {
		fmt.Fprintf(w, pageShell, "pintr setup", `<p class="err">state mismatch. start over so a fresh login link is generated.</p>`+h.keptKeyForm("start", "start over"))
		return
	}

	h.mu.Lock()
	entry, ok := h.pending[state]
	delete(h.pending, state)
	h.mu.Unlock()
	if !ok || time.Since(entry.createdAt) > loginTimeout {
		fmt.Fprintf(w, pageShell, "pintr setup", `<p class="err">this login attempt expired. start over.</p>`+h.keptKeyForm("start", "start over"))
		return
	}

	auth, err := exchangeAuthorizationCode(r.Context(), parsed.Query().Get("code"), setupRedirectURI, entry.verifier)
	if err != nil {
		fmt.Fprintf(w, pageShell, "pintr setup", `<p class="err">code exchange failed: `+html.EscapeString(err.Error())+`</p>`+h.keptKeyForm("start", "try again"))
		return
	}
	if err := h.provider.store.save(auth); err != nil {
		fmt.Fprintf(w, pageShell, "pintr setup", `<p class="err">saving tokens failed: `+html.EscapeString(err.Error())+`</p>`)
		return
	}
	h.provider.store.mu.Lock()
	h.provider.store.auth = auth
	h.provider.store.mu.Unlock()

	fmt.Fprintf(w, pageShell, "pintr setup", fmt.Sprintf(
		`<p class="ok">linked to %s (plan: %s). image generation is ready.</p>`,
		html.EscapeString(orUnknown(auth.Email)), html.EscapeString(orUnknown(auth.PlanType))))
}

func (h *setupHandler) hiddenKey() string {
	return `<input type="hidden" name="access_key" value="` + html.EscapeString(h.provider.accessKey) + `">`
}

func (h *setupHandler) keptKeyForm(step, label string) string {
	return `<form method="post" action="/setup">
<input type="hidden" name="step" value="` + step + `">` + h.hiddenKey() + `
<button type="submit">` + label + `</button>
</form>`
}
