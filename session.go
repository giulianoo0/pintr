package main

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Browser session cookies and the two CSRF schemes (session-bound tokens for
// authenticated POSTs, double-submit cookies for pre-session forms).

const (
	sessionCookieName = "pintr_session"
	sessionTTL        = 30 * 24 * time.Hour
)

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
