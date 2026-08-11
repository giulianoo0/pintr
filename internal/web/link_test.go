package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giulianoo0/pintr/internal/store"
)

// stubChecker is a captcha verifier with a fixed verdict.
type stubChecker bool

func (s stubChecker) Check(*http.Request) bool { return bool(s) }

type linkHarness struct {
	handlers *Handlers
	cookie   string
	csrf     string
	userID   string
}

func newLinkHarness(t *testing.T, checker humanChecker) *linkHarness {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "web.db"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u, err := st.CreateUser(context.Background(), "dev@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, err := st.CreateSession(context.Background(), u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session, ok := st.LookupSession(context.Background(), cookie)
	if !ok {
		t.Fatal("session lookup failed")
	}
	return &linkHarness{
		handlers: &Handlers{store: st, turnstile: checker, pending: map[string]pendingLink{}},
		cookie:   cookie,
		csrf:     session.CSRF,
		userID:   u.ID,
	}
}

func (h *linkHarness) post(t *testing.T, path string, form url.Values, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("csrf", h.csrf)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: h.cookie})
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// The captcha is checked when linking STARTS (dashboard button, token seconds
// old), because the finish arrives only after the OpenAI round-trip — longer
// than a Turnstile token lives.
func TestLinkStartRejectsFailedCaptcha(t *testing.T) {
	h := newLinkHarness(t, stubChecker(false))
	rec := h.post(t, "/link/start", url.Values{}, h.handlers.handleLinkStart)
	if !strings.Contains(rec.Body.String(), "verification failed") {
		t.Fatalf("expected captcha rejection, got status %d body %q", rec.Code, rec.Body.String())
	}
	if len(h.handlers.pending) != 0 {
		t.Error("no pending link attempt should be created on captcha failure")
	}
}

// The finish step must NOT require a captcha token: it is protected by
// session + CSRF + the single-use state minted at start.
func TestLinkFinishSkipsCaptcha(t *testing.T) {
	h := newLinkHarness(t, stubChecker(false))
	h.handlers.pending["st1"] = pendingLink{userID: h.userID, verifier: "v", createdAt: time.Now()}

	rec := h.post(t, "/link/finish", url.Values{"state": {"st1"}, "callback_url": {"not-a-url"}}, h.handlers.handleLinkFinish)
	if strings.Contains(rec.Body.String(), "verification failed") {
		t.Fatalf("finish must not run the captcha check, got %q", rec.Body.String())
	}
	// It got past the captcha and failed on the bogus callback url instead.
	if !strings.Contains(rec.Body.String(), "no code in it") {
		t.Errorf("expected callback-url validation error, got status %d body %q", rec.Code, rec.Body.String())
	}
}
