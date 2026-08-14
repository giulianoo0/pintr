package oauth

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

func newTestProvider(t *testing.T) *Provider {
	p, _ := newTestProviderWithUser(t)
	return p
}

func newTestProviderWithUser(t *testing.T) (*Provider, store.User) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "pintr.db"), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	user, err := st.CreateUser(context.Background(), "u@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return New("https://pintr.example", st), user
}

// consentForm returns a valid consent POST for a freshly registered client.
func consentForm(t *testing.T, p *Provider, csrf string) url.Values {
	t.Helper()
	clientID, err := p.sign(clientBlob{Kind: "client", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, IssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://claude.ai/api/mcp/auth_callback"},
		"response_type":         {"code"},
		"state":                 {"xyz"},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
		"resource":              {"https://pintr.example/mcp"},
		"csrf":                  {csrf},
	}
}

// A failed captcha check must re-render the consent form (fresh widget, fresh
// token) instead of a dead-end error page: Turnstile tokens are single-use, so
// "go back and click allow again" replays a spent token and can never succeed.
func TestConsentCaptchaFailureRerendersConsent(t *testing.T) {
	p, user := newTestProviderWithUser(t)
	session := store.SessionInfo{User: user, CSRF: "csrf-tok"}
	p.LookupSession = func(*http.Request) (store.SessionInfo, bool) { return session, true }
	p.VerifyHuman = func(*http.Request) bool { return false }

	var gotNotice string
	var gotQuery url.Values
	p.RenderConsent = func(w http.ResponseWriter, _ store.SessionInfo, query url.Values, notice string) {
		gotNotice, gotQuery = notice, query
		w.WriteHeader(http.StatusOK)
	}

	form := consentForm(t, p, session.CSRF)
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.handleAuthorize(rec, req)

	if gotNotice == "" {
		t.Fatalf("expected consent re-render with a notice, got status %d body %q", rec.Code, rec.Body.String())
	}
	if gotQuery.Get("client_id") == "" || gotQuery.Get("code_challenge") == "" {
		t.Errorf("re-render must carry the oauth params so the form can be resubmitted, got %v", gotQuery)
	}
	// The re-render needs the callback origin too, or the retry hits the CSP
	// wall that silently swallowed the redirect in the first place.
	if gotQuery.Get("redirect_uri") == "" {
		t.Error("re-render must carry redirect_uri so the consent CSP allows the callback")
	}
}

// With the captcha satisfied (or unconfigured), a CSRF-bound consent POST
// issues the code.
func TestConsentPostIssuesCode(t *testing.T) {
	p, user := newTestProviderWithUser(t)
	session := store.SessionInfo{User: user, CSRF: "csrf-tok"}
	p.LookupSession = func(*http.Request) (store.SessionInfo, bool) { return session, true }
	p.VerifyHuman = func(*http.Request) bool { return true }
	p.RenderConsent = func(http.ResponseWriter, store.SessionInfo, url.Values, string) {
		t.Error("valid consent POST should issue a code, not re-render")
	}

	form := consentForm(t, p, session.CSRF)
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.handleAuthorize(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect with a code, got %d body %q", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("redirect must carry an authorization code, got %q", rec.Header().Get("Location"))
	}
	if loc.Host != "claude.ai" || loc.Query().Get("state") != "xyz" {
		t.Errorf("redirect target wrong: %q", rec.Header().Get("Location"))
	}
}

// The GET consent render passes an empty notice.
func TestConsentGetRendersWithoutNotice(t *testing.T) {
	p := newTestProvider(t)
	session := store.SessionInfo{User: store.User{ID: "u1", Email: "u@example.com"}, CSRF: "csrf-tok"}
	p.LookupSession = func(*http.Request) (store.SessionInfo, bool) { return session, true }

	called := false
	p.RenderConsent = func(w http.ResponseWriter, _ store.SessionInfo, _ url.Values, notice string) {
		called = true
		if notice != "" {
			t.Errorf("GET render should have no notice, got %q", notice)
		}
	}

	form := consentForm(t, p, session.CSRF)
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+form.Encode(), nil)
	p.handleAuthorize(httptest.NewRecorder(), req)

	if !called {
		t.Fatal("expected consent to render")
	}
}
