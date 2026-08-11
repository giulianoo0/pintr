package oauth

import (
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
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "pintr.db"), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New("https://pintr.example", st)
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
	p := newTestProvider(t)
	session := store.SessionInfo{User: store.User{ID: "u1", Email: "u@example.com"}, CSRF: "csrf-tok"}
	p.LookupSession = func(*http.Request) (store.SessionInfo, bool) { return session, true }
	p.VerifyHuman = func(*http.Request) bool { return false }

	var gotNotice string
	var gotQuery url.Values
	p.RenderConsent = func(w http.ResponseWriter, _ store.SessionInfo, query url.Values, notice string) {
		gotNotice = notice
		gotQuery = query
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
