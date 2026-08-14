package web

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/giulianoo0/pintr/internal/mcpserver"
	"github.com/giulianoo0/pintr/internal/store"
)

// formAction returns the form-action sources of a Content-Security-Policy.
func formAction(t *testing.T, policy string) string {
	t.Helper()
	for _, directive := range strings.Split(policy, ";") {
		if sources, ok := strings.CutPrefix(strings.TrimSpace(directive), "form-action "); ok {
			return sources
		}
	}
	t.Fatalf("no form-action directive in %q", policy)
	return ""
}

// The consent POST answers with a 302 to the MCP client's callback, and
// browsers match form-action against that redirect too — with a bare 'self'
// the authorization code never reaches the client and pairing hangs forever.
func TestConsentCSPAllowsClientCallbackOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	query := url.Values{
		"client_id":    {"cid"},
		"redirect_uri": {"http://127.0.0.1:49177/callback"},
		"state":        {"xyz"},
	}
	RenderConsent(rec, store.SessionInfo{User: store.User{Email: "u@example.test"}, CSRF: "tok"}, query, "")

	sources := formAction(t, rec.Header().Get("Content-Security-Policy"))
	if !strings.Contains(sources, "http://127.0.0.1:49177") {
		t.Errorf("consent form-action must allow the client callback origin, got %q", sources)
	}
	if !strings.Contains(sources, "'self'") {
		t.Errorf("consent form-action must still allow 'self' (the form posts to /authorize), got %q", sources)
	}
}

// Only the callback's origin is granted — not the whole scheme, and not any
// other host the client might name later.
func TestConsentCSPGrantsOnlyThatOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	query := url.Values{"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}}
	RenderConsent(rec, store.SessionInfo{}, query, "")

	sources := formAction(t, rec.Header().Get("Content-Security-Policy"))
	if !strings.Contains(sources, "https://claude.ai") {
		t.Errorf("form-action must allow the callback origin, got %q", sources)
	}
	if strings.Contains(sources, "auth_callback") {
		t.Errorf("form-action should carry the origin, not the path, got %q", sources)
	}
	for _, source := range strings.Fields(sources) {
		if source == "http:" || source == "https:" || strings.Contains(source, "*") {
			t.Errorf("form-action must not widen to a bare scheme or wildcard, got %q", sources)
		}
	}
}

// A missing or unparseable redirect_uri must not widen the policy. (The OAuth
// handler rejects those before rendering; this is the belt-and-braces half.)
func TestConsentCSPIgnoresUnusableRedirectURI(t *testing.T) {
	for _, redirect := range []string{"", "not a url", "/relative/only", "javascript:alert(1)"} {
		rec := httptest.NewRecorder()
		RenderConsent(rec, store.SessionInfo{}, url.Values{"redirect_uri": {redirect}}, "")

		if got := formAction(t, rec.Header().Get("Content-Security-Policy")); got != "'self'" {
			t.Errorf("redirect_uri %q must leave form-action at 'self', got %q", redirect, got)
		}
	}
}

// Ordinary pages keep the locked-down policy.
func TestNonConsentPagesKeepBareFormAction(t *testing.T) {
	if got := formAction(t, pageCSP); got != "'self'" {
		t.Errorf("default page form-action must be 'self', got %q", got)
	}
}

// pageCSP is built at init, consentCSP per request. They read the same env and
// constants, so the consent policy must differ from the page policy in
// form-action and nowhere else — a widened script-src or img-src here would be
// an accident.
func TestConsentCSPWidensOnlyFormAction(t *testing.T) {
	consent := consentCSP("http://127.0.0.1:49177/callback")
	want, got := directives(pageCSP), directives(consent)

	if len(want) != len(got) {
		t.Fatalf("directive count changed:\n page:    %v\n consent: %v", want, got)
	}
	for name, source := range want {
		if name == "form-action" {
			continue
		}
		if got[name] != source {
			t.Errorf("directive %q changed: page %q, consent %q", name, source, got[name])
		}
	}
}

// directives splits a policy into name -> sources.
func directives(policy string) map[string]string {
	out := map[string]string{}
	for _, directive := range strings.Split(policy, ";") {
		name, sources, _ := strings.Cut(strings.TrimSpace(directive), " ")
		out[name] = sources
	}
	return out
}

// Render the dashboard with asset storage configured — that branch can't be
// exercised in a smoke test without real S3 credentials.
func TestDashboardTemplateWithAssets(t *testing.T) {
	page := dashboardPage{
		Title:            "pintr dashboard",
		CSRF:             "csrf-token",
		Resource:         "https://example.test/mcp",
		Email:            "user@example.test",
		AssetsConfigured: true,
		AssetCountKnown:  true,
		AssetCount:       3,
		UploadCountKnown: true,
		UploadCount:      2,
	}
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "dashboard", page); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		"<b>3</b> generated image(s)",
		"<b>2</b> reference upload(s)",
		`name="kind" value="generated"`,
		`name="kind" value="uploads"`,
		"auto-delete 24h after generation",
		"auto-delete 1h after upload",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard html missing %q", want)
		}
	}
}

// The footer always shows the version; the commit link only exists when the
// binary carries vcs info (go test builds don't, so exercise both by forcing
// a commit).
func TestFooterVersionAndCommit(t *testing.T) {
	saved := buildCommit
	defer func() { buildCommit = saved }()
	buildCommit = "0123456789abcdef0123456789abcdef01234567"

	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "footer", nil); err != nil {
		t.Fatalf("render footer: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		"v" + mcpserver.Version,
		`href="https://github.com/giulianoo0/pintr/commit/0123456789abcdef0123456789abcdef01234567"`,
		">0123456<",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("footer html missing %q", want)
		}
	}

	buildCommit = ""
	buf.Reset()
	if err := pageTemplates.ExecuteTemplate(&buf, "footer", nil); err != nil {
		t.Fatalf("render footer without commit: %v", err)
	}
	if strings.Contains(buf.String(), "/commit/") {
		t.Errorf("footer must omit the commit link without vcs info, got: %s", buf.String())
	}
}

func TestDocsRedirect(t *testing.T) {
	rec := httptest.NewRecorder()
	handleDocs(rec, httptest.NewRequest("GET", "/docs", nil))
	if rec.Code != 302 || rec.Header().Get("Location") != "/llms.txt" {
		t.Errorf("want 302 → /llms.txt, got %d → %q", rec.Code, rec.Header().Get("Location"))
	}
}
