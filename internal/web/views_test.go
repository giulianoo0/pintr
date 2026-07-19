package web

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giulianoo0/pintr/internal/mcpserver"
)

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
