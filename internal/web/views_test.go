package web

import (
	"bytes"
	"strings"
	"testing"
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
		Script:           dashScript,
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
