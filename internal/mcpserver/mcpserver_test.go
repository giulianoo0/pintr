package mcpserver

import (
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// The stdio and hosted servers must advertise only the reference mechanism
// that works in their mode — a shared description made agents upload even when
// a local file path would do.
func TestGenerateImageToolPerMode(t *testing.T) {
	stdio := generateImageTool(false)
	hosted := generateImageTool(true)

	stdioRefs := stdio.InputSchema.(*jsonschema.Schema).Properties["reference_images"].Description
	hostedRefs := hosted.InputSchema.(*jsonschema.Schema).Properties["reference_images"].Description

	if !strings.Contains(stdioRefs, "LOCAL FILE PATHS") {
		t.Errorf("stdio refs description must tell agents to pass local paths, got: %s", stdioRefs)
	}
	for _, banned := range []string{"/upload", "ref_"} {
		if strings.Contains(stdioRefs, banned) || strings.Contains(stdio.Description, banned) {
			t.Errorf("stdio tool must not mention %q anywhere", banned)
		}
	}

	if !strings.Contains(hostedRefs, "/upload") || !strings.Contains(hostedRefs, "ref_") {
		t.Errorf("hosted refs description must document the upload flow, got: %s", hostedRefs)
	}
	if strings.Contains(hosted.Description, "saved_path") {
		t.Error("hosted tool description must not mention saved_path")
	}
	if !strings.Contains(hosted.Description, "24 hours") {
		t.Error("hosted tool description must mention the 24h auto-delete")
	}
}
