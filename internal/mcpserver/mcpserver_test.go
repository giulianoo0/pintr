package mcpserver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

// Clients disagree on whether the model sees content or structuredContent, so
// the hosted result must carry the full serialized JSON as its own pure-JSON
// TextContent block — content-only clients (opencode, Grok Build) otherwise
// get the note but never the URLs.
func TestHostedCallResultCarriesJSON(t *testing.T) {
	result := generateImageResult{
		AssetURL:          "https://cdn.example/abc",
		DecryptedAssetURL: "https://pintr.example/view?o=abc&k=key",
		DecryptionKey:     "key",
		MimeType:          "image/png",
		Model:             "gpt-5.6-terra",
		Account:           "acct",
		SizeBytes:         42,
	}
	callResult, err := hostedCallResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(callResult.Content) != 2 {
		t.Fatalf("want 2 content blocks (note + JSON), got %d", len(callResult.Content))
	}
	note := callResult.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(note, "decrypted_asset_url") {
		t.Errorf("note must point at decrypted_asset_url, got: %s", note)
	}
	var parsed generateImageResult
	jsonBlock := callResult.Content[1].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(jsonBlock), &parsed); err != nil {
		t.Fatalf("second block must be pure JSON: %v\n%s", err, jsonBlock)
	}
	if parsed != result {
		t.Errorf("JSON block must round-trip the result, got %+v", parsed)
	}
}
