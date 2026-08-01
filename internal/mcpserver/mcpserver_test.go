package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/assets"
)

type fakeReferenceDownloader struct {
	data  map[string][]byte
	calls []string
}

func (d *fakeReferenceDownloader) Download(_ context.Context, rawURL string) ([]byte, error) {
	d.calls = append(d.calls, rawURL)
	b, ok := d.data[rawURL]
	if !ok {
		return nil, errors.New("missing test image")
	}
	return b, nil
}

// The stdio and hosted servers must advertise only the reference mechanism
// that works in their mode — a shared description made agents upload even when
// a local file path would do.
func TestGenerateImageToolPerMode(t *testing.T) {
	stdio := generateImageTool(false)
	hosted := generateImageTool(true)

	meta := hosted.Meta["openai/fileParams"].([]string)
	if !slices.Equal(meta, []string{"reference_image_files"}) {
		t.Fatalf("file params = %#v", meta)
	}
	if _, ok := stdio.Meta["openai/fileParams"]; ok {
		t.Fatal("stdio tool advertises ChatGPT file params")
	}

	var hostedJSON, stdioJSON map[string]any
	for name, tc := range map[string]struct {
		tool *mcp.Tool
		out  *map[string]any
	}{
		"hosted": {tool: hosted, out: &hostedJSON},
		"stdio":  {tool: stdio, out: &stdioJSON},
	} {
		b, err := json.Marshal(tc.tool)
		if err != nil {
			t.Fatalf("marshal %s tool: %v", name, err)
		}
		if err := json.Unmarshal(b, tc.out); err != nil {
			t.Fatalf("unmarshal %s tool: %v", name, err)
		}
	}
	hostedProperties := hostedJSON["inputSchema"].(map[string]any)["properties"].(map[string]any)
	stdioProperties := stdioJSON["inputSchema"].(map[string]any)["properties"].(map[string]any)
	if _, ok := stdioProperties["reference_image_files"]; ok {
		t.Fatal("stdio schema advertises reference_image_files")
	}
	fileSchema, ok := hostedProperties["reference_image_files"].(map[string]any)
	if !ok {
		t.Fatal("hosted schema omits reference_image_files")
	}
	fileTypes := fileSchema["type"].([]any)
	if !slices.Contains(fileTypes, any("array")) {
		t.Fatalf("reference_image_files type = %#v", fileTypes)
	}
	itemSchema := fileSchema["items"].(map[string]any)
	itemProperties := itemSchema["properties"].(map[string]any)
	gotFields := make([]string, 0, len(itemProperties))
	for field := range itemProperties {
		gotFields = append(gotFields, field)
	}
	slices.Sort(gotFields)
	if want := []string{"download_url", "file_id", "file_name", "mime_type"}; !slices.Equal(gotFields, want) {
		t.Fatalf("reference file fields = %#v, want %#v", gotFields, want)
	}
	gotRequiredJSON := itemSchema["required"].([]any)
	gotRequired := make([]string, len(gotRequiredJSON))
	for i, field := range gotRequiredJSON {
		gotRequired[i] = field.(string)
	}
	slices.Sort(gotRequired)
	if want := []string{"download_url", "file_id"}; !slices.Equal(gotRequired, want) {
		t.Fatalf("reference file required fields = %#v, want %#v", gotRequired, want)
	}
	for _, required := range hostedJSON["inputSchema"].(map[string]any)["required"].([]any) {
		if required == "reference_image_files" {
			t.Fatal("reference_image_files must be optional")
		}
	}

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

	if !strings.Contains(hostedRefs, "request_reference_upload") || !strings.Contains(hostedRefs, "ref_") {
		t.Errorf("hosted refs description must direct Claude to the upload tool, got: %s", hostedRefs)
	}
	if !strings.Contains(hosted.Description, "reference_image_files") {
		t.Errorf("hosted description must direct ChatGPT to attachment parameters, got: %s", hosted.Description)
	}
	for _, banned := range []string{"curl", "Bearer", "/upload"} {
		if strings.Contains(hostedRefs, banned) || strings.Contains(hosted.Description, banned) {
			t.Errorf("hosted generate_image copy must not contain manual upload instruction %q", banned)
		}
	}
	if strings.Contains(hosted.Description, "saved_path") {
		t.Error("hosted tool description must not mention saved_path")
	}
	if !strings.Contains(hosted.Description, "24 hours") {
		t.Error("hosted tool description must mention the 24h auto-delete")
	}
}

func TestResolveHostedChatGPTFiles(t *testing.T) {
	t.Run("downloads and encodes attachments in argument order", func(t *testing.T) {
		downloader := &fakeReferenceDownloader{data: map[string][]byte{
			"https://files.example/first":  []byte("\x89PNG\r\n\x1a\none"),
			"https://files.example/second": []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00two"),
		}}
		files := []referenceImageFile{
			{DownloadURL: "https://files.example/first", FileID: "file-first", MIMEType: "image/png", FileName: "first.png"},
			{DownloadURL: "https://files.example/second", FileID: "file-second", MIMEType: "image/jpeg", FileName: "second.jpg"},
		}

		got, err := resolveHostedReferences(context.Background(), nil, "", nil, files, downloader)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{
			"data:image/png;base64,iVBORw0KGgpvbmU=",
			"data:image/jpeg;base64,/9j/4AAQSkZJRgB0d28=",
		}; !slices.Equal(got, want) {
			t.Fatalf("references = %#v, want %#v", got, want)
		}
		if want := []string{"https://files.example/first", "https://files.example/second"}; !slices.Equal(downloader.calls, want) {
			t.Fatalf("download calls = %#v, want %#v", downloader.calls, want)
		}
	})

	for _, tt := range []struct {
		name  string
		file  referenceImageFile
		field string
	}{
		{
			name:  "missing download URL",
			file:  referenceImageFile{FileID: "file-one", MIMEType: "image/png", FileName: "portrait.png"},
			field: "download_url",
		},
		{
			name:  "missing file ID",
			file:  referenceImageFile{DownloadURL: "https://files.example/private?signed=do-not-print", MIMEType: "image/png", FileName: "portrait.png"},
			field: "file_id",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			downloader := &fakeReferenceDownloader{data: map[string][]byte{}}
			_, err := resolveHostedReferences(context.Background(), nil, "", nil, []referenceImageFile{tt.file}, downloader)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), "attachment 1") || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error does not safely identify attachment and field: %v", err)
			}
			if (tt.file.DownloadURL != "" && strings.Contains(err.Error(), tt.file.DownloadURL)) || strings.Contains(err.Error(), "do-not-print") {
				t.Fatalf("error leaks signed URL: %v", err)
			}
			if len(downloader.calls) != 0 {
				t.Fatalf("invalid attachment caused downloads: %#v", downloader.calls)
			}
		})
	}

	t.Run("download error does not expose signed URL", func(t *testing.T) {
		const signedURL = "https://files.example/private?signed=do-not-print"
		downloader := &fakeReferenceDownloader{data: map[string][]byte{}}
		_, err := resolveHostedReferences(context.Background(), nil, "", nil, []referenceImageFile{{
			DownloadURL: signedURL,
			FileID:      "file-private",
			MIMEType:    "image/png",
			FileName:    "private.png",
		}}, downloader)
		if err == nil {
			t.Fatal("expected download error")
		}
		if !strings.Contains(err.Error(), "attachment 1") {
			t.Fatalf("error does not safely identify attachment: %v", err)
		}
		if strings.Contains(err.Error(), signedURL) || strings.Contains(err.Error(), "do-not-print") {
			t.Fatalf("error leaks signed URL: %v", err)
		}
	})
}

func TestResolveHostedReferenceErrorsHideInputs(t *testing.T) {
	for _, tt := range []struct {
		name   string
		ref    string
		marker string
	}{
		{
			name:   "data URL",
			ref:    "data:image/png;base64,LEAKED_IMAGE_BYTES_123",
			marker: "LEAKED_IMAGE_BYTES",
		},
		{
			name:   "bearer token",
			ref:    "Bearer LEAKED_BEARER_TOKEN_123",
			marker: "LEAKED_BEARER_TOKEN",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveHostedReferences(context.Background(), &assets.Store{}, "user-1", []string{tt.ref}, nil, nil)
			if err == nil {
				t.Fatal("expected rejected reference error")
			}
			if strings.Contains(err.Error(), tt.ref) || strings.Contains(err.Error(), tt.marker) {
				t.Fatalf("error leaks rejected reference input: %v", err)
			}
		})
	}
}

func TestResolveHostedMalformedReferenceDoesNotLeakToErrorOrLog(t *testing.T) {
	const (
		ref    = "ref_LEAKED_REFERENCE_SECRET_123"
		marker = "LEAKED_REFERENCE_SECRET"
	)
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	_, err := resolveHostedReferences(context.Background(), &assets.Store{}, "user-1", []string{ref}, nil, nil)
	if err == nil {
		t.Fatal("expected malformed reference error")
	}
	if strings.Contains(err.Error(), ref) || strings.Contains(err.Error(), marker) {
		t.Fatalf("error leaks malformed reference input: %v", err)
	}
	if strings.Contains(logs.String(), ref) || strings.Contains(logs.String(), marker) {
		t.Fatalf("log leaks malformed reference input: %s", logs.String())
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
