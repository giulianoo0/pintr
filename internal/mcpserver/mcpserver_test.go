package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/referenceupload"
	"github.com/giulianoo0/pintr/internal/store"
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

type fakeUploadIssuer struct {
	userID string
	req    referenceupload.Request
}

func (f *fakeUploadIssuer) Issue(userID string, req referenceupload.Request) (referenceupload.Ticket, error) {
	f.userID, f.req = userID, req
	return referenceupload.Ticket{
		UploadURL: "https://pintr.example/reference-upload/token",
		UploadID:  "upload-1", ExpiresIn: 300, MaxSizeBytes: referenceupload.MaxBytes,
	}, nil
}

func authenticatedOAuthContext(t *testing.T) (context.Context, string) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "pintr.db"), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user, err := st.CreateUser(context.Background(), "claude@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	key, err := st.CreateAccessKey(context.Background(), user.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	provider := oauth.New("https://pintr.example", st)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	var authenticated context.Context
	provider.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || authenticated == nil {
		t.Fatalf("OAuth authentication status = %d, context set = %t", w.Code, authenticated != nil)
	}
	return authenticated, user.ID
}

func TestReferenceUploadToolDefinition(t *testing.T) {
	tool := referenceUploadTool()
	schema := tool.InputSchema.(*jsonschema.Schema)
	fields := make([]string, 0, len(schema.Properties))
	for field := range schema.Properties {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	if want := []string{"filename", "mime_type", "size_bytes"}; !slices.Equal(fields, want) {
		t.Fatalf("input fields = %#v, want %#v", fields, want)
	}
	required := append([]string(nil), schema.Required...)
	slices.Sort(required)
	if want := []string{"filename", "mime_type", "size_bytes"}; !slices.Equal(required, want) {
		t.Fatalf("required fields = %#v, want %#v", required, want)
	}
	for _, phrase := range []string{
		"sandbox", "Additional allowed domains", "upload_url origin", "pintr.giuli.dev", "five minutes",
		"returned ref", "generate_image.reference_images",
	} {
		if !strings.Contains(tool.Description, phrase) {
			t.Errorf("description must contain %q, got: %s", phrase, tool.Description)
		}
	}
}

func TestReferenceUploadHostedHandler(t *testing.T) {
	ctx, userID := authenticatedOAuthContext(t)
	issuer := &fakeUploadIssuer{}
	handler := HostedReferenceUpload(issuer)
	args := referenceUploadArgs{Filename: "portrait.png", MIMEType: "image/png", SizeBytes: 1234}

	callResult, got, err := handler(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if callResult != nil {
		t.Fatalf("call result = %#v, want nil", callResult)
	}
	if issuer.userID != userID {
		t.Fatalf("issuer user ID = %q, want %q", issuer.userID, userID)
	}
	if want := (referenceupload.Request{Filename: "portrait.png", MIMEType: "image/png", SizeBytes: 1234}); issuer.req != want {
		t.Fatalf("issuer request = %#v, want %#v", issuer.req, want)
	}
	if got.UploadURL != "https://pintr.example/reference-upload/token" || got.UploadID != "upload-1" ||
		got.ExpiresIn != 300 || got.MaxSizeBytes != 10<<20 {
		t.Fatalf("result does not mirror ticket: %#v", got)
	}
	for _, phrase := range []string{
		"sandbox", "PUT", "Additional allowed domains", "https://pintr.example", "five minutes",
		"returned ref", "generate_image.reference_images",
	} {
		if !strings.Contains(got.Instructions, phrase) {
			t.Errorf("instructions must contain %q, got: %s", phrase, got.Instructions)
		}
	}
}

func TestReferenceUploadHostedHandlerRejectsUnauthenticated(t *testing.T) {
	issuer := &fakeUploadIssuer{}
	_, _, err := HostedReferenceUpload(issuer)(context.Background(), referenceUploadArgs{
		Filename: "portrait.png", MIMEType: "image/png", SizeBytes: 1234,
	})
	if err == nil || err.Error() != "unauthenticated" {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
	if issuer.userID != "" {
		t.Fatalf("unauthenticated call reached issuer with user %q", issuer.userID)
	}
}

func TestReferenceUploadRegistrationIsHostedOnly(t *testing.T) {
	generate := func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		return nil, generateImageResult{}, nil
	}
	usage := func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		return nil, usageResult{}, nil
	}
	upload := HostedReferenceUpload(&fakeUploadIssuer{})

	for _, tt := range []struct {
		name   string
		server *mcp.Server
		want   bool
	}{
		{name: "hosted", server: New(true, generate, usage, upload), want: true},
		{name: "stdio", server: New(false, generate, usage, upload), want: false},
		{name: "hosted without storage", server: New(true, generate, usage, nil), want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := tt.server.Connect(context.Background(), serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = serverSession.Close() })
			client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
			clientSession, err := client.Connect(context.Background(), clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = clientSession.Close() })
			listed, err := clientSession.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, tool := range listed.Tools {
				if tool.Name == "request_reference_upload" {
					found = true
				}
			}
			if found != tt.want {
				t.Fatalf("request_reference_upload registered = %t, want %t", found, tt.want)
			}
		})
	}
}

func TestReferenceUploadRegisteredToolCallsHostedHandler(t *testing.T) {
	ctx, userID := authenticatedOAuthContext(t)
	issuer := &fakeUploadIssuer{}
	generate := func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		return nil, generateImageResult{}, nil
	}
	usage := func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		return nil, usageResult{}, nil
	}
	server := New(true, generate, usage, HostedReferenceUpload(issuer))
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	result, err := clientSession.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "request_reference_upload",
		Arguments: map[string]any{
			"filename": "portrait.png", "mime_type": "image/png", "size_bytes": float64(1234),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("registered tool returned error: %#v", result.Content)
	}
	if issuer.userID != userID {
		t.Fatalf("issuer user ID = %q, want %q", issuer.userID, userID)
	}
	if want := (referenceupload.Request{Filename: "portrait.png", MIMEType: "image/png", SizeBytes: 1234}); issuer.req != want {
		t.Fatalf("issuer request = %#v, want %#v", issuer.req, want)
	}
	structured, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type = %T, want map[string]any", result.StructuredContent)
	}
	if structured["upload_url"] != "https://pintr.example/reference-upload/token" ||
		structured["upload_id"] != "upload-1" || structured["expires_in"] != float64(300) ||
		structured["max_size_bytes"] != float64(10<<20) {
		t.Fatalf("wire result does not mirror ticket: %#v", structured)
	}
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
	if !strings.Contains(hosted.Description, "Do not manually construct") {
		t.Errorf("hosted description must tell ChatGPT not to construct file descriptors, got: %s", hosted.Description)
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
		if !strings.Contains(err.Error(), "retry with the attachment") {
			t.Fatalf("error does not tell ChatGPT how to recover: %v", err)
		}
		for _, secret := range []string{signedURL, "do-not-print", "file-private", "private.png", "missing test image"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks attachment input %q: %v", secret, err)
			}
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
			if strings.Contains(err.Error(), "/upload") || !strings.Contains(err.Error(), "request_reference_upload") {
				t.Fatalf("error gives obsolete hosted upload guidance: %v", err)
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
	if strings.Contains(err.Error(), "/upload") || !strings.Contains(err.Error(), "request_reference_upload") {
		t.Fatalf("error gives obsolete hosted upload guidance: %v", err)
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
