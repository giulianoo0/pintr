package mcpserver

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/runway"
)

func noopGenerate(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
	return nil, generateImageResult{}, nil
}

func noopUsage(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
	return nil, usageResult{}, nil
}

func noopVideo(context.Context, generateVideoArgs) (*mcp.CallToolResult, generateVideoResult, error) {
	return nil, generateVideoResult{}, nil
}

func listToolNames(t *testing.T, server *mcp.Server) []string {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
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
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// generate_video depends on the per-user Runway token the hosted dashboard
// stores, so stdio must never advertise it.
func TestGenerateVideoRegistrationIsHostedOnly(t *testing.T) {
	for _, tt := range []struct {
		name   string
		server *mcp.Server
		want   bool
	}{
		{name: "hosted", server: New(true, noopGenerate, noopUsage, nil, noopVideo), want: true},
		{name: "stdio", server: New(false, noopGenerate, noopUsage, nil, noopVideo), want: false},
		{name: "hosted without runway", server: New(true, noopGenerate, noopUsage, nil, nil), want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Contains(listToolNames(t, tt.server), "generate_video")
			if got != tt.want {
				t.Fatalf("generate_video registered = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestGenerateVideoSchema(t *testing.T) {
	tool := generateVideoTool()
	schema, ok := tool.InputSchema.(*jsonschema.Schema)
	if !ok {
		t.Fatalf("InputSchema is %T, want *jsonschema.Schema", tool.InputSchema)
	}

	// prompt must stay optional: resuming a queued generation passes only
	// task_id, and a required prompt would make that call invalid.
	if slices.Contains(schema.Required, "prompt") {
		t.Error("prompt must be optional so task_id can resume a generation alone")
	}
	for _, field := range []string{"prompt", "task_id", "model", "duration_seconds", "aspect_ratio", "resolution", "audio", "reference_images"} {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("schema is missing %q", field)
		}
	}

	// The model enum is an allowlist: it must not leak non-video task types
	// like workflow execution or image generation.
	modelEnum := schema.Properties["model"].Enum
	if len(modelEnum) != len(runway.ModelNames()) {
		t.Errorf("model enum has %d entries, want %d", len(modelEnum), len(runway.ModelNames()))
	}
	for _, value := range modelEnum {
		name, _ := value.(string)
		if _, err := runway.LookupModel(name); err != nil {
			t.Errorf("model enum offers %q, which the client rejects: %v", name, err)
		}
	}
	if !slices.Contains(modelEnum, any(runway.DefaultModel)) {
		t.Errorf("model enum must include the default %q", runway.DefaultModel)
	}

	if limit := schema.Properties["reference_images"].MaxItems; limit == nil || *limit != hostedMaxReferenceImages {
		t.Errorf("reference_images MaxItems = %v, want %d", limit, hostedMaxReferenceImages)
	}
	if params, ok := tool.Meta["openai/fileParams"]; !ok {
		t.Error("attachments need openai/fileParams so ChatGPT fills reference_image_files")
	} else if names, _ := params.([]string); !slices.Contains(names, "reference_image_files") {
		t.Errorf("openai/fileParams = %v", params)
	}
}

// The description is the only thing steering an agent through a queue that can
// outlast the call, so the instructions that prevent duplicate generations have
// to actually be in it.
func TestGenerateVideoDescriptionExplainsResuming(t *testing.T) {
	description := generateVideoTool().Description
	for _, phrase := range []string{
		"Explore mode", "task_id", "queued", "ONE generation at a time",
		"decrypted_asset_url", "@Image1", "request_reference_upload", "24 hours",
	} {
		if !strings.Contains(description, phrase) {
			t.Errorf("description must mention %q", phrase)
		}
	}
}

func TestGenerateVideoRejectsUnauthenticated(t *testing.T) {
	_, _, err := HostedGenerateVideo(nil, nil, nil, "https://pintr.example", nil)(
		context.Background(), generateVideoArgs{Prompt: "a cat"})
	if err == nil || err.Error() != "unauthenticated" {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
}
