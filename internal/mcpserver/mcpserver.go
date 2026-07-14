// Package mcpserver builds the MCP server and its two tools. The tool
// handlers differ by mode: stdio works on the single local account; the
// hosted server on the authenticated user's accounts (handlers.go).
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/codex"
)

// Version is the MCP implementation version pintr reports to clients.
const Version = "0.2.0"

// Generation can take up to 420s; give it 10 minutes before reporting an
// error. Progress notifications every few seconds keep MCP clients (whose
// default tool timeouts are shorter than a generation) from giving up, and
// keep bytes flowing so Cloudflare/nginx don't idle the connection out.
const (
	generationTimeout = 10 * time.Minute
	progressInterval  = 10 * time.Second
)

// generateImageArgs is the MCP tool input. There is deliberately no model
// field (fixed server-side) and no output path (the client never chooses
// where the server writes) — delivery is decided by the server per mode. The
// reference_images description is mode-specific and set in generateImageTool;
// the tag below is only a fallback.
type generateImageArgs struct {
	Prompt          string   `json:"prompt" jsonschema:"the full image prompt to render"`
	ReferenceImages []string `json:"reference_images,omitempty" jsonschema:"optional reference images to anchor a character or style"`
}

type generateImageResult struct {
	AssetURL          string              `json:"asset_url,omitempty"`
	DecryptedAssetURL string              `json:"decrypted_asset_url,omitempty"`
	DecryptionKey     string              `json:"decryption_key,omitempty"`
	MimeType          string              `json:"mime_type,omitempty"`
	SavedPath         string              `json:"saved_path,omitempty"`
	Model             string              `json:"model"`
	Account           string              `json:"account"`
	DurationMs        int64               `json:"duration_ms"`
	SizeBytes         int                 `json:"size_bytes,omitempty"`
	Usage             *codex.AccountUsage `json:"usage,omitempty"`
}

// getUsageArgs is the (empty) input to the get_usage tool.
type getUsageArgs struct{}

type usageResult struct {
	Accounts []codex.AccountUsage `json:"accounts"`
}

type GenerateFunc func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error)
type UsageFunc func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error)

// The tool description and the reference_images schema are mode-specific on
// purpose: when both modes shared one description that documented /upload,
// agents on the LOCAL server kept uploading instead of passing file paths.
// Each mode only advertises the one reference mechanism that works there.

const generateDescriptionCommon = "Generate an image with the Codex image model (GPT Image, gpt-5.6-terra). " +
	"Generation can take up to 420 seconds — do NOT treat a long-running call as stuck; the server " +
	"streams progress notifications and only errors out after 10 minutes. " +
	"The result also includes the account's remaining rate limits under usage. "

const generateDescriptionStdio = generateDescriptionCommon +
	"ALWAYS look at the image after generating: read saved_path and view it, so you can confirm it matches " +
	"the request before continuing. " +
	"For reference_images, pass LOCAL FILE PATHS — this server runs on your machine and reads them straight " +
	"off disk. Never base64-encode, inline, or upload reference images; a plain path is all it takes."

const generateDescriptionHosted = generateDescriptionCommon +
	"ALWAYS look at the image after generating: open decrypted_asset_url from the result and view it, so you " +
	"can confirm it matches the request before continuing. decrypted_asset_url returns the decrypted PNG " +
	"(image/png) directly, no decryption needed on your side. (asset_url is the raw encrypted ciphertext and " +
	"decryption_key is its key, if you'd rather fetch and decrypt it yourself.) " +
	"Stored images auto-delete 24 hours after generation — download the PNG if you need it longer. " +
	"For reference_images, upload the raw bytes to /upload first and pass the returned ref_ handle " +
	"(see the reference_images field); this server is remote and cannot read files off your machine."

const refsDescriptionStdio = "optional reference images to anchor a character or style. Pass LOCAL FILE " +
	"PATHS (png/jpeg/webp/gif) — this server runs alongside you and reads them directly off disk. " +
	"Do NOT base64-encode, inline, or pass data: URLs (they are rejected), and do not upload anything."

const refsDescriptionHosted = "optional reference images to anchor a character or style, passed as ref_ " +
	"upload handles. This server is remote: it cannot read files off your machine, so local paths do not " +
	"work here. Do NOT base64-encode, inline, or pass data: URLs — that bloats context and is rejected. " +
	"Instead POST the RAW image bytes to the /upload endpoint (e.g. https://pintr.giuli.dev/upload) with " +
	"your bearer token, e.g.: curl -s -X POST https://pintr.giuli.dev/upload -H \"Authorization: Bearer " +
	"<token-or-pintr_key>\" --data-binary @image.png ; it returns {\"ref\":\"ref_...\"}. Pass those ref_... " +
	"handles here. Keep each upload under ~10 MB (Cloudflare caps request bodies) — downscale large " +
	"references; there is no chunked upload. Uploads are stored encrypted and auto-delete after 1 hour, so " +
	"the same ref_ handle can be reused across multiple generate_image calls within that window — upload " +
	"once per reference, reuse the handle."

// generateImageTool builds the generate_image tool definition for one mode,
// overriding the reference_images schema description with the mode's text.
func generateImageTool(hosted bool) *mcp.Tool {
	schema, err := jsonschema.For[generateImageArgs](nil)
	if err != nil {
		panic(fmt.Sprintf("generate_image schema: %v", err))
	}
	description, refsDescription := generateDescriptionStdio, refsDescriptionStdio
	if hosted {
		description, refsDescription = generateDescriptionHosted, refsDescriptionHosted
	}
	schema.Properties["reference_images"].Description = refsDescription
	return &mcp.Tool{Name: "generate_image", Description: description, InputSchema: schema}
}

// New builds the MCP server with the two tools bound to the given handlers.
func New(hosted bool, generate GenerateFunc, usage UsageFunc) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: Version}, nil)
	mcp.AddTool(server, generateImageTool(hosted), func(ctx context.Context, req *mcp.CallToolRequest, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		ctx, cancel := context.WithTimeout(ctx, generationTimeout)
		defer cancel()
		stopProgress := startProgress(ctx, req)
		res, out, err := generate(ctx, args)
		stopProgress()
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("image generation timed out after %s (it can take up to 420s) — try again", generationTimeout)
		}
		return res, out, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name: "get_usage",
		Description: "Return the remaining Codex rate limits for your linked account(s): the 5h, weekly and " +
			"monthly windows (only the ones OpenAI currently exposes), each with used and remaining percent.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		return usage(ctx, args)
	})
	return server
}

// startProgress emits MCP progress notifications every progressInterval until
// the returned stop function is called (or ctx ends). Without them, clients
// abort a tool call that stays silent for the length of a generation. Only
// possible when the client sent a progress token; otherwise it's a no-op.
func startProgress(ctx context.Context, req *mcp.CallToolRequest) func() {
	token := req.Params.GetProgressToken()
	if token == nil || req.Session == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		startedAt := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := int(time.Since(startedAt).Seconds())
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      float64(elapsed),
					Message:       fmt.Sprintf("generating… %ds elapsed (can take up to 420s)", elapsed),
				})
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
