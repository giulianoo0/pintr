// Package mcpserver builds the MCP server and its mode-specific tools. The
// handlers differ by mode: stdio works on the single local account; the hosted
// server on the authenticated user's accounts (handlers.go).
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
	"github.com/giulianoo0/pintr/internal/runway"
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
	// videoTimeout bounds one generate_video call. Runway's Explore-mode queue
	// can outlast it; the tool then returns a task_id instead of an error so a
	// follow-up call can resume the same generation.
	videoTimeout                 = 10 * time.Minute
	hostedMaxReferenceImages     = 8
	hostedMaxReferenceImageBytes = 10 << 20
	hostedMaxReferenceTotalBytes = 40 << 20
)

// generateImageArgs is the MCP tool input. There is deliberately no model
// field (fixed server-side) and no output path (the client never chooses
// where the server writes) — delivery is decided by the server per mode. The
// reference_images description is mode-specific and set in generateImageTool;
// the tag below is only a fallback.
type referenceImageFile struct {
	DownloadURL string `json:"download_url"`
	FileID      string `json:"file_id"`
	MIMEType    string `json:"mime_type,omitempty"`
	FileName    string `json:"file_name,omitempty"`
}

type generateImageArgs struct {
	Prompt              string               `json:"prompt" jsonschema:"the full image prompt to render"`
	ReferenceImages     []string             `json:"reference_images,omitempty" jsonschema:"optional reference images to anchor a character or style"`
	ReferenceImageFiles []referenceImageFile `json:"reference_image_files,omitempty" jsonschema:"ChatGPT-provided attached reference images"`
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

// generateVideoArgs is the generate_video input. The tool is dual-purpose: a
// call with a prompt submits a generation, a call with only task_id resumes
// polling one that outlived an earlier call. Runway's Explore mode queues, and
// a queue can outlast any sane tool timeout, so the alternative would be
// losing finished videos.
type generateVideoArgs struct {
	Prompt              string               `json:"prompt,omitempty" jsonschema:"the full video prompt; reference images are addressed as @Image1, @Image2, … in prompt text"`
	ReferenceImages     []string             `json:"reference_images,omitempty" jsonschema:"optional reference images as ref_ upload handles"`
	ReferenceImageFiles []referenceImageFile `json:"reference_image_files,omitempty" jsonschema:"ChatGPT-provided attached reference images"`
	FirstFrameImage     string               `json:"first_frame_image,omitempty" jsonschema:"ref_ handle for the image the video should START on"`
	EndFrameImage       string               `json:"end_frame_image,omitempty" jsonschema:"ref_ handle for the image the video should END on; needs first_frame_image too"`
	Model               string               `json:"model,omitempty" jsonschema:"video model to use; defaults to seedance_2"`
	DurationSeconds     int                  `json:"duration_seconds,omitempty" jsonschema:"clip length in seconds (1-12); defaults to 5"`
	AspectRatio         string               `json:"aspect_ratio,omitempty" jsonschema:"defaults to 16:9"`
	Resolution          string               `json:"resolution,omitempty" jsonschema:"defaults to 720p"`
	Audio               *bool                `json:"audio,omitempty" jsonschema:"generate a soundtrack on models that support it; defaults to true"`
	TaskID              string               `json:"task_id,omitempty" jsonschema:"resume a generation started by an earlier call; pass this alone, with no prompt"`
}

type generateVideoResult struct {
	Status            string `json:"status"` // queued, running, succeeded, failed
	TaskID            string `json:"task_id"`
	ProgressPercent   int    `json:"progress_percent"`
	Message           string `json:"message"`
	AssetURL          string `json:"asset_url,omitempty"`
	DecryptedAssetURL string `json:"decrypted_asset_url,omitempty"`
	DecryptionKey     string `json:"decryption_key,omitempty"`
	MimeType          string `json:"mime_type,omitempty"`
	Model             string `json:"model"`
	DurationMs        int64  `json:"duration_ms"`
	SizeBytes         int    `json:"size_bytes,omitempty"`
}

// getUsageArgs is the (empty) input to the get_usage tool.
type getUsageArgs struct{}

type usageResult struct {
	Accounts []codex.AccountUsage `json:"accounts"`
}

type referenceUploadArgs struct {
	Filename  string `json:"filename"`
	MIMEType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
}

type referenceUploadResult struct {
	UploadURL    string `json:"upload_url"`
	UploadID     string `json:"upload_id"`
	ExpiresIn    int64  `json:"expires_in"`
	MaxSizeBytes int64  `json:"max_size_bytes"`
	Instructions string `json:"instructions"`
}

type GenerateFunc func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error)
type GenerateVideoFunc func(context.Context, generateVideoArgs) (*mcp.CallToolResult, generateVideoResult, error)
type UsageFunc func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error)
type ReferenceUploadFunc func(context.Context, referenceUploadArgs) (*mcp.CallToolResult, referenceUploadResult, error)

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
	"Hosted calls accept at most 8 total reference images across reference_images and reference_image_files, " +
	"with 40 MiB total decoded bytes and 10 MiB per image. " +
	"In ChatGPT, attach images to the conversation; the host supplies them through reference_image_files. Do not manually construct " +
	"file descriptors. In Claude, call " +
	"request_reference_upload and pass the returned ref_ handle through reference_images. This server is " +
	"remote and cannot read files off your machine."

const refsDescriptionStdio = "optional reference images to anchor a character or style. Pass LOCAL FILE " +
	"PATHS (png/jpeg/webp/gif) — this server runs alongside you and reads them directly off disk. " +
	"Do NOT base64-encode, inline, or pass data: URLs (they are rejected), and do not upload anything."

const refsDescriptionHosted = "optional reference images to anchor a character or style, passed as ref_ " +
	"upload handles. This server is remote: it cannot read files off your machine, so local paths do not " +
	"work here. Do NOT base64-encode, inline, or pass data: URLs — that bloats context and is rejected. " +
	"Hosted calls accept at most 8 total reference images across reference_images and reference_image_files, " +
	"with 40 MiB total decoded bytes and 10 MiB per image. " +
	"In Claude, call request_reference_upload and pass its ref_ handle here. Uploads auto-delete after 1 " +
	"hour, so the same handle can be reused across multiple generate_image calls within that window. In " +
	"ChatGPT, pass attachments directly through reference_image_files instead."

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
		schema.Properties["reference_images"].MaxItems = jsonschema.Ptr(hostedMaxReferenceImages)
		schema.Properties["reference_image_files"].MaxItems = jsonschema.Ptr(hostedMaxReferenceImages)
		schema.Properties["reference_image_files"].Description = "ChatGPT-provided attached reference images. " +
			"Hosted calls accept at most 8 total images across reference_images and reference_image_files, " +
			"with 40 MiB total decoded bytes and 10 MiB per image."
	} else {
		delete(schema.Properties, "reference_image_files")
	}
	schema.Properties["reference_images"].Description = refsDescription
	tool := &mcp.Tool{Name: "generate_image", Description: description, InputSchema: schema}
	if hosted {
		tool.Meta = mcp.Meta{"openai/fileParams": []string{"reference_image_files"}}
	}
	return tool
}

func referenceUploadTool() *mcp.Tool {
	schema, err := jsonschema.For[referenceUploadArgs](nil)
	if err != nil {
		panic(fmt.Sprintf("request_reference_upload schema: %v", err))
	}
	return &mcp.Tool{
		Name: "request_reference_upload",
		Description: "Prepare a reference-image upload from Claude's code-execution sandbox using metadata only. " +
			"If the sandbox blocks the PUT, add the upload_url origin (pintr.giuli.dev on the default hosted service) " +
			"under Settings → Capabilities → Code execution and file creation → Additional allowed domains. The " +
			"signed upload URL expires in five minutes. PUT the sandbox file's raw bytes there, then pass the returned " +
			"ref to generate_image.reference_images.",
		InputSchema: schema,
	}
}

// generateVideoTool builds the hosted-only generate_video tool. Runway is
// reached with the user's own pasted browser token, so there is nothing to
// offer in stdio mode, where pintr has no per-user credential store.
func generateVideoTool() *mcp.Tool {
	schema, err := jsonschema.For[generateVideoArgs](nil)
	if err != nil {
		panic(fmt.Sprintf("generate_video schema: %v", err))
	}
	schema.Properties["reference_images"].MaxItems = jsonschema.Ptr(hostedMaxReferenceImages)
	schema.Properties["reference_image_files"].MaxItems = jsonschema.Ptr(hostedMaxReferenceImages)
	schema.Properties["model"].Enum = toAnySlice(runway.ModelNames())
	schema.Properties["aspect_ratio"].Enum = toAnySlice(runway.AspectRatios())
	schema.Properties["resolution"].Enum = toAnySlice(runway.Resolutions())
	schema.Properties["reference_images"].Description = "optional reference images, passed as ref_ upload handles. " +
		"Call request_reference_upload first and pass the handle it returns. This server is remote: local file " +
		"paths and inline base64/data: URLs do not work and are rejected. Address each one from the prompt as " +
		"@Image1, @Image2, … in the order you list them here. Only the seedance_2 family accepts these; other " +
		"models take first_frame_image / end_frame_image instead."
	return &mcp.Tool{
		Name:        "generate_video",
		Description: generateVideoDescription,
		InputSchema: schema,
		Meta:        mcp.Meta{"openai/fileParams": []string{"reference_image_files"}},
	}
}

const generateVideoDescription = "Generate a video with Runway (default model Seedance 2.0) using the Runway " +
	"account connected in the pintr dashboard. Generations always run in Runway's Explore mode: they cost no " +
	"credits but they QUEUE, often for several minutes. " +
	"This call polls for up to 10 minutes. If the video is not ready by then it returns status \"queued\" or " +
	"\"running\" with a task_id — that is NOT a failure and NOT a reason to start another generation. Call " +
	"generate_video again with ONLY that task_id (no prompt) to keep waiting; repeat until status is " +
	"\"succeeded\" or \"failed\". " +
	"Explore mode runs ONE generation at a time per Runway account: submitting a second while one is pending " +
	"fails, so always resume with task_id instead. " +
	"When it succeeds, ALWAYS look at the video: open decrypted_asset_url, which returns the decrypted MP4 " +
	"(video/mp4) directly, no decryption needed on your side. (asset_url is the raw encrypted ciphertext and " +
	"decryption_key is its key, if you would rather fetch and decrypt it yourself.) Stored videos auto-delete " +
	"24 hours after generation — download the MP4 if you need it longer. " +
	"There are two different ways to give it images, and models differ in which they accept. " +
	"(1) REFERENCES — to anchor characters, places or style: call request_reference_upload for each image, pass " +
	"the ref_ handles in reference_images, and refer to them from the prompt as @Image1, @Image2, … matching that " +
	"order. Only the seedance_2 family accepts references. " +
	"(2) KEYFRAMES — to pin the exact opening and closing image: pass first_frame_image (and optionally " +
	"end_frame_image, which requires first_frame_image) as ref_ handles. Most other models accept keyframes " +
	"instead of references; some take a first frame only. seedance_2 accepts both at once. " +
	"The tool reports which is supported if you pick a model that does not take what you passed. " +
	"In ChatGPT, attached images arrive through reference_image_files instead; do not construct file descriptors " +
	"by hand."

func toAnySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

// New builds the MCP server with the tools available in the selected mode.
func New(hosted bool, generate GenerateFunc, usage UsageFunc, referenceUpload ReferenceUploadFunc, generateVideo GenerateVideoFunc) *mcp.Server {
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
	if hosted && referenceUpload != nil {
		mcp.AddTool(server, referenceUploadTool(), func(ctx context.Context, req *mcp.CallToolRequest, args referenceUploadArgs) (*mcp.CallToolResult, referenceUploadResult, error) {
			return referenceUpload(ctx, args)
		})
	}
	if hosted && generateVideo != nil {
		mcp.AddTool(server, generateVideoTool(), func(ctx context.Context, req *mcp.CallToolRequest, args generateVideoArgs) (*mcp.CallToolResult, generateVideoResult, error) {
			ctx, cancel := context.WithTimeout(ctx, videoTimeout)
			defer cancel()
			stopProgress := startVideoProgress(ctx, req)
			res, out, err := generateVideo(ctx, args)
			stopProgress()
			return res, out, err
		})
	}
	return server
}

// startProgress emits MCP progress notifications every progressInterval until
// the returned stop function is called (or ctx ends). Without them, clients
// abort a tool call that stays silent for the length of a generation. Only
// possible when the client sent a progress token; otherwise it's a no-op.
func startProgress(ctx context.Context, req *mcp.CallToolRequest) func() {
	return startProgressWith(ctx, req, func(elapsed int) string {
		return fmt.Sprintf("generating… %ds elapsed (can take up to 420s)", elapsed)
	})
}

// startVideoProgress is the same ticker for generate_video, whose wait is
// dominated by Runway's Explore-mode queue rather than by rendering.
func startVideoProgress(ctx context.Context, req *mcp.CallToolRequest) func() {
	return startProgressWith(ctx, req, func(elapsed int) string {
		return fmt.Sprintf("waiting on runway… %ds elapsed (explore mode queues; this call polls for up to %s)",
			elapsed, videoTimeout)
	})
}

func startProgressWith(ctx context.Context, req *mcp.CallToolRequest, message func(elapsed int) string) func() {
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
					Message:       message(elapsed),
				})
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
