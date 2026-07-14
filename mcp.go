package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP server and its two tools. The tool handlers differ by mode: stdio
// works on the single local account; the hosted server on the authenticated
// user's accounts.

// Generation can take up to 420s; give it 10 minutes before reporting an
// error. Progress notifications every few seconds keep MCP clients (whose
// default tool timeouts are shorter than a generation) from giving up, and
// keep bytes flowing so Cloudflare/nginx don't idle the connection out.
const (
	generationTimeout = 10 * time.Minute
	progressInterval  = 10 * time.Second
)

type generateHandler func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error)
type usageHandler func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error)

// The tool description and the reference_images schema are mode-specific on
// purpose: when both modes shared one description that documented /upload,
// agents on the LOCAL server kept uploading instead of passing file paths.
// Each mode now only advertises the one reference mechanism that works there.

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

func newMCPServer(hosted bool, generate generateHandler, usage usageHandler) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: serverVersion}, nil)
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

// --- stdio mode handlers (single local account) ---

// writeLocalPNG saves the image to a pintr-managed cache dir (a path pintr
// chooses, never one the caller supplies) and returns it.
func writeLocalPNG(png []byte) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "pintr", "images")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	id, err := randomToken(12)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".png")
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// stdioGenerate resolves the single local account, generates, and saves the PNG
// to a pintr-managed path (returned as saved_path).
func stdioGenerate(fileStore *authStore) generateHandler {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		refs, err := resolveReferences(args.ReferenceImages)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := generateImage(ctx, []codexAccount{fileAccount{store: fileStore}}, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		path, err := writeLocalPNG(img.PNG)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return nil, generateImageResult{
			SavedPath: path, MimeType: "image/png", Model: img.Model, Account: img.Account,
			DurationMs: img.DurationMs, SizeBytes: len(img.PNG), Usage: img.Usage,
		}, nil
	}
}

func stdioUsage(fileStore *authStore) usageHandler {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		// get_usage is an explicit check → fetch fresh and reset the cache timer.
		usage, _, err := accountUsage30m(ctx, fileAccount{store: fileStore}, true)
		if err != nil {
			return nil, usageResult{}, err
		}
		return nil, usageResult{Accounts: []accountUsage{usage}}, nil
	}
}

// --- hosted mode handlers (the authenticated user's linked accounts) ---

// resolveHostedReferences turns each reference into a data: URL. On the hosted
// server the only accepted reference is a "ref_" upload handle: it's fetched and
// decrypted (it stays reusable until it expires, one hour after upload). Inline
// base64 / data: URLs and file paths are rejected — a remote server can't read
// the caller's filesystem, and inlining bloats context; the caller must upload
// the bytes to /upload first.
func resolveHostedReferences(ctx context.Context, assets *assetStore, userID string, refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, "ref_") {
			return nil, fmt.Errorf("reference image %q is not an uploaded handle — the hosted server can't read local files or accept inline base64/data: URLs; upload the raw bytes to /upload and pass the returned ref_ handle", truncate(ref, 48))
		}
		img, err := assets.fetchUpload(ctx, userID, ref)
		if err != nil {
			// Log the id only — the part after the dot is the decryption key.
			logImage("reference %s failed: %v", refID(ref), err)
			return nil, fmt.Errorf("reference %s: %w (uploads expire 1 hour after upload — re-upload to /upload and retry with the new handle)", refID(ref), err)
		}
		out = append(out, bytesToDataURL(img))
	}
	return out, nil
}

// refID returns the public id part of a ref_ handle, safe for logs and error
// messages (the segment after the dot is the decryption key).
func refID(handle string) string {
	if id, _, ok := strings.Cut(handle, "."); ok {
		return id
	}
	return handle
}

func hostedUsage(st *store) usageHandler {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		u, ok := userFromContext(ctx)
		if !ok {
			return nil, usageResult{}, errors.New("unauthenticated")
		}
		accounts, err := userCodexAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, usageResult{}, err
		}
		out := make([]accountUsage, 0, len(accounts))
		for _, account := range accounts {
			// get_usage is an explicit check → fetch fresh and reset the timer.
			usage, _, err := accountUsage30m(ctx, account, true)
			if err != nil {
				logImage("usage fetch failed for %s: %v", account.label(), err)
				continue
			}
			out = append(out, usage)
		}
		return nil, usageResult{Accounts: out}, nil
	}
}

// hostedGenerate resolves the authenticated user's accounts, generates, encrypts
// the PNG under a one-time key, uploads the ciphertext, and returns a presigned
// download URL plus the key. It never touches the local filesystem or a
// caller-chosen path.
func hostedGenerate(st *store, assets *assetStore, publicURL string) generateHandler {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		u, ok := userFromContext(ctx)
		if !ok {
			return nil, generateImageResult{}, errors.New("unauthenticated")
		}
		if assets == nil {
			return nil, generateImageResult{}, errors.New("image storage is not configured on this server (set PINTR_S3_*)")
		}
		refs, err := resolveHostedReferences(ctx, assets, u.ID, args.ReferenceImages)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		accounts, err := userCodexAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := generateImage(ctx, accounts, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		stored, err := assets.putEncrypted(ctx, u.ID, img.PNG)
		if err != nil {
			return nil, generateImageResult{}, fmt.Errorf("storing image: %w", err)
		}

		result := generateImageResult{
			AssetURL:          stored.URL,
			DecryptedAssetURL: decryptedAssetURL(publicURL, stored.ObjectKey, stored.KeyB64),
			DecryptionKey:     stored.KeyB64,
			MimeType:          "image/png",
			Model:             img.Model,
			Account:           img.Account,
			DurationMs:        img.DurationMs,
			SizeBytes:         len(img.PNG),
			Usage:             img.Usage,
		}
		note := fmt.Sprintf(
			"Image generated (%d bytes). To view it, open decrypted_asset_url — it returns the decrypted "+
				"PNG directly (image/png), decrypted server-side. asset_url is the raw encrypted ciphertext; "+
				"decryption_key is the AES-256-GCM key, returned only here and never stored. The stored image "+
				"auto-deletes in 24 hours — download the PNG now if you need it longer.", len(img.PNG))
		callResult := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: note}}}
		return callResult, result, nil
	}
}
