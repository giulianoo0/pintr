package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/analytics"
	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/random"
	"github.com/giulianoo0/pintr/internal/store"
)

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
	id, err := random.Token(12)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".png")
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// StdioGenerate resolves the single local account, generates, and saves the
// PNG to a pintr-managed path (returned as saved_path).
func StdioGenerate(authStore *codex.AuthStore) GenerateFunc {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		refs, err := codex.ResolveFileReferences(args.ReferenceImages)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := codex.GenerateImage(ctx, []codex.Account{codex.NewFileAccount(authStore)}, args.Prompt, refs)
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

func StdioUsage(authStore *codex.AuthStore) UsageFunc {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		// get_usage is an explicit check → fetch fresh and reset the cache timer.
		usage, _, err := codex.CachedUsage(ctx, codex.NewFileAccount(authStore), true)
		if err != nil {
			return nil, usageResult{}, err
		}
		return nil, usageResult{Accounts: []codex.AccountUsage{usage}}, nil
	}
}

// --- hosted mode handlers (the authenticated user's linked accounts) ---

type referenceDownloader interface {
	Download(context.Context, string) ([]byte, error)
}

// resolveHostedReferences turns hosted references into data: URLs. Existing
// ref_ handles are resolved first and remain reusable until they expire. Any
// ChatGPT-provided attachments are downloaded directly into memory and
// appended in argument order; their bytes are never persisted.
func resolveHostedReferences(ctx context.Context, st *assets.Store, userID string, refs []string, files []referenceImageFile, downloader referenceDownloader) ([]string, error) {
	out := make([]string, 0, len(refs)+len(files))
	for i, ref := range refs {
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, "ref_") {
			return nil, fmt.Errorf("reference image %d is not an uploaded handle — the hosted server can't read local files or accept inline base64/data: URLs; upload the raw bytes to /upload and pass the returned ref_ handle", i+1)
		}
		img, err := st.FetchUpload(ctx, userID, ref)
		if err != nil {
			log.Printf("[generate_image] reference image %d failed", i+1)
			return nil, fmt.Errorf("reference image %d could not be resolved (uploads expire 1 hour after upload — re-upload to /upload and retry with the new handle)", i+1)
		}
		out = append(out, codex.DataURL(img))
	}
	for i, file := range files {
		if strings.TrimSpace(file.DownloadURL) == "" {
			return nil, fmt.Errorf("attachment %d is missing download_url", i+1)
		}
		if strings.TrimSpace(file.FileID) == "" {
			return nil, fmt.Errorf("attachment %d is missing file_id", i+1)
		}
		if downloader == nil {
			return nil, fmt.Errorf("attachment %d cannot be downloaded", i+1)
		}
		img, err := downloader.Download(ctx, file.DownloadURL)
		if err != nil {
			return nil, fmt.Errorf("attachment %d download failed", i+1)
		}
		out = append(out, codex.DataURL(img))
	}
	return out, nil
}

// viewURL builds the decrypted-view link served by web's /view handler: the
// object key and the decryption key travel as query params so an agent that
// can only open a url gets back the raw image.
func viewURL(publicURL, objectKey, keyB64 string) string {
	return publicURL + "/view?o=" + url.QueryEscape(objectKey) + "&k=" + url.QueryEscape(keyB64)
}

func HostedUsage(st *store.Store, tracker *analytics.Tracker) UsageFunc {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, usageResult{}, errors.New("unauthenticated")
		}
		tracker.Event("get_usage")
		accounts, err := codex.UserAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, usageResult{}, err
		}
		out := make([]codex.AccountUsage, 0, len(accounts))
		for _, account := range accounts {
			// get_usage is an explicit check → fetch fresh and reset the timer.
			usage, _, err := codex.CachedUsage(ctx, account, true)
			if err != nil {
				log.Printf("[get_usage] fetch failed for %s: %v", account.Label(), err)
				continue
			}
			out = append(out, usage)
		}
		return nil, usageResult{Accounts: out}, nil
	}
}

// HostedGenerate resolves the authenticated user's accounts, generates,
// encrypts the PNG under a one-time key, uploads the ciphertext, and returns
// a presigned download URL plus the key. It never touches the local
// filesystem or a caller-chosen path.
func HostedGenerate(st *store.Store, assetStore *assets.Store, tracker *analytics.Tracker, publicURL string, downloader referenceDownloader) GenerateFunc {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, generateImageResult{}, errors.New("unauthenticated")
		}
		if assetStore == nil {
			return nil, generateImageResult{}, errors.New("image storage is not configured on this server (set PINTR_S3_*)")
		}
		refs, err := resolveHostedReferences(ctx, assetStore, u.ID, args.ReferenceImages, args.ReferenceImageFiles, downloader)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		accounts, err := codex.UserAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := codex.GenerateImage(ctx, accounts, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		stored, err := assetStore.PutEncrypted(ctx, u.ID, img.PNG)
		if err != nil {
			return nil, generateImageResult{}, fmt.Errorf("storing image: %w", err)
		}
		tracker.Event("generate_image")

		result := generateImageResult{
			AssetURL:          stored.URL,
			DecryptedAssetURL: viewURL(publicURL, stored.ObjectKey, stored.KeyB64),
			DecryptionKey:     stored.KeyB64,
			MimeType:          "image/png",
			Model:             img.Model,
			Account:           img.Account,
			DurationMs:        img.DurationMs,
			SizeBytes:         len(img.PNG),
			Usage:             img.Usage,
		}
		callResult, err := hostedCallResult(result)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return callResult, result, nil
	}
}

// hostedCallResult builds the unstructured content for a hosted generation.
// MCP clients disagree on which channel reaches the model: some forward only
// structuredContent (Claude Code, VS Code, Codex), others read only the
// content blocks (opencode, Grok Build, most adapters). The result must
// therefore appear in BOTH — the SDK fills structuredContent from the typed
// result, and per the spec's backwards-compatibility rule the same serialized
// JSON goes here as its own TextContent block (kept pure JSON, no prose mixed
// in, so content-only clients can parse it). Returning a non-nil result
// suppresses the SDK's own JSON fallback, so it must be included by hand.
func hostedCallResult(result generateImageResult) (*mcp.CallToolResult, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	note := fmt.Sprintf(
		"Image generated (%d bytes). To view it, open decrypted_asset_url — it returns the decrypted "+
			"PNG directly (image/png), decrypted server-side. asset_url is the raw encrypted ciphertext; "+
			"decryption_key is the AES-256-GCM key, returned only here and never stored. The stored image "+
			"auto-deletes in 24 hours — download the PNG now if you need it longer.", result.SizeBytes)
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: note},
		&mcp.TextContent{Text: string(resultJSON)},
	}}, nil
}
