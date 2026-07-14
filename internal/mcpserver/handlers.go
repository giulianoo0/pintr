package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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

// resolveHostedReferences turns each reference into a data: URL. On the
// hosted server the only accepted reference is a "ref_" upload handle: it's
// fetched and decrypted (it stays reusable until it expires, one hour after
// upload). Inline base64 / data: URLs and file paths are rejected — a remote
// server can't read the caller's filesystem, and inlining bloats context; the
// caller must upload the bytes to /upload first.
func resolveHostedReferences(ctx context.Context, st *assets.Store, userID string, refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, "ref_") {
			return nil, fmt.Errorf("reference image %q is not an uploaded handle — the hosted server can't read local files or accept inline base64/data: URLs; upload the raw bytes to /upload and pass the returned ref_ handle", truncate(ref, 48))
		}
		img, err := st.FetchUpload(ctx, userID, ref)
		if err != nil {
			// Log the id only — the part after the dot is the decryption key.
			log.Printf("[generate_image] reference %s failed: %v", refID(ref), err)
			return nil, fmt.Errorf("reference %s: %w (uploads expire 1 hour after upload — re-upload to /upload and retry with the new handle)", refID(ref), err)
		}
		out = append(out, codex.DataURL(img))
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// viewURL builds the decrypted-view link served by web's /view handler: the
// object key and the decryption key travel as query params so an agent that
// can only open a url gets back the raw image.
func viewURL(publicURL, objectKey, keyB64 string) string {
	return publicURL + "/view?o=" + url.QueryEscape(objectKey) + "&k=" + url.QueryEscape(keyB64)
}

func HostedUsage(st *store.Store) UsageFunc {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, usageResult{}, errors.New("unauthenticated")
		}
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
func HostedGenerate(st *store.Store, assetStore *assets.Store, publicURL string) GenerateFunc {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, generateImageResult{}, errors.New("unauthenticated")
		}
		if assetStore == nil {
			return nil, generateImageResult{}, errors.New("image storage is not configured on this server (set PINTR_S3_*)")
		}
		refs, err := resolveHostedReferences(ctx, assetStore, u.ID, args.ReferenceImages)
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
		note := fmt.Sprintf(
			"Image generated (%d bytes). To view it, open decrypted_asset_url — it returns the decrypted "+
				"PNG directly (image/png), decrypted server-side. asset_url is the raw encrypted ciphertext; "+
				"decryption_key is the AES-256-GCM key, returned only here and never stored. The stored image "+
				"auto-deletes in 24 hours — download the PNG now if you need it longer.", len(img.PNG))
		callResult := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: note}}}
		return callResult, result, nil
	}
}
