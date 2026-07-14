// Command pintr is an MCP server that generates images through the Codex
// backend using ChatGPT OAuth logins.
//
// Usage:
//
//	pintr login                    # local browser login only (stdio mode)
//	pintr                          # serve MCP over stdio (logs in first if needed)
//	pintr -http 127.0.0.1:8090     # serve the multi-user HTTP app + MCP
//
// HTTP mode is the hosted, multi-user app: pintr users register, link one or
// more ChatGPT accounts through the dashboard, and MCP clients authenticate via
// the standard MCP OAuth flow (or a personal access key). It requires
// PINTR_SECRET (master secret for signing tokens and encrypting stored
// credentials) and PINTR_DB (SQLite path); PINTR_PUBLIC_URL sets the public
// https base.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverVersion = "0.2.0"

// Generation can take up to 420s; give it 10 minutes before reporting an
// error. Progress notifications every few seconds keep MCP clients (whose
// default tool timeouts are shorter than a generation) from giving up, and
// keep bytes flowing so Cloudflare/nginx don't idle the connection out.
const (
	generationTimeout = 10 * time.Minute
	progressInterval  = 10 * time.Second
)

func main() {
	httpAddr := flag.String("http", "", "serve the HTTP app + MCP on this address instead of stdio")
	authFile := flag.String("auth-file", "", "stdio mode: auth token file (default: ~/.config/pintr/auth.json)")
	flag.Parse()

	ctx := context.Background()

	if *httpAddr != "" {
		serveHTTP(*httpAddr)
		return
	}

	// stdio mode: single local account backed by a file.
	fileStore := newAuthStore(*authFile)
	switch flag.Arg(0) {
	case "login":
		if _, err := runLogin(ctx, fileStore); err != nil {
			log.Fatalf("login failed: %v", err)
		}
		return
	case "":
	default:
		log.Fatalf("unknown command %q (supported: login)", flag.Arg(0))
	}

	if err := ensureLoggedIn(ctx, fileStore); err != nil {
		log.Fatalf("auth: %v", err)
	}
	server := newMCPServer(stdioGenerate(fileStore), stdioUsage(fileStore))
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("stdio server: %v", err)
	}
}

type generateHandler func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error)
type usageHandler func(context.Context, getUsageArgs) (*mcp.CallToolResult, usageResult, error)

// newMCPServer builds an MCP server with the two tools. The handlers differ by
// mode: stdio works on the single local account; the hosted server on the
// authenticated user's accounts.
func newMCPServer(generate generateHandler, usage usageHandler) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: serverVersion}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name: "generate_image",
		Description: "Generate an image with the Codex image model (GPT Image, gpt-5.6-terra). " +
			"Generation can take up to 420 seconds — do NOT treat a long-running call as stuck; the server " +
			"streams progress notifications and only errors out after 10 minutes. " +
			"ALWAYS look at the image after generating: open decrypted_asset_url from the result (hosted) or read " +
			"saved_path (local stdio) and view it, so you can confirm it matches the request before continuing. " +
			"decrypted_asset_url returns the decrypted PNG (image/png) directly, no decryption needed on your side. " +
			"(asset_url is the raw encrypted ciphertext and decryption_key is its key, if you'd rather fetch and " +
			"decrypt it yourself.) The result also includes the account's remaining rate limits under usage. " +
			"For reference_images: do NOT base64-encode or inline images — upload the raw bytes to the server's " +
			"/upload endpoint and pass the returned ref_ handle (see the reference_images field).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
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
		refs, err := resolveReferences(args.ReferenceImages, true)
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

// resolveHostedReferences turns each reference into a data: URL. A "ref_" handle
// is an uploaded image: it's fetched and decrypted (it stays reusable until it
// expires, one hour after upload). A data:/base64 value is used inline (fine
// for small images). A file path is rejected — a remote server can't read the
// caller's filesystem.
func resolveHostedReferences(ctx context.Context, assets *assetStore, userID string, refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "ref_") {
			img, err := assets.fetchUpload(ctx, userID, ref)
			if err != nil {
				// Log the id only — the part after the dot is the decryption key.
				logImage("reference %s failed: %v", refID(ref), err)
				return nil, fmt.Errorf("reference %s: %w (uploads expire 1 hour after upload — re-upload to /upload and retry with the new handle)", refID(ref), err)
			}
			out = append(out, bytesToDataURL(img))
			continue
		}
		dataURL, err := resolveReference(ref, false)
		if err != nil {
			return nil, err
		}
		out = append(out, dataURL)
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
func hostedGenerate(st *store, assets *assetStore, publicURL string) func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
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
				"decryption_key is the AES-256-GCM key, returned only here and never stored.", len(img.PNG))
		callResult := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: note}}}
		return callResult, result, nil
	}
}

func serveHTTP(addr string) {
	secret := strings.TrimSpace(os.Getenv("PINTR_SECRET"))
	if len(secret) < 32 {
		log.Fatal("HTTP mode requires PINTR_SECRET (>= 32 random chars) — it signs tokens and encrypts stored credentials")
	}
	dbPath := os.Getenv("PINTR_DB")
	if dbPath == "" {
		dbPath = "pintr.db"
	}
	publicURL := os.Getenv("PINTR_PUBLIC_URL")
	if publicURL == "" {
		publicURL = "https://pintr.giuli.dev"
	}

	st, err := openStore(dbPath, []byte(secret))
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer st.close()

	assets := newAssetStore()
	if assets == nil {
		log.Print("warning: PINTR_S3_* not set — image storage disabled; generate_image will error until configured")
	} else {
		assets.startUploadJanitor(context.Background())
	}

	provider := newOAuthProvider(publicURL, st)
	web := newWebHandlers(st, provider, assets, strings.HasPrefix(publicURL, "https://"))

	hosted := hostedGenerate(st, assets, publicURL)
	hostedUsageFn := hostedUsage(st)

	// Stateless: getServer runs per request, so the MCP server is always bound
	// to the current request's authenticated user (no cross-user session reuse).
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			if _, ok := userFromContext(r.Context()); !ok {
				return nil
			}
			return newMCPServer(hosted, hostedUsageFn)
		},
		// DisableLocalhostProtection: requests arrive from nginx on 127.0.0.1
		// with Host pintr.giuli.dev, which the SDK's DNS-rebinding guard would
		// otherwise reject. The bearer gate in requireAuth is the real defense —
		// a rebound browser origin can't supply a valid token.
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true},
	)

	mux := http.NewServeMux()
	// MCP OAuth protocol endpoints. The resource metadata is served both at the
	// root well-known path and the resource-suffixed path (…/mcp) so both
	// RFC 9728 client discovery styles work.
	mux.HandleFunc("/.well-known/oauth-protected-resource", provider.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", provider.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", provider.handleAuthServerMetadata)
	mux.HandleFunc("/register", provider.handleRegister)
	mux.HandleFunc("/authorize", provider.handleAuthorize)
	mux.HandleFunc("/token", provider.handleToken)
	// MCP endpoint (bearer-guarded, per-user)
	mux.Handle("/mcp", provider.requireAuth(mcpHandler))
	// Dashboard
	mux.HandleFunc("/signup", web.handleSignup)
	mux.HandleFunc("/login", web.handleLogin)
	mux.HandleFunc("/logout", web.handleLogout)
	mux.HandleFunc("/dashboard", web.handleDashboard)
	mux.HandleFunc("/link/start", web.handleLinkStart)
	mux.HandleFunc("/link/finish", web.handleLinkFinish)
	mux.HandleFunc("/accounts/default", web.handleAccountDefault)
	mux.HandleFunc("/accounts/remove", web.handleAccountRemove)
	mux.HandleFunc("/keys/create", web.handleKeyCreate)
	mux.HandleFunc("/keys/remove", web.handleKeyRemove)
	mux.HandleFunc("/tokens/revoke", web.handleRevokeTokens)
	mux.HandleFunc("/sessions/remove", web.handleSessionRemove)
	mux.HandleFunc("/usage/refresh", web.handleUsageRefresh)
	mux.HandleFunc("/assets/purge", web.handleAssetsPurge)
	mux.HandleFunc("/account/delete", web.handleDeleteAccount)
	mux.HandleFunc("/upload", web.handleUpload)
	mux.HandleFunc("/view", web.handleView)
	mux.HandleFunc("/llms.txt", handleLLMs)
	mux.HandleFunc("/", web.handleIndex)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("pintr listening on %s (public url %s, db %s)", addr, publicURL, dbPath)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
