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
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverVersion = "0.2.0"

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
	server := newMCPServer(stdioGenerate(fileStore))
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("stdio server: %v", err)
	}
}

// newMCPServer builds an MCP server whose generate_image tool runs the given
// handler. The handler differs by mode: stdio writes a local file; the hosted
// server encrypts and uploads.
func newMCPServer(run func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error)) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: serverVersion}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name: "generate_image",
		Description: "Generate an image with the Codex image model (GPT Image, gpt-5.6-terra). " +
			"Optionally pass reference_images to anchor characters or style. On the hosted server the PNG is " +
			"encrypted, stored, and returned as a presigned download URL plus a one-time decryption key (asset_url + decryption_key); " +
			"in local stdio mode it is written to output_path.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		return run(ctx, args)
	})
	return server
}

// stdioGenerate resolves the single local account, generates, and writes the
// PNG to the caller-provided output_path (same machine, so a caller-chosen path
// is fine here).
func stdioGenerate(fileStore *authStore) func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		refs, err := resolveReferences(args.ReferenceImages, true)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := generateImage(ctx, []codexAccount{fileAccount{store: fileStore}}, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		outputPath := strings.TrimSpace(args.OutputPath)
		if outputPath == "" {
			return nil, generateImageResult{}, errors.New("output_path is required in local mode")
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return nil, generateImageResult{}, err
		}
		if err := os.WriteFile(outputPath, img.PNG, 0o644); err != nil {
			return nil, generateImageResult{}, err
		}
		return nil, generateImageResult{
			SavedPath: outputPath, Model: img.Model, Account: img.Account, DurationMs: img.DurationMs,
		}, nil
	}
}

// hostedGenerate resolves the authenticated user's accounts, generates, encrypts
// the PNG under a one-time key, uploads the ciphertext, and returns a presigned
// download URL plus the key. It never touches the local filesystem or a
// caller-chosen path.
func hostedGenerate(st *store, assets *assetStore) func(context.Context, generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		u, ok := userFromContext(ctx)
		if !ok {
			return nil, generateImageResult{}, errors.New("unauthenticated")
		}
		if assets == nil {
			return nil, generateImageResult{}, errors.New("image storage is not configured on this server (set PINTR_S3_*)")
		}
		refs, err := resolveReferences(args.ReferenceImages, false)
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
			AssetURL: stored.URL, DecryptionKey: stored.KeyB64,
			Model: img.Model, Account: img.Account, DurationMs: img.DurationMs, SizeBytes: len(img.PNG),
		}
		note := fmt.Sprintf(
			"Encrypted PNG stored (%d bytes). To save it: download asset_url and decrypt with decryption_key "+
				"(AES-256-GCM; the 12-byte nonce is the file's first bytes). The image is also shown inline below. "+
				"The key is only returned here — it is not stored anywhere.", len(img.PNG))
		callResult := &mcp.CallToolResult{Content: []mcp.Content{
			&mcp.ImageContent{Data: img.PNG, MIMEType: "image/png"},
			&mcp.TextContent{Text: note},
		}}
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
	}

	provider := newOAuthProvider(publicURL, st)
	web := newWebHandlers(st, provider, assets, strings.HasPrefix(publicURL, "https://"))

	hosted := hostedGenerate(st, assets)

	// Stateless: getServer runs per request, so the MCP server is always bound
	// to the current request's authenticated user (no cross-user session reuse).
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			if _, ok := userFromContext(r.Context()); !ok {
				return nil
			}
			return newMCPServer(hosted)
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
	mux.HandleFunc("/assets/purge", web.handleAssetsPurge)
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
