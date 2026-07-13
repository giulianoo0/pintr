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
	"flag"
	"log"
	"net/http"
	"os"
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
	server := newMCPServer(func(context.Context) ([]codexAccount, error) {
		return []codexAccount{fileAccount{store: fileStore}}, nil
	})
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("stdio server: %v", err)
	}
}

// newMCPServer builds an MCP server whose generate_image tool resolves accounts
// lazily via resolve — one local account in stdio mode, or the calling user's
// linked accounts in HTTP mode.
func newMCPServer(resolve func(context.Context) ([]codexAccount, error)) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: serverVersion}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name: "generate_image",
		Description: "Generate an image with the Codex image model (GPT Image, gpt-5.6-terra) and save it as a PNG at output_path. " +
			"Optionally pass reference_images (file paths) to anchor characters, style, or an existing frame.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		accounts, err := resolve(ctx)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		result, err := generateImage(ctx, accounts, args)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return nil, result, nil
	})
	return server
}

func serveHTTP(addr string) {
	secret := strings.TrimSpace(os.Getenv("PINTR_SECRET"))
	if len(secret) < 16 {
		log.Fatal("HTTP mode requires PINTR_SECRET (>= 16 chars) — signs tokens and encrypts stored credentials")
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

	provider := newOAuthProvider(publicURL, st)
	web := newWebHandlers(st, provider, strings.HasPrefix(publicURL, "https://"))

	// Stateless: getServer runs per request, so the MCP server is always bound
	// to the current request's authenticated user (no cross-user session reuse).
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			u, ok := userFromContext(r.Context())
			if !ok {
				return nil
			}
			return newMCPServer(func(ctx context.Context) ([]codexAccount, error) {
				return userCodexAccounts(ctx, st, u.ID)
			})
		},
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true},
	)

	mux := http.NewServeMux()
	// MCP OAuth protocol endpoints
	mux.HandleFunc("/.well-known/oauth-protected-resource", provider.handleProtectedResourceMetadata)
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
