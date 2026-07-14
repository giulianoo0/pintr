package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serveHTTP wires up and runs the hosted, multi-user app: the dashboard, the
// MCP OAuth provider, and the bearer-guarded MCP endpoint.
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
