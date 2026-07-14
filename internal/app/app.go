// Package app wires the pieces together for each run mode: the hosted
// multi-user HTTP server and the local stdio MCP server.
package app

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/analytics"
	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/mcpserver"
	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/store"
	"github.com/giulianoo0/pintr/internal/web"
)

// Login runs the interactive browser login and saves tokens to the stdio
// auth file.
func Login(ctx context.Context, authFile string) error {
	_, err := codex.RunLogin(ctx, codex.NewAuthStore(authFile))
	return err
}

// ServeStdio runs the single-user MCP server over stdin/stdout, logging in
// first if there is no saved auth.
func ServeStdio(ctx context.Context, authFile string) error {
	authStore := codex.NewAuthStore(authFile)
	if err := codex.EnsureLoggedIn(ctx, authStore); err != nil {
		return err
	}
	server := mcpserver.New(false, mcpserver.StdioGenerate(authStore), mcpserver.StdioUsage(authStore))
	return server.Run(ctx, &mcp.StdioTransport{})
}

// ServeHTTP wires up and runs the hosted, multi-user app: the dashboard, the
// MCP OAuth provider, and the bearer-guarded MCP endpoint.
func ServeHTTP(addr string) {
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

	st, err := store.New(dbPath, []byte(secret))
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer st.Close()

	assetStore := assets.New()
	if assetStore == nil {
		log.Print("warning: PINTR_S3_* not set — image storage disabled; generate_image will error until configured")
	} else {
		assetStore.StartJanitor(context.Background())
	}

	tracker := analytics.New()
	if tracker != nil {
		log.Print("anonymous analytics enabled (PINTR_PLAUSIBLE_DOMAIN set)")
	}

	provider := oauth.New(publicURL, st)
	provider.Analytics = tracker
	webHandlers := web.New(st, provider, assetStore, tracker, strings.HasPrefix(publicURL, "https://"))
	// The authorize endpoint needs the browser session and the consent page,
	// both owned by web; injecting them here keeps oauth free of cookies and
	// templates.
	provider.LookupSession = webHandlers.SessionFromRequest
	provider.RenderConsent = web.RenderConsent

	hostedGenerate := mcpserver.HostedGenerate(st, assetStore, tracker, publicURL)
	hostedUsage := mcpserver.HostedUsage(st, tracker)

	// Stateless: getServer runs per request, so the MCP server is always bound
	// to the current request's authenticated user (no cross-user session reuse).
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			if _, ok := oauth.UserFromContext(r.Context()); !ok {
				return nil
			}
			return mcpserver.New(true, hostedGenerate, hostedUsage)
		},
		// DisableLocalhostProtection: requests arrive from nginx on 127.0.0.1
		// with Host pintr.giuli.dev, which the SDK's DNS-rebinding guard would
		// otherwise reject. The bearer gate in RequireAuth is the real defense —
		// a rebound browser origin can't supply a valid token.
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true},
	)

	mux := http.NewServeMux()
	provider.Register(mux)
	webHandlers.Register(mux)
	// MCP endpoint (bearer-guarded, per-user)
	mux.Handle("/mcp", provider.RequireAuth(mcpHandler))

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
