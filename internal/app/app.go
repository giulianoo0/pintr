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
	"github.com/giulianoo0/pintr/internal/referenceupload"
	"github.com/giulianoo0/pintr/internal/remoteimage"
	"github.com/giulianoo0/pintr/internal/store"
	"github.com/giulianoo0/pintr/internal/turnstile"
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
	// generate_video is hosted-only: it needs the per-user Runway token the
	// dashboard stores, which stdio mode has no place for.
	server := mcpserver.New(false, mcpserver.StdioGenerate(authStore), mcpserver.StdioUsage(authStore), nil, nil)
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
	verifier := turnstile.New()
	if verifier != nil {
		log.Print("turnstile enabled on signup/login/link/consent (PINTR_TURNSTILE_* set)")
	}

	provider := oauth.New(publicURL, st)
	provider.Analytics = tracker
	provider.VerifyHuman = verifier.Check
	webHandlers := web.New(st, provider, assetStore, tracker, verifier, strings.HasPrefix(publicURL, "https://"))
	// The authorize endpoint needs the browser session and the consent page,
	// both owned by web; injecting them here keeps oauth free of cookies and
	// templates.
	provider.LookupSession = webHandlers.SessionFromRequest
	provider.RenderConsent = web.RenderConsent

	hostedGenerate := mcpserver.HostedGenerate(st, assetStore, tracker, publicURL, remoteimage.New())
	hostedGenerateVideo := mcpserver.HostedGenerateVideo(st, assetStore, tracker, publicURL, remoteimage.New())
	hostedUsage := mcpserver.HostedUsage(st, tracker)
	var (
		uploadHandler         http.Handler
		hostedReferenceUpload mcpserver.ReferenceUploadFunc
	)
	if assetStore != nil {
		uploadManager := referenceupload.New([]byte(secret), publicURL, assetStore, func() {
			tracker.Event("reference_upload")
		})
		uploadHandler = uploadManager
		hostedReferenceUpload = mcpserver.HostedReferenceUpload(uploadManager)
	}

	// Stateless: getServer runs per request, so the MCP server is always bound
	// to the current request's authenticated user (no cross-user session reuse).
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			if _, ok := oauth.UserFromContext(r.Context()); !ok {
				return nil
			}
			return mcpserver.New(true, hostedGenerate, hostedUsage, hostedReferenceUpload, hostedGenerateVideo)
		},
		// DisableLocalhostProtection: requests arrive from nginx on 127.0.0.1
		// with Host pintr.giuli.dev, which the SDK's DNS-rebinding guard would
		// otherwise reject. The bearer gate in RequireAuth is the real defense —
		// a rebound browser origin can't supply a valid token.
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true},
	)

	mux := newHTTPMux(provider, webHandlers, mcpHandler, uploadHandler)

	httpServer := newHTTPServer(addr, mux)
	log.Printf("pintr listening on %s (public url %s, db %s)", addr, publicURL, dbPath)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       5 * time.Minute,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func newHTTPMux(provider *oauth.Provider, webHandlers *web.Handlers, mcpHandler, uploadHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	provider.Register(mux)
	webHandlers.Register(mux)
	if uploadHandler != nil {
		// The short-lived HMAC ticket is this endpoint's narrowly scoped
		// authorization; it must remain reachable from Claude's sandbox without
		// the MCP bearer token.
		mux.Handle("/reference-upload/", uploadHandler)
	}
	// MCP remains bearer-guarded and binds each request to its OAuth user.
	mux.Handle("/mcp", provider.RequireAuth(mcpHandler))
	return mux
}
