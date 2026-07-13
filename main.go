// Command pintr is an MCP server that generates images through the Codex
// backend using the user's own ChatGPT OAuth login.
//
// Usage:
//
//	pintr login              # browser OAuth login only
//	pintr                    # serve MCP over stdio (logs in first if needed)
//	pintr -http 127.0.0.1:8090   # serve MCP over streamable HTTP
//
// HTTP mode requires MCP_AUTH_TOKEN in the environment; every request must
// carry "Authorization: Bearer $MCP_AUTH_TOKEN".
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverVersion = "0.1.0"

func main() {
	httpAddr := flag.String("http", "", "serve MCP over streamable HTTP on this address instead of stdio")
	authFile := flag.String("auth-file", "", "path to the auth token file (default: ~/.config/pintr/auth.json)")
	flag.Parse()

	store := newAuthStore(*authFile)
	ctx := context.Background()

	switch flag.Arg(0) {
	case "login":
		if _, err := runLogin(ctx, store); err != nil {
			log.Fatalf("login failed: %v", err)
		}
		return
	case "":
		// fall through to serve
	default:
		log.Fatalf("unknown command %q (supported: login)", flag.Arg(0))
	}

	server := newMCPServer(store)
	if *httpAddr != "" {
		// HTTP mode is headless (systemd): never trigger an interactive login
		// here. If auth is missing, start anyway and let tool calls return an
		// actionable error until `pintr login` is run once.
		if _, err := store.load(); err != nil {
			log.Printf("warning: not logged in yet (%v) — run `pintr login`; serving anyway", err)
		}
		serveHTTP(server, *httpAddr)
		return
	}

	if err := ensureLoggedIn(ctx, store); err != nil {
		log.Fatalf("auth: %v", err)
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("stdio server: %v", err)
	}
}

func newMCPServer(store *authStore) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "pintr", Version: serverVersion}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name: "generate_image",
		Description: "Generate an image with the Codex image model (GPT Image) and save it as a PNG at output_path. " +
			"Optionally pass reference_images (file paths) to anchor characters, style, or an existing frame.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		result, err := generateImage(ctx, store, args)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return nil, result, nil
	})
	return server
}

func serveHTTP(server *mcp.Server, addr string) {
	authToken := os.Getenv("MCP_AUTH_TOKEN")
	if authToken == "" {
		log.Fatal("HTTP mode requires MCP_AUTH_TOKEN to be set — refusing to expose the server unauthenticated")
	}

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		// Localhost protection would 403 proxied requests (they arrive on
		// 127.0.0.1 with Host pintr.giuli.dev); the bearer check below is the
		// real gate.
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true},
	)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           requireBearer(authToken, handler),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("pintr listening on %s", addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

func requireBearer(token string, next http.Handler) http.Handler {
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(expected) || subtle.ConstantTimeCompare(got, expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
