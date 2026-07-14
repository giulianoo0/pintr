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
	server := newMCPServer(false, stdioGenerate(fileStore), stdioUsage(fileStore))
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("stdio server: %v", err)
	}
}
