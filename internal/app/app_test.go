package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/store"
	"github.com/giulianoo0/pintr/internal/web"
)

func testHostedWeb(t *testing.T) (*oauth.Provider, *web.Handlers, string) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "pintr.db"), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	user, err := st.CreateUser(context.Background(), "route-test@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	key, err := st.CreateAccessKey(context.Background(), user.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	provider := oauth.New("https://pintr.example", st)
	return provider, web.New(st, provider, nil, nil, nil, true), key
}

func TestHTTPRoutesKeepMCPAuthenticatedAndReferenceUploadPublic(t *testing.T) {
	provider, webHandlers, key := testHostedWeb(t)
	mcpCalls := 0
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mcpCalls++
		w.WriteHeader(http.StatusNoContent)
	})
	uploadCalls := 0
	uploadHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadCalls++
		w.WriteHeader(http.StatusCreated)
	})
	mux := newHTTPMux(provider, webHandlers, mcpHandler, uploadHandler)

	uploadRequest := httptest.NewRequest(http.MethodPut, "/reference-upload/signed-token", nil)
	uploadResponse := httptest.NewRecorder()
	mux.ServeHTTP(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusCreated || uploadCalls != 1 {
		t.Fatalf("public upload status = %d, calls = %d; want 201 and 1", uploadResponse.Code, uploadCalls)
	}

	unauthenticatedMCP := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	unauthenticatedResponse := httptest.NewRecorder()
	mux.ServeHTTP(unauthenticatedResponse, unauthenticatedMCP)
	if unauthenticatedResponse.Code != http.StatusUnauthorized || mcpCalls != 0 {
		t.Fatalf("unauthenticated MCP status = %d, calls = %d; want 401 and 0", unauthenticatedResponse.Code, mcpCalls)
	}

	authenticatedMCP := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	authenticatedMCP.Header.Set("Authorization", "Bearer "+key)
	authenticatedResponse := httptest.NewRecorder()
	mux.ServeHTTP(authenticatedResponse, authenticatedMCP)
	if authenticatedResponse.Code != http.StatusNoContent || mcpCalls != 1 {
		t.Fatalf("authenticated MCP status = %d, calls = %d; want 204 and 1", authenticatedResponse.Code, mcpCalls)
	}
}

func TestHTTPRoutesOmitReferenceUploadWhenStorageIsUnavailable(t *testing.T) {
	provider, webHandlers, _ := testHostedWeb(t)
	mux := newHTTPMux(provider, webHandlers, http.NotFoundHandler(), nil)
	req := httptest.NewRequest(http.MethodPut, "/reference-upload/signed-token", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("reference upload without storage status = %d, want 404", w.Code)
	}
}

func TestHostedHTTPServerHasRequestBodyReadTimeout(t *testing.T) {
	server := newHTTPServer(":0", http.NotFoundHandler())
	if server.ReadTimeout != 5*time.Minute {
		t.Fatalf("ReadTimeout = %s, want 5m", server.ReadTimeout)
	}
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 10s", server.ReadHeaderTimeout)
	}
}
