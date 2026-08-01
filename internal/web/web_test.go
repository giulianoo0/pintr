package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyUploadRouteIsNotRegistered(t *testing.T) {
	mux := http.NewServeMux()
	(&Handlers{}).Register(mux)
	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /upload status = %d, want 404", w.Code)
	}
}
