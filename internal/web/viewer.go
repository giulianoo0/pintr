package web

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed llms.txt
var llmsTxt string

// handleLLMs serves the project's llms.txt (endpoints and behavior for LLMs).
func handleLLMs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(llmsTxt))
}

// handleView fetches the ciphertext from storage, decrypts it server-side with
// the key from the query, and writes the raw image — nothing else, so opening
// the link shows the image in a browser or hands an agent usable bytes.
func (h *Handlers) handleView(w http.ResponseWriter, r *http.Request) {
	if h.assets == nil {
		http.Error(w, "asset storage is not configured", http.StatusServiceUnavailable)
		return
	}
	objectKey := r.URL.Query().Get("o")
	keyB64 := r.URL.Query().Get("k")
	if !strings.HasPrefix(objectKey, "assets/") || strings.Contains(objectKey, "..") {
		http.Error(w, "bad asset reference", http.StatusBadRequest)
		return
	}

	png, err := h.assets.FetchAndDecrypt(r.Context(), objectKey, keyB64)
	if err != nil {
		// Same response whether the object is missing or the key is wrong, so
		// the endpoint isn't an oracle.
		http.Error(w, "could not decrypt this asset (wrong or missing key)", http.StatusBadRequest)
		return
	}

	// Only ever serve image types on this origin. Generated assets are always
	// images, but if decrypted bytes were somehow HTML-shaped, sniffing them
	// into text/html here would be stored XSS on the app domain.
	contentType := http.DetectContentType(png)
	if !strings.HasPrefix(contentType, "image/") {
		contentType = "application/octet-stream"
		w.Header().Set("Content-Disposition", "attachment; filename=asset")
	}
	h.analytics.Event("image_view")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	_, _ = w.Write(png)
}
