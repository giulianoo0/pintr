package main

import (
	"net/http"
	"net/url"
	"strings"
)

// decryptedAssetURL builds a link that returns the decrypted image directly.
// The object key and the decryption key travel as query params so an agent that
// can only open a url (no javascript) gets back the raw image with the right
// content-type. The server decrypts on the fly; it does not persist the key.
func decryptedAssetURL(publicURL, objectKey, keyB64 string) string {
	return publicURL + "/view?o=" + url.QueryEscape(objectKey) + "&k=" + url.QueryEscape(keyB64)
}

// handleView fetches the ciphertext from storage, decrypts it server-side with
// the key from the query, and writes the raw image — nothing else, so opening
// the link shows the image in a browser or hands an agent usable bytes.
func (h *webHandlers) handleView(w http.ResponseWriter, r *http.Request) {
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

	png, err := h.assets.fetchAndDecrypt(r.Context(), objectKey, keyB64)
	if err != nil {
		// Same response whether the object is missing or the key is wrong, so
		// the endpoint isn't an oracle.
		http.Error(w, "could not decrypt this asset (wrong or missing key)", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", http.DetectContentType(png))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(png)
}
