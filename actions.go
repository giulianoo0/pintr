package main

import (
	"io"
	"log"
	"net/http"
	"strings"
)

// Dashboard mutations: small session+CSRF-checked POSTs that change one thing
// and bounce back to the dashboard, plus the few that render or reply directly
// (key creation, upload, account deletion).

// mutate runs a session-checked, CSRF-checked change and returns to the dashboard.
func (h *webHandlers) mutate(w http.ResponseWriter, r *http.Request, fn func(sessionInfo) error) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	if err := fn(session); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (h *webHandlers) handleAccountDefault(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.setDefaultCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *webHandlers) handleAccountRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.deleteCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *webHandlers) handleKeyRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.deleteAccessKey(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

// handleRevokeTokens invalidates all issued OAuth tokens at once (kill-switch):
// it bumps the token epoch and removes every OAuth session.
func (h *webHandlers) handleRevokeTokens(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		if err := h.store.revokeTokens(r.Context(), session.User.ID); err != nil {
			return err
		}
		return h.store.deleteAllOAuthSessions(r.Context(), session.User.ID)
	})
}

// handleSessionRemove revokes a single OAuth session (one client's tokens).
func (h *webHandlers) handleSessionRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		return h.store.deleteOAuthSession(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

// handleUsageRefresh force-fetches each linked account's Codex limits (resetting
// the 30-minute cache) and returns to the dashboard.
func (h *webHandlers) handleUsageRefresh(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		accounts, err := userCodexAccounts(r.Context(), h.store, session.User.ID)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			if _, _, uerr := accountUsage30m(r.Context(), account, true); uerr != nil {
				log.Printf("usage refresh for %s: %v", account.label(), uerr)
			}
		}
		return nil
	})
}

// handleAssetsPurge deletes the user's stored (encrypted) objects. The form's
// "kind" field picks what: generated images, reference uploads, or (default)
// both.
func (h *webHandlers) handleAssetsPurge(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session sessionInfo) error {
		if h.assets == nil {
			return nil
		}
		kind := r.FormValue("kind")
		var (
			deleted int
			err     error
		)
		switch kind {
		case "generated":
			deleted, err = h.assets.deleteAssets(r.Context(), session.User.ID)
		case "uploads":
			deleted, err = h.assets.deleteUploads(r.Context(), session.User.ID)
		default:
			kind = "all"
			deleted, err = h.assets.deleteAll(r.Context(), session.User.ID)
		}
		if err != nil {
			log.Printf("purge %s for %s: %v", kind, session.User.ID, err)
			return err
		}
		log.Printf("purged %d object(s) (%s) for %s", deleted, kind, session.User.ID)
		return nil
	})
}

type newKeyPage struct {
	basePage
	Key string
}

func (h *webHandlers) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	key, err := h.store.createAccessKey(r.Context(), session.User.ID, r.FormValue("name"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "newkey", newKeyPage{basePage: authedPage("new access key"), Key: key})
}

// handleDeleteAccount permanently deletes the user and everything they own:
// stored images in S3, then the DB row (which cascades to sessions, access
// keys, and linked codex accounts).
func (h *webHandlers) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	// Delete stored assets first; if that fails, keep the account so nothing is
	// left half-deleted and the user can retry.
	if h.assets != nil {
		if _, err := h.assets.deleteAll(r.Context(), session.User.ID); err != nil {
			log.Printf("delete account: purge assets for %s: %v", session.User.ID, err)
			http.Error(w, "could not delete your stored images — account NOT deleted, please try again", http.StatusInternalServerError)
			return
		}
	}
	if err := h.store.deleteUser(r.Context(), session.User.ID); err != nil {
		log.Printf("delete account %s: %v", session.User.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.clearSessionCookie(w)
	log.Printf("deleted account %s (%s)", session.User.ID, session.User.Email)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleUpload accepts a reference image (raw bytes, bearer-authenticated),
// encrypts and stores it, and returns a short handle. The handle goes into a
// generate_image call instead of the image bytes, keeping large data out of the
// model's context. The upload stays reusable for one hour, then the janitor
// deletes it.
func (h *webHandlers) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.provider.authenticatedUser(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.assets == nil {
		http.Error(w, "asset storage is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20)) // 25 MiB cap
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if mime := http.DetectContentType(body); !strings.HasPrefix(mime, "image/") {
		http.Error(w, "body is not an image", http.StatusBadRequest)
		return
	}
	handle, err := h.assets.putUploadEncrypted(r.Context(), user.ID, body)
	if err != nil {
		log.Printf("upload for %s: %v", user.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"ref": handle})
}
