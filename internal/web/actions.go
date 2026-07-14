package web

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/store"
)

// Dashboard mutations: small session+CSRF-checked POSTs that change one thing
// and bounce back to the dashboard, plus the few that render or reply directly
// (key creation, upload, account deletion).

// mutate runs a session-checked, CSRF-checked change and returns to the dashboard.
func (h *Handlers) mutate(w http.ResponseWriter, r *http.Request, fn func(store.SessionInfo) error) {
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

func (h *Handlers) handleAccountDefault(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		return h.store.SetDefaultCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *Handlers) handleAccountRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		return h.store.DeleteCodexAccount(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

func (h *Handlers) handleKeyRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		return h.store.DeleteAccessKey(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

// handleRevokeTokens invalidates all issued OAuth tokens at once (kill-switch):
// it bumps the token epoch and removes every OAuth session.
func (h *Handlers) handleRevokeTokens(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		if err := h.store.RevokeTokens(r.Context(), session.User.ID); err != nil {
			return err
		}
		return h.store.DeleteAllOAuthSessions(r.Context(), session.User.ID)
	})
}

// handleSessionRemove revokes a single OAuth session (one client's tokens).
func (h *Handlers) handleSessionRemove(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		return h.store.DeleteOAuthSession(r.Context(), session.User.ID, r.FormValue("id"))
	})
}

// handleUsageRefresh force-fetches each linked account's Codex limits (resetting
// the usage cache) and returns to the dashboard.
func (h *Handlers) handleUsageRefresh(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		accounts, err := codex.UserAccounts(r.Context(), h.store, session.User.ID)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			if _, _, uerr := codex.CachedUsage(r.Context(), account, true); uerr != nil {
				log.Printf("usage refresh for %s: %v", account.Label(), uerr)
			}
		}
		return nil
	})
}

// handleAssetsPurge deletes the user's stored (encrypted) objects. The form's
// "kind" field picks what: generated images, reference uploads, or (default)
// both.
func (h *Handlers) handleAssetsPurge(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
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
			deleted, err = h.assets.DeleteAssets(r.Context(), session.User.ID)
		case "uploads":
			deleted, err = h.assets.DeleteUploads(r.Context(), session.User.ID)
		default:
			kind = "all"
			deleted, err = h.assets.DeleteAll(r.Context(), session.User.ID)
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

func (h *Handlers) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}
	key, err := h.store.CreateAccessKey(r.Context(), session.User.ID, r.FormValue("name"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "newkey", newKeyPage{basePage: authedPage("new access key"), Key: key})
}

// handleDeleteAccount permanently deletes the user and everything they own:
// stored images in S3, then the DB row (which cascades to sessions, access
// keys, and linked codex accounts).
func (h *Handlers) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
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
		if _, err := h.assets.DeleteAll(r.Context(), session.User.ID); err != nil {
			log.Printf("delete account: purge assets for %s: %v", session.User.ID, err)
			http.Error(w, "could not delete your stored images — account NOT deleted, please try again", http.StatusInternalServerError)
			return
		}
	}
	if err := h.store.DeleteUser(r.Context(), session.User.ID); err != nil {
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
func (h *Handlers) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, ok := h.provider.AuthenticatedUser(r)
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
	handle, err := h.assets.PutUploadEncrypted(r.Context(), user.ID, body)
	if err != nil {
		log.Printf("upload for %s: %v", user.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ref": handle})
}
