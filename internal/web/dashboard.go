package web

import (
	"log"
	"math"
	"net/http"
	"time"

	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/store"
)

// View models for the dashboard template. Everything is precomputed here so
// the template only interpolates plain values.

type dashboardPage struct {
	Title            string
	CSRF             string
	Resource         string
	Email            string
	Accounts         []dashAccount
	Keys             []store.AccessKey
	OAuthSessions    []store.OAuthSession
	AssetsConfigured bool
	AssetCountKnown  bool
	AssetCount       int // generated images stored
	UploadCountKnown bool
	UploadCount      int // reference uploads stored
}

type dashAccount struct {
	ID        string
	Email     string
	Plan      string
	IsDefault bool
	HasUsage  bool
	Windows   []dashWindow
	FreshAge  int // seconds since the usage was fetched
	FreshLeft int // seconds until the usage cache expires
}

// dashWindow is one rate-limit bar; Class colors it by how much is left.
type dashWindow struct {
	Label string
	Class string
	Pct   int
}

func barClass(remainingPercent float64) string {
	switch {
	case remainingPercent <= 10:
		return "low"
	case remainingPercent <= 30:
		return "warn"
	default:
		return "ok"
	}
}

func dashWindows(usage codex.AccountUsage) []dashWindow {
	windows := make([]dashWindow, 0, len(usage.Windows))
	for _, w := range usage.Windows {
		windows = append(windows, dashWindow{
			Label: w.Label,
			Class: barClass(w.RemainingPercent),
			Pct:   int(math.Round(w.RemainingPercent)),
		})
	}
	return windows
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func shortDate(rfc3339 string) string {
	if t, err := time.Parse(time.RFC3339, rfc3339); err == nil {
		return t.Format("2006-01-02")
	}
	return rfc3339
}

func (h *Handlers) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	accounts, err := h.store.ListCodexAccounts(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	keys, err := h.store.ListAccessKeys(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	oauthSessions, err := h.store.ListOAuthSessions(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	page := dashboardPage{
		Title:         "pintr dashboard",
		CSRF:          session.CSRF,
		Resource:      h.provider.ResourceURL(),
		Email:         session.User.Email,
		Keys:          keys,
		OAuthSessions: oauthSessions,
	}

	for _, a := range accounts {
		entry := dashAccount{
			ID:        a.ID,
			Email:     orUnknown(a.Email),
			Plan:      orUnknown(a.PlanType),
			IsDefault: a.IsDefault,
		}
		account := codex.NewDBAccount(h.store, session.User.ID, a.ID, orUnknown(a.Email))
		if usage, at, uerr := codex.CachedUsage(r.Context(), account, false); uerr == nil {
			entry.HasUsage = true
			entry.Windows = dashWindows(usage)
			entry.FreshAge = max(int(time.Since(at).Seconds()), 0)
			entry.FreshLeft = max(int(codex.UsageTTL.Seconds())-entry.FreshAge, 0)
		}
		page.Accounts = append(page.Accounts, entry)
	}

	if h.assets != nil {
		page.AssetsConfigured = true
		if count, err := h.assets.CountAssets(r.Context(), session.User.ID); err != nil {
			log.Printf("dashboard: count assets: %v", err)
		} else {
			page.AssetCountKnown = true
			page.AssetCount = count
		}
		if count, err := h.assets.CountUploads(r.Context(), session.User.ID); err != nil {
			log.Printf("dashboard: count uploads: %v", err)
		} else {
			page.UploadCountKnown = true
			page.UploadCount = count
		}
	}

	renderTemplate(w, "dashboard", page)
}
