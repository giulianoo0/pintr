package main

import (
	"html/template"
	"log"
	"math"
	"net/http"
	"time"
)

// View models for the dashboard template. Everything is precomputed here so
// the template only interpolates plain values.

type dashboardPage struct {
	Title            string
	CSRF             string
	Resource         string
	Email            string
	Accounts         []dashAccount
	Keys             []accessKeyRow
	OAuthSessions    []oauthSessionRow
	AssetsConfigured bool
	AssetCountKnown  bool
	AssetCount       int
	Script           template.JS
}

type dashAccount struct {
	ID        string
	Email     string
	Plan      string
	IsDefault bool
	HasUsage  bool
	Windows   []dashWindow
	FreshAge  int // seconds since the usage was fetched
	FreshLeft int // seconds until the 30m cache expires
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

func dashWindows(usage accountUsage) []dashWindow {
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

func (h *webHandlers) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}

	accounts, err := h.store.listCodexAccounts(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	keys, err := h.store.listAccessKeys(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	oauthSessions, err := h.store.listOAuthSessions(r.Context(), session.User.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	page := dashboardPage{
		Title:         "pintr dashboard",
		CSRF:          session.CSRF,
		Resource:      h.provider.resourceURL,
		Email:         session.User.Email,
		Keys:          keys,
		OAuthSessions: oauthSessions,
		Script:        dashScript,
	}

	for _, a := range accounts {
		entry := dashAccount{
			ID:        a.ID,
			Email:     orUnknown(a.Email),
			Plan:      orUnknown(a.PlanType),
			IsDefault: a.IsDefault,
		}
		account := dbAccount{store: h.store, userID: session.User.ID, rowID: a.ID, display: orUnknown(a.Email)}
		if usage, at, uerr := accountUsage30m(r.Context(), account, false); uerr == nil {
			entry.HasUsage = true
			entry.Windows = dashWindows(usage)
			entry.FreshAge = max(int(time.Since(at).Seconds()), 0)
			entry.FreshLeft = max(int(usageTTL.Seconds())-entry.FreshAge, 0)
		}
		page.Accounts = append(page.Accounts, entry)
	}

	if h.assets != nil {
		page.AssetsConfigured = true
		if count, err := h.assets.countAssets(r.Context(), session.User.ID); err != nil {
			log.Printf("dashboard: count assets: %v", err)
		} else {
			page.AssetCountKnown = true
			page.AssetCount = count
		}
	}

	renderTemplate(w, "dashboard", page)
}
