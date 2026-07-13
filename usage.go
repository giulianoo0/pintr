package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Codex usage is cached per account for 30 minutes so passive reads (dashboard
// loads, the usage attached to each generate_image) don't hammer the upstream
// endpoint. A forced read (the dashboard refresh button, the get_usage tool)
// fetches fresh and resets the timer.
const usageTTL = 30 * time.Minute

var (
	usageCacheMu sync.Mutex
	usageCache   = map[string]cachedUsage{}
)

type cachedUsage struct {
	usage     accountUsage
	fetchedAt time.Time
}

// accountUsage30m returns the account's usage and the time it was fetched, using
// the 30-minute cache unless force is set. A successful fetch (forced or a cache
// miss) resets the timer.
func accountUsage30m(ctx context.Context, account codexAccount, force bool) (accountUsage, time.Time, error) {
	key := account.cacheKey()
	if !force {
		usageCacheMu.Lock()
		cached, ok := usageCache[key]
		usageCacheMu.Unlock()
		if ok && time.Since(cached.fetchedAt) < usageTTL {
			return cached.usage, cached.fetchedAt, nil
		}
	}
	usage, err := fetchAccountUsage(ctx, account)
	if err != nil {
		return accountUsage{}, time.Time{}, err
	}
	now := time.Now()
	usageCacheMu.Lock()
	usageCache[key] = cachedUsage{usage: usage, fetchedAt: now}
	usageCacheMu.Unlock()
	return usage, now, nil
}

// pintr reads Codex rate limits from the same endpoint the Codex CLI uses. The
// response exposes rolling windows; OpenAI enables/disables them per plan, so a
// window is only reported when it actually has data.
const codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"

type usageWindow struct {
	Label            string  `json:"label"` // "5h" | "weekly" | "monthly"
	UsedPercent      float64 `json:"used_percent"`
	RemainingPercent float64 `json:"remaining_percent"`
	ResetsAt         int64   `json:"resets_at,omitempty"` // unix seconds
}

type accountUsage struct {
	Account  string        `json:"account"`
	PlanType string        `json:"plan_type,omitempty"`
	Windows  []usageWindow `json:"windows"`
}

// getUsageArgs is the (empty) input to the get_usage tool.
type getUsageArgs struct{}

type usageResult struct {
	Accounts []accountUsage `json:"accounts"`
}

type whamWindow struct {
	UsedPercent        *float64 `json:"used_percent"`
	LimitWindowSeconds *float64 `json:"limit_window_seconds"`
	ResetAt            *float64 `json:"reset_at"`
}

type whamRateLimit struct {
	PrimaryWindow   *whamWindow `json:"primary_window"`
	SecondaryWindow *whamWindow `json:"secondary_window"`
}

type whamPayload struct {
	PlanType             string        `json:"plan_type"`
	RateLimit            whamRateLimit `json:"rate_limit"`
	AdditionalRateLimits []struct {
		RateLimit whamRateLimit `json:"rate_limit"`
	} `json:"additional_rate_limits"`
}

// fetchAccountUsage fetches and labels the rate-limit windows for one account.
func fetchAccountUsage(ctx context.Context, account codexAccount) (accountUsage, error) {
	auth, err := account.fresh(ctx)
	if err != nil {
		return accountUsage{}, err
	}
	usage, err := fetchUsage(ctx, auth)
	if err != nil {
		return accountUsage{}, err
	}
	usage.Account = account.label()
	return usage, nil
}

func fetchUsage(ctx context.Context, auth codexAuth) (accountUsage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageURL, nil)
	if err != nil {
		return accountUsage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+auth.AccessToken)
	req.Header.Set("ChatGPT-Account-ID", auth.AccountID)
	req.Header.Set("originator", oauthOriginator)
	req.Header.Set("version", codexVersion)
	req.Header.Set("User-Agent", codexUserAgent)
	if auth.Fedramp {
		req.Header.Set("X-OpenAI-Fedramp", "true")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return accountUsage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return accountUsage{}, fmt.Errorf("usage request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var payload whamPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return accountUsage{}, err
	}
	return accountUsage{PlanType: payload.PlanType, Windows: classifyWindows(payload)}, nil
}

// classifyWindows labels each present window by its duration and keeps them in
// a stable 5h → weekly → monthly order. Windows without usage data are dropped.
func classifyWindows(p whamPayload) []usageWindow {
	byLabel := map[string]usageWindow{}
	add := func(w *whamWindow) {
		if w == nil || w.UsedPercent == nil || w.LimitWindowSeconds == nil {
			return
		}
		label := windowLabel(*w.LimitWindowSeconds)
		if _, exists := byLabel[label]; exists {
			return // first window of a given size wins
		}
		win := usageWindow{
			Label:            label,
			UsedPercent:      round1(*w.UsedPercent),
			RemainingPercent: round1(clampPercent(100 - *w.UsedPercent)),
		}
		if w.ResetAt != nil {
			win.ResetsAt = int64(*w.ResetAt)
		}
		byLabel[label] = win
	}

	add(p.RateLimit.PrimaryWindow)
	add(p.RateLimit.SecondaryWindow)
	for _, extra := range p.AdditionalRateLimits {
		add(extra.RateLimit.PrimaryWindow)
		add(extra.RateLimit.SecondaryWindow)
	}

	windows := []usageWindow{}
	for _, label := range []string{"5h", "weekly", "monthly"} {
		if win, ok := byLabel[label]; ok {
			windows = append(windows, win)
		}
	}
	return windows
}

func windowLabel(seconds float64) string {
	switch {
	case seconds <= 24*3600:
		return "5h"
	case seconds <= 14*24*3600:
		return "weekly"
	default:
		return "monthly"
	}
}

func clampPercent(v float64) float64 {
	return math.Max(0, math.Min(100, v))
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
