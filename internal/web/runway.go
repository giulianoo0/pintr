package web

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/giulianoo0/pintr/internal/runway"
	"github.com/giulianoo0/pintr/internal/store"
)

// Connecting Runway. There is no OAuth to hang this off: the endpoints pintr
// uses are Runway's own app API, authenticated with the bearer token the web
// app keeps in localStorage. So the flow is a paste box — validated against
// Runway before it is stored, so a typo fails here rather than at generation
// time.

// runwayConnectTimeout bounds the validation calls made while the user waits
// on the form.
const runwayConnectTimeout = 20 * time.Second

func (h *Handlers) handleRunwayConnect(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !h.checkCSRF(w, r, session) {
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	// People paste the whole "Bearer eyJ…" line out of devtools often enough to
	// be worth handling rather than rejecting.
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	if token == "" {
		h.runwayError(w, "paste your runway token first")
		return
	}
	if strings.Count(token, ".") != 2 {
		h.runwayError(w, "that doesn't look like a runway token — copy the whole RW_USER_TOKEN value (three dot-separated parts, starting with eyJ)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), runwayConnectTimeout)
	defer cancel()

	client := runway.NewClient(token, 0)
	profile, err := client.GetProfile(ctx)
	if err != nil {
		log.Printf("runway connect for %s: profile: %v", session.User.ID, err)
		h.runwayError(w, "runway rejected that token — make sure you copied the current RW_USER_TOKEN value from a logged-in runway tab")
		return
	}
	teams, err := client.ListTeams(ctx)
	if err != nil || len(teams) == 0 {
		log.Printf("runway connect for %s: teams: %v", session.User.ID, err)
		h.runwayError(w, "connected to runway but found no workspace for that account")
		return
	}

	account := store.RunwayAccount{
		RunwayUserID: strconv.FormatInt(profile.ID, 10),
		TeamID:       teams[0].ID,
		Username:     firstNonEmpty(teams[0].Username, profile.Username),
		Email:        profile.Email,
		Plan:         profile.Plan,
	}
	if expires, err := runway.TokenExpiry(token); err == nil {
		account.TokenExpires = expires
	}
	if err := h.store.UpsertRunwayAccount(r.Context(), session.User.ID, account, token); err != nil {
		log.Printf("runway connect for %s: store: %v", session.User.ID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.analytics.Event("runway_connect")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (h *Handlers) handleRunwayDisconnect(w http.ResponseWriter, r *http.Request) {
	h.mutate(w, r, func(session store.SessionInfo) error {
		return h.store.DeleteRunwayAccount(r.Context(), session.User.ID)
	})
}

func (h *Handlers) runwayError(w http.ResponseWriter, message string) {
	renderMessage(w, authedPage("connect runway"), message, "/dashboard", "back to dashboard")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
