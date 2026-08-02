package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giulianoo0/pintr/internal/runway"
	"github.com/giulianoo0/pintr/internal/store"
)

// runwayMP4Header is the start of a real Runway artifact: a 32-byte ftyp box
// with major brand "isom" and compatible brands including "mp41". /view relies
// on Go sniffing this as video/mp4 — if it didn't, generated videos would be
// served as application/octet-stream downloads instead of playing.
func runwayMP4Header() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x20, // box size 32
		'f', 't', 'y', 'p',
		'i', 's', 'o', 'm',
		0x00, 0x00, 0x02, 0x00, // minor version
		'i', 's', 'o', 'm',
		'i', 's', 'o', '2',
		'a', 'v', 'c', '1',
		'm', 'p', '4', '1',
	}
}

func TestRunwayVideoSniffsAsMP4(t *testing.T) {
	if got := http.DetectContentType(runwayMP4Header()); got != "video/mp4" {
		t.Fatalf("DetectContentType = %q, want video/mp4 — /view would not serve generated videos playable", got)
	}
}

func TestDashboardTemplateRunwayConnected(t *testing.T) {
	page := dashboardPage{
		Title: "pintr dashboard",
		CSRF:  "csrf-token",
		Email: "user@example.test",
		Runway: dashRunway{
			Connected: true,
			Username:  "someone",
			Email:     "someone@example.test",
			Plan:      "unlimited",
			Expires:   "2026-09-01",
			DaysLeft:  30,
			Models:    []string{"seedance_2", "gen4"},
		},
	}
	html := renderDashboard(t, page)
	for _, want := range []string{
		`id="p-runway"`,
		"someone",
		"token valid until 2026-09-01",
		"/runway/disconnect",
		"<code>seedance_2</code>",
		"replace the token",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("runway pane missing %q", want)
		}
	}
	// The stored token must never reach the page: the paste field is always
	// empty, and dashRunway carries no token to render in the first place.
	if !strings.Contains(html, `<input type="password" name="token" placeholder="RW_USER_TOKEN"`) {
		t.Error("the token field should be a blank password input")
	}
	if strings.Contains(html, `name="token" value=`) {
		t.Error("the token field must never be pre-filled")
	}
}

func TestDashboardTemplateRunwayNotConnected(t *testing.T) {
	html := renderDashboard(t, dashboardPage{
		Title:  "pintr dashboard",
		CSRF:   "csrf-token",
		Runway: dashRunway{Models: []string{"seedance_2"}},
	})
	for _, want := range []string{
		"no runway account connected",
		"connect runway",
		"/runway/connect",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("runway pane missing %q", want)
		}
	}
	if strings.Contains(html, "/runway/disconnect") {
		t.Error("disconnect offered with no account connected")
	}
}

func TestDashboardTemplateRunwayExpiredToken(t *testing.T) {
	html := renderDashboard(t, dashboardPage{
		CSRF: "csrf-token",
		Runway: dashRunway{
			Connected: true, Username: "someone", Plan: "unlimited",
			Expires: "2026-01-01", Expired: true,
		},
	})
	if !strings.Contains(html, "token expired on 2026-01-01") {
		t.Error("an expired token must be called out on the dashboard")
	}
}

// The token lifetime drives the dashboard warning, so the thresholds that
// produce it are worth pinning down.
func TestExpiryThresholds(t *testing.T) {
	for name, tc := range map[string]struct {
		in                    time.Duration
		wantSoon, wantExpired bool
	}{
		"fresh":   {in: 30 * 24 * time.Hour},
		"soon":    {in: 2 * 24 * time.Hour, wantSoon: true},
		"expired": {in: -time.Hour, wantExpired: true},
	} {
		expires := time.Now().Add(tc.in)
		left := time.Until(expires)
		expired := left <= 0
		soon := !expired && left < 5*24*time.Hour
		if expired != tc.wantExpired || soon != tc.wantSoon {
			t.Errorf("%s: expired=%t soon=%t", name, expired, soon)
		}
	}
}

// --- connect handler ---

// connectHarness wires real Handlers against a temp store and a stand-in
// Runway API, and returns a logged-in POST request builder.
type connectHarness struct {
	handlers *Handlers
	store    *store.Store
	userID   string
	cookie   string
	csrf     string
}

func newConnectHarness(t *testing.T, api http.HandlerFunc) *connectHarness {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "web.db"), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	server := httptest.NewServer(api)
	previous := runway.APIBase
	runway.APIBase = server.URL
	t.Cleanup(func() {
		runway.APIBase = previous
		server.Close()
	})

	u, err := st.CreateUser(context.Background(), "dev@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, err := st.CreateSession(context.Background(), u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session, ok := st.LookupSession(context.Background(), cookie)
	if !ok {
		t.Fatal("session lookup failed")
	}
	return &connectHarness{
		handlers: &Handlers{store: st},
		store:    st,
		userID:   u.ID,
		cookie:   cookie,
		csrf:     session.CSRF,
	}
}

func (h *connectHarness) connect(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/runway/connect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: h.cookie})
	rec := httptest.NewRecorder()
	h.handlers.handleRunwayConnect(rec, req)
	return rec
}

func okRunwayAPI(t *testing.T, gotToken *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gotToken != nil {
			*gotToken = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		switch r.URL.Path {
		case "/v1/profile":
			_, _ = w.Write([]byte(`{"user":{"id":58179174,"email":"me@example.test","username":"someone","plan":"unlimited"}}`))
		case "/v1/teams":
			_, _ = w.Write([]byte(`{"teams":[{"id":58179174,"username":"someone","teamName":"Someone"}]}`))
		default:
			t.Errorf("unexpected call to %s", r.URL.Path)
		}
	}
}

func TestRunwayConnectStoresValidatedToken(t *testing.T) {
	var seenToken string
	h := newConnectHarness(t, okRunwayAPI(t, &seenToken))

	// A JWT-shaped token with a real exp so the dashboard can show it.
	token := "eyJhbGciOiJIUzI1NiJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"id":58179174,"exp":1788220749}`)) + ".sig"

	rec := h.connect(t, url.Values{"csrf": {h.csrf}, "token": {token}})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d (%s), want 302", rec.Code, rec.Body.String())
	}
	if seenToken != token {
		t.Error("the pasted token was not used to validate against runway")
	}

	stored, account, err := h.store.LoadRunwayToken(context.Background(), h.userID)
	if err != nil {
		t.Fatal(err)
	}
	if stored != token {
		t.Errorf("stored token = %q", stored)
	}
	if account.TeamID != 58179174 || account.Username != "someone" || account.Plan != "unlimited" {
		t.Errorf("account = %+v", account)
	}
	if account.TokenExpires.Unix() != 1788220749 {
		t.Errorf("expiry not recorded: %v", account.TokenExpires)
	}
}

// People paste the whole "Bearer eyJ…" line out of devtools; that should work
// rather than be stored verbatim and fail at generation time.
func TestRunwayConnectStripsBearerPrefix(t *testing.T) {
	var seenToken string
	h := newConnectHarness(t, okRunwayAPI(t, &seenToken))
	token := "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig"

	if rec := h.connect(t, url.Values{"csrf": {h.csrf}, "token": {"Bearer " + token}}); rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if seenToken != token {
		t.Errorf("token sent to runway = %q, want the prefix stripped", seenToken)
	}
	stored, _, err := h.store.LoadRunwayToken(context.Background(), h.userID)
	if err != nil || stored != token {
		t.Errorf("stored = %q, err = %v", stored, err)
	}
}

// A token Runway rejects must never be stored, or generate_video would fail
// later with no clue why.
func TestRunwayConnectRejectsBadToken(t *testing.T) {
	h := newConnectHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	})

	rec := h.connect(t, url.Values{"csrf": {h.csrf}, "token": {"eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig"}})
	if rec.Code == http.StatusFound {
		t.Fatal("a token runway rejected was accepted")
	}
	if !strings.Contains(rec.Body.String(), "rejected that token") {
		t.Errorf("body should explain the rejection, got: %s", rec.Body.String())
	}
	if _, err := h.store.GetRunwayAccount(context.Background(), h.userID); !errors.Is(err, store.ErrNoRunwayAccount) {
		t.Error("a rejected token was stored anyway")
	}
}

func TestRunwayConnectRejectsMalformedInput(t *testing.T) {
	for name, token := range map[string]string{
		"empty":       "",
		"not a jwt":   "hunter2",
		"partial jwt": "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0",
	} {
		t.Run(name, func(t *testing.T) {
			h := newConnectHarness(t, func(http.ResponseWriter, *http.Request) {
				t.Error("a malformed token was sent to runway")
			})
			if rec := h.connect(t, url.Values{"csrf": {h.csrf}, "token": {token}}); rec.Code == http.StatusFound {
				t.Fatal("malformed token accepted")
			}
		})
	}
}

func TestRunwayConnectRequiresCSRF(t *testing.T) {
	h := newConnectHarness(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a request without a valid CSRF token reached runway")
	})
	rec := h.connect(t, url.Values{"csrf": {"wrong"}, "token": {"eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRunwayConnectRequiresSession(t *testing.T) {
	h := newConnectHarness(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an unauthenticated request reached runway")
	})
	req := httptest.NewRequest(http.MethodPost, "/runway/connect", strings.NewReader("token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.handlers.handleRunwayConnect(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status = %d → %q, want redirect to /login", rec.Code, rec.Header().Get("Location"))
	}
}

func renderDashboard(t *testing.T, page dashboardPage) string {
	t.Helper()
	var buf bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&buf, "dashboard", page); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	return buf.String()
}
