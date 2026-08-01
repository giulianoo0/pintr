package referenceupload

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/giulianoo0/pintr/internal/assets"
)

var testPNG = []byte("\x89PNG\r\n\x1a\nvalid-enough-for-sniffing")

type fakeStore struct {
	seen   map[string]bool
	calls  int
	stored []byte
}

func (s *fakeStore) PutUploadEncryptedWithID(_ context.Context, userID, id string, body []byte) (string, error) {
	s.calls++
	key := userID + "/" + id
	if s.seen[key] {
		return "", assets.ErrUploadExists
	}
	s.seen[key] = true
	s.stored = append([]byte(nil), body...)
	return "ref_" + id + ".test-key", nil
}

func newTestManager(secret []byte, publicURL string, store uploadStore, now func() time.Time) *Manager {
	return newManager(secret, publicURL, store, nil, now)
}

func issuePNG(t *testing.T, m *Manager) Ticket {
	t.Helper()
	ticket, err := m.Issue("user-1", Request{
		Filename:  "ref.png",
		MIMEType:  "image/png",
		SizeBytes: int64(len(testPNG)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func put(t *testing.T, m *Manager, uploadURL string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(body))
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	return w
}

func TestIssueAndUpload(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	stored := 0
	m := newManager(
		[]byte("01234567890123456789012345678901"),
		"https://pintr.example/",
		store,
		func() { stored++ },
		func() time.Time { return now },
	)

	ticket := issuePNG(t, m)
	if ticket.UploadID == "" {
		t.Fatal("empty upload id")
	}
	if !strings.HasPrefix(ticket.UploadURL, "https://pintr.example/reference-upload/") {
		t.Fatal("upload URL does not use the configured public reference-upload path")
	}
	if ticket.ExpiresIn != 300 {
		t.Fatalf("expires_in = %d, want 300", ticket.ExpiresIn)
	}
	if ticket.MaxSizeBytes != 10<<20 {
		t.Fatalf("max_size_bytes = %d, want %d", ticket.MaxSizeBytes, 10<<20)
	}

	w := put(t, m, ticket.UploadURL, testPNG)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if !bytes.Equal(store.stored, testPNG) {
		t.Fatal("stored body differs from uploaded image")
	}
	if stored != 1 {
		t.Fatalf("onStored calls = %d, want 1", stored)
	}

	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 2 {
		t.Fatalf("response has %d keys, want only ref and expires_in", len(response))
	}
	if response["ref"] != "ref_"+ticket.UploadID+".test-key" {
		t.Fatal("response ref does not match the stored handle")
	}
	if response["expires_in"] != float64(3600) {
		t.Fatalf("expires_in = %v, want 3600", response["expires_in"])
	}
	if strings.Contains(w.Body.String(), "user-1") {
		t.Fatal("response leaked user id")
	}
}

func TestTamperedTicketReturnsUnauthorizedWithoutStoring(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
	ticket := issuePNG(t, m)

	const uploadPath = "/reference-upload/"
	tokenStart := strings.Index(ticket.UploadURL, uploadPath) + len(uploadPath)
	tampered := ticket.UploadURL[:tokenStart] + "A" + ticket.UploadURL[tokenStart+1:]
	w := put(t, m, tampered, testPNG)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0", store.calls)
	}
}

func TestTamperedFinalSignatureCharacterReturnsUnauthorizedWithoutStoring(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
	ticket := issuePNG(t, m)

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := ticket.UploadURL[len(ticket.UploadURL)-1]
	index := strings.IndexByte(alphabet, last)
	if index < 0 || index%4 != 0 || index == len(alphabet)-1 {
		t.Fatalf("unexpected canonical final signature character index %d", index)
	}
	tampered := ticket.UploadURL[:len(ticket.UploadURL)-1] + string(alphabet[index+1])
	w := put(t, m, tampered, testPNG)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0", store.calls)
	}
}

func TestExpiredTicketReturnsGoneWithoutStoring(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
	ticket := issuePNG(t, m)
	now = now.Add(UploadTTL)

	w := put(t, m, ticket.UploadURL, testPNG)

	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", w.Code)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0", store.calls)
	}
}

func TestNonPUTReturnsMethodNotAllowed(t *testing.T) {
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", &fakeStore{seen: map[string]bool{}}, time.Now)
	req := httptest.NewRequest(http.MethodPost, "/reference-upload/anything", nil)
	w := httptest.NewRecorder()

	m.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestIssueRejectsInvalidRequest(t *testing.T) {
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", &fakeStore{seen: map[string]bool{}}, time.Now)
	tests := []struct {
		name string
		req  Request
	}{
		{name: "unsupported MIME", req: Request{Filename: "ref.bmp", MIMEType: "image/bmp", SizeBytes: 10}},
		{name: "zero size", req: Request{Filename: "ref.png", MIMEType: "image/png", SizeBytes: 0}},
		{name: "negative size", req: Request{Filename: "ref.png", MIMEType: "image/png", SizeBytes: -1}},
		{name: "over maximum", req: Request{Filename: "ref.png", MIMEType: "image/png", SizeBytes: (10 << 20) + 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := m.Issue("user-1", tt.req); err == nil {
				t.Fatal("Issue returned nil error")
			}
		})
	}
}

func TestIssueAcceptsSupportedMIMEsAtMaximumSize(t *testing.T) {
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", &fakeStore{seen: map[string]bool{}}, time.Now)
	for _, mimeType := range []string{"image/png", "image/jpeg", "image/webp", "image/gif"} {
		t.Run(mimeType, func(t *testing.T) {
			if _, err := m.Issue("user-1", Request{Filename: "ref", MIMEType: mimeType, SizeBytes: MaxBytes}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUploadRejectsBodyWithDifferentSize(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "shorter", body: testPNG[:len(testPNG)-1]},
		{name: "longer", body: append(append([]byte(nil), testPNG...), 'x')},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStore{seen: map[string]bool{}}
			m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
			w := put(t, m, issuePNG(t, m).UploadURL, tt.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if store.calls != 0 {
				t.Fatalf("store calls = %d, want 0", store.calls)
			}
		})
	}
}

func TestUploadRejectsMIMEThatDiffersFromClaim(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
	body := []byte("plain text with the same byte count!")
	ticket, err := m.Issue("user-1", Request{Filename: "ref.png", MIMEType: "image/png", SizeBytes: int64(len(body))})
	if err != nil {
		t.Fatal(err)
	}

	w := put(t, m, ticket.UploadURL, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if store.calls != 0 {
		t.Fatalf("store calls = %d, want 0", store.calls)
	}
}

func TestUploadTicketIsSingleUse(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	stored := 0
	m := newManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() { stored++ }, func() time.Time { return now })
	ticket := issuePNG(t, m)
	if w := put(t, m, ticket.UploadURL, testPNG); w.Code != http.StatusCreated {
		t.Fatalf("first status = %d", w.Code)
	}

	w := put(t, m, ticket.UploadURL, testPNG)

	if w.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", w.Code)
	}
	if stored != 1 {
		t.Fatalf("onStored calls = %d, want 1", stored)
	}
}
