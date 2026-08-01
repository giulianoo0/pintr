// Package referenceupload issues authenticated, short-lived upload URLs for
// reference images and accepts each issued upload exactly once.
package referenceupload

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/random"
)

const (
	MaxBytes     int64 = 10 << 20
	UploadTTL          = 5 * time.Minute
	referenceTTL       = time.Hour
)

type Request struct {
	Filename  string `json:"filename"`
	MIMEType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
}

type Ticket struct {
	UploadURL    string `json:"upload_url"`
	UploadID     string `json:"upload_id"`
	ExpiresIn    int64  `json:"expires_in"`
	MaxSizeBytes int64  `json:"max_size_bytes"`
}

type uploadStore interface {
	PutUploadEncryptedWithID(context.Context, string, string, []byte) (string, error)
}

type Manager struct {
	secret    []byte
	publicURL string
	store     uploadStore
	now       func() time.Time
	onStored  func()
}

type claims struct {
	UploadID  string `json:"id"`
	UserID    string `json:"user_id"`
	Filename  string `json:"filename"`
	MIMEType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
	ExpiresAt int64  `json:"exp"`
}

func New(secret []byte, publicURL string, store uploadStore, onStored func()) *Manager {
	return newManager(secret, publicURL, store, onStored, time.Now)
}

func newManager(secret []byte, publicURL string, store uploadStore, onStored func(), now func() time.Time) *Manager {
	return &Manager{
		secret:    append([]byte(nil), secret...),
		publicURL: strings.TrimRight(publicURL, "/"),
		store:     store,
		now:       now,
		onStored:  onStored,
	}
}

func (m *Manager) Issue(userID string, req Request) (Ticket, error) {
	if !supportedMIME(req.MIMEType) {
		return Ticket{}, fmt.Errorf("unsupported reference image MIME type %q", req.MIMEType)
	}
	if req.SizeBytes <= 0 || req.SizeBytes > MaxBytes {
		return Ticket{}, fmt.Errorf("reference image size must be between 1 and %d bytes", MaxBytes)
	}

	id, err := random.Token(18)
	if err != nil {
		return Ticket{}, err
	}
	payload, err := json.Marshal(claims{
		UploadID:  id,
		UserID:    userID,
		Filename:  req.Filename,
		MIMEType:  req.MIMEType,
		SizeBytes: req.SizeBytes,
		ExpiresAt: m.now().Add(UploadTTL).Unix(),
	})
	if err != nil {
		return Ticket{}, err
	}
	payloadText := base64.RawURLEncoding.EncodeToString(payload)
	token := payloadText + "." + base64.RawURLEncoding.EncodeToString(m.sign(payloadText))
	return Ticket{
		UploadURL:    m.publicURL + "/reference-upload/" + token,
		UploadID:     id,
		ExpiresIn:    int64(UploadTTL / time.Second),
		MaxSizeBytes: MaxBytes,
	}, nil
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claim, status := m.verify(strings.TrimPrefix(r.URL.Path, "/reference-upload/"))
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBytes))
	if err != nil {
		http.Error(w, "invalid upload body", http.StatusBadRequest)
		return
	}
	if int64(len(body)) != claim.SizeBytes {
		http.Error(w, "upload size does not match ticket", http.StatusBadRequest)
		return
	}
	if http.DetectContentType(body) != claim.MIMEType {
		http.Error(w, "upload MIME type does not match ticket", http.StatusBadRequest)
		return
	}

	ref, err := m.store.PutUploadEncryptedWithID(r.Context(), claim.UserID, claim.UploadID, body)
	if err != nil {
		if errors.Is(err, assets.ErrUploadExists) {
			http.Error(w, "upload ticket already used", http.StatusConflict)
			return
		}
		http.Error(w, "could not store upload", http.StatusInternalServerError)
		return
	}
	if m.onStored != nil {
		m.onStored()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(struct {
		Ref       string `json:"ref"`
		ExpiresIn int64  `json:"expires_in"`
	}{Ref: ref, ExpiresIn: int64(referenceTTL / time.Second)})
}

func (m *Manager) verify(token string) (claims, int) {
	payloadText, signatureText, ok := strings.Cut(token, ".")
	if !ok || payloadText == "" || signatureText == "" || strings.Contains(signatureText, ".") {
		return claims{}, http.StatusUnauthorized
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	if err != nil || !hmac.Equal(signature, m.sign(payloadText)) {
		return claims{}, http.StatusUnauthorized
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		return claims{}, http.StatusUnauthorized
	}
	var claim claims
	if err := json.Unmarshal(payload, &claim); err != nil {
		return claims{}, http.StatusUnauthorized
	}
	if m.now().Unix() >= claim.ExpiresAt {
		return claims{}, http.StatusGone
	}
	if claim.UploadID == "" || claim.UserID == "" || !supportedMIME(claim.MIMEType) || claim.SizeBytes <= 0 || claim.SizeBytes > MaxBytes {
		return claims{}, http.StatusUnauthorized
	}
	return claim, 0
}

func (m *Manager) sign(payload string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = io.WriteString(mac, payload)
	return mac.Sum(nil)
}

func supportedMIME(mimeType string) bool {
	switch mimeType {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
		return true
	default:
		return false
	}
}
