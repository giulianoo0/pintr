package assets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func testUploadStore(serverURL string) *Store {
	client := s3.New(s3.Options{
		Region:       "auto",
		BaseEndpoint: aws.String(serverURL),
		Credentials:  credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
		UsePathStyle: true,
	})
	return &Store{client: client, bucket: "test-bucket"}
}

func TestPutUploadEncryptedWithIDUsesConditionalEncryptedWrite(t *testing.T) {
	plaintext := []byte("reference image bytes")
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		if r.URL.Path != "/test-bucket/uploads/user-1/upload-1" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("If-None-Match"); got != "*" {
			t.Errorf("If-None-Match = %q, want *", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q", got)
		}
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handle, err := testUploadStore(server.URL).PutUploadEncryptedWithID(context.Background(), "user-1", "upload-1", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(handle, "ref_upload-1.") {
		t.Fatal("handle does not preserve the ref_<id> prefix")
	}
	keyText := strings.TrimPrefix(handle, "ref_upload-1.")
	key, err := base64.RawURLEncoding.DecodeString(keyText)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotBody) < gcm.NonceSize() {
		t.Fatalf("encrypted body is only %d bytes", len(gotBody))
	}
	decrypted, err := gcm.Open(nil, gotBody[:gcm.NonceSize()], gotBody[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("decrypted body differs from uploaded image")
	}
}

func TestPutUploadEncryptedWithIDTranslatesConditionalWriteErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		code       string
	}{
		{name: "precondition failed", statusCode: http.StatusPreconditionFailed, code: "PreconditionFailed"},
		{name: "conditional request conflict", statusCode: http.StatusConflict, code: "ConditionalRequestConflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, "<Error><Code>"+tt.code+"</Code><Message>already exists</Message></Error>")
			}))
			defer server.Close()

			_, err := testUploadStore(server.URL).PutUploadEncryptedWithID(context.Background(), "user-1", "upload-1", []byte("image"))
			if !errors.Is(err, ErrUploadExists) {
				t.Fatalf("error = %v, want ErrUploadExists", err)
			}
		})
	}
}
