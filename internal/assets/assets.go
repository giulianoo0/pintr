// Package assets keeps generated images and reference uploads in an
// S3-compatible bucket (Cloudflare R2), encrypted at rest. Each object gets a
// fresh random AES-256-GCM key that is returned to the caller once and never
// stored — so the bucket (and pintr itself) only ever hold ciphertext, and
// nobody but the caller can decrypt.
package assets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/giulianoo0/pintr/internal/random"
)

// Retention: the janitor permanently deletes objects from the bucket once
// they expire — nothing is kept after these windows.
//
// uploadTTL is how long an uploaded reference image is kept. Uploads used to
// be one-shot (deleted on first fetch, before the generation even ran), which
// broke agent retries after a client timeout and multi-image runs that reuse
// the same reference handle.
//
// assetTTL is how long a generated image is kept. It matches presignTTL: once
// the presigned download URL dies, the ciphertext has no reachable consumer,
// so keeping it would only accumulate undeletable-by-anyone data.
const (
	uploadTTL = time.Hour
	assetTTL  = 24 * time.Hour
)

type Store struct {
	client     *s3.Client
	presign    *s3.PresignClient
	bucket     string
	presignTTL time.Duration

	// When publicHost is set (PINTR_S3_PUBLIC_BASE, e.g. an R2 custom domain
	// bound to the bucket), download URLs are presigned for that host with the
	// object key as the path (no bucket prefix). These creds are kept for that
	// hand-rolled signing.
	publicHost string
	accessKey  string
	secretKey  string
	region     string
}

// New builds the store from PINTR_S3_* env vars. It returns nil when storage
// isn't configured, so the server can still run (generation just reports that
// storage is unconfigured).
func New() *Store {
	endpoint := os.Getenv("PINTR_S3_ENDPOINT")
	bucket := os.Getenv("PINTR_S3_BUCKET")
	keyID := os.Getenv("PINTR_S3_ACCESS_KEY_ID")
	secret := os.Getenv("PINTR_S3_SECRET_ACCESS_KEY")
	if endpoint == "" || bucket == "" || keyID == "" || secret == "" {
		return nil
	}
	region := os.Getenv("PINTR_S3_REGION")
	if region == "" {
		region = "auto" // R2 default
	}

	client := s3.New(s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider(keyID, secret, ""),
		UsePathStyle: true,
	})
	return &Store{
		client:     client,
		presign:    s3.NewPresignClient(client),
		bucket:     bucket,
		presignTTL: 24 * time.Hour,
		publicHost: hostOnly(os.Getenv("PINTR_S3_PUBLIC_BASE")),
		accessKey:  keyID,
		secretKey:  secret,
		region:     region,
	}
}

// hostOnly strips scheme and trailing slash so "https://pintr-assets.giuli.dev/"
// becomes "pintr-assets.giuli.dev".
func hostOnly(base string) string {
	base = strings.TrimSpace(base)
	base = strings.TrimPrefix(base, "https://")
	base = strings.TrimPrefix(base, "http://")
	return strings.TrimRight(base, "/")
}

// Stored describes one uploaded ciphertext.
type Stored struct {
	URL       string // presigned GET of the ciphertext
	ObjectKey string // storage key, e.g. assets/<userID>/<id>
	KeyB64    string // AES-256-GCM key, base64 (returned once, never stored)
}

// PutEncrypted encrypts png under a fresh key, uploads the ciphertext, and
// returns a presigned download URL plus the key.
func (a *Store) PutEncrypted(ctx context.Context, userID string, png []byte) (Stored, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Stored{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Stored{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Stored{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Stored{}, err
	}
	// Blob layout: nonce || ciphertext(+tag). The decryptor reads the first
	// NonceSize bytes as the nonce.
	blob := gcm.Seal(nonce, nonce, png, nil)

	id, err := random.Token(24)
	if err != nil {
		return Stored{}, err
	}
	objectKey := "assets/" + userID + "/" + id

	if _, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &a.bucket,
		Key:         &objectKey,
		Body:        bytes.NewReader(blob),
		ContentType: aws.String("application/octet-stream"),
	}); err != nil {
		return Stored{}, err
	}

	downloadURL, err := a.presignGet(ctx, objectKey)
	if err != nil {
		return Stored{}, err
	}
	return Stored{URL: downloadURL, ObjectKey: objectKey, KeyB64: base64.StdEncoding.EncodeToString(key)}, nil
}

// FetchAndDecrypt downloads a stored object and decrypts it with the given
// key (server-side, so callers only need to open a url). It never stores the
// key.
func (a *Store) FetchAndDecrypt(ctx context.Context, objectKey, keyB64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid key")
	}
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &a.bucket, Key: &objectKey})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	blob, err := io.ReadAll(io.LimitReader(out.Body, 64<<20)) // 64 MiB cap
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// presignGet returns a presigned download URL — on the public custom domain
// when configured, otherwise on the S3 API endpoint via the SDK.
func (a *Store) presignGet(ctx context.Context, objectKey string) (string, error) {
	if a.publicHost != "" {
		return presignURL(a.publicHost, a.accessKey, a.secretKey, a.region, objectKey, a.presignTTL, time.Now()), nil
	}
	presigned, err := a.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &a.bucket,
		Key:    &objectKey,
	}, s3.WithPresignExpires(a.presignTTL))
	if err != nil {
		return "", err
	}
	return presigned.URL, nil
}

// PutUploadEncrypted encrypts an uploaded reference image under a fresh key,
// stores only the ciphertext, and returns a short opaque handle that carries
// the id and key (so no key is stored server-side). The upload stays reusable
// until the janitor expires it after uploadTTL.
func (a *Store) PutUploadEncrypted(ctx context.Context, userID string, img []byte) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	blob := gcm.Seal(nonce, nonce, img, nil)

	id, err := random.Token(18)
	if err != nil {
		return "", err
	}
	objectKey := "uploads/" + userID + "/" + id
	if _, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &a.bucket,
		Key:         &objectKey,
		Body:        bytes.NewReader(blob),
		ContentType: aws.String("application/octet-stream"),
	}); err != nil {
		return "", err
	}
	// handle = ref_<id>.<key>; the key never touches the server's storage.
	return "ref_" + id + "." + base64.RawURLEncoding.EncodeToString(key), nil
}

// FetchUpload downloads and decrypts an uploaded reference. The object is
// left in place so the same handle keeps working across retries and multiple
// generations; expiry is the janitor's job (uploadTTL).
func (a *Store) FetchUpload(ctx context.Context, userID, handle string) ([]byte, error) {
	rest := strings.TrimPrefix(handle, "ref_")
	id, keyEnc, ok := strings.Cut(rest, ".")
	if !ok || id == "" {
		return nil, errors.New("bad reference handle")
	}
	key, err := base64.RawURLEncoding.DecodeString(keyEnc)
	if err != nil || len(key) != 32 {
		return nil, errors.New("bad reference key")
	}
	objectKey := "uploads/" + userID + "/" + id

	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &a.bucket, Key: &objectKey})
	if err != nil {
		return nil, err
	}
	blob, readErr := io.ReadAll(io.LimitReader(out.Body, 64<<20))
	out.Body.Close()
	if readErr != nil {
		return nil, readErr
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("upload too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// StartJanitor sweeps expired objects in the background: reference uploads
// after uploadTTL, generated images after assetTTL. Expiry is a real
// DeleteObjects against the bucket — the ciphertext is gone from R2, not just
// unreachable.
func (a *Store) StartJanitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			for _, sweep := range []struct {
				prefix string
				ttl    time.Duration
			}{
				{"uploads/", uploadTTL},
				{"assets/", assetTTL},
			} {
				if n, err := a.sweepExpired(ctx, sweep.prefix, sweep.ttl); err != nil {
					log.Printf("janitor %s: %v", sweep.prefix, err)
				} else if n > 0 {
					log.Printf("janitor: deleted %d expired object(s) under %s", n, sweep.prefix)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// sweepExpired deletes every object under prefix older than ttl, across all
// users, and returns how many it removed.
func (a *Store) sweepExpired(ctx context.Context, prefix string, ttl time.Duration) (int, error) {
	cutoff := time.Now().Add(-ttl)
	deleted := 0
	paginator := s3.NewListObjectsV2Paginator(a.client, &s3.ListObjectsV2Input{Bucket: &a.bucket, Prefix: &prefix})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return deleted, err
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, obj := range page.Contents {
			if obj.LastModified != nil && obj.LastModified.Before(cutoff) {
				ids = append(ids, types.ObjectIdentifier{Key: obj.Key})
			}
		}
		if len(ids) == 0 {
			continue
		}
		if _, err := a.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &a.bucket,
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		}); err != nil {
			return deleted, err
		}
		deleted += len(ids)
	}
	return deleted, nil
}

// countPrefix counts a user's stored objects under one prefix (dashboard).
func (a *Store) countPrefix(ctx context.Context, prefix string) (int, error) {
	count := 0
	paginator := s3.NewListObjectsV2Paginator(a.client, &s3.ListObjectsV2Input{Bucket: &a.bucket, Prefix: &prefix})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return count, err
		}
		count += len(page.Contents)
	}
	return count, nil
}

func (a *Store) CountAssets(ctx context.Context, userID string) (int, error) {
	return a.countPrefix(ctx, "assets/"+userID+"/")
}

func (a *Store) CountUploads(ctx context.Context, userID string) (int, error) {
	return a.countPrefix(ctx, "uploads/"+userID+"/")
}

// DeleteAssets removes a user's generated images; DeleteUploads their
// reference uploads; DeleteAll both.
func (a *Store) DeleteAssets(ctx context.Context, userID string) (int, error) {
	return a.deletePrefix(ctx, "assets/"+userID+"/")
}

func (a *Store) DeleteUploads(ctx context.Context, userID string) (int, error) {
	return a.deletePrefix(ctx, "uploads/"+userID+"/")
}

func (a *Store) DeleteAll(ctx context.Context, userID string) (int, error) {
	deleted, err := a.DeleteAssets(ctx, userID)
	if err != nil {
		return deleted, err
	}
	n, err := a.DeleteUploads(ctx, userID)
	return deleted + n, err
}

func (a *Store) deletePrefix(ctx context.Context, prefix string) (int, error) {
	deleted := 0
	paginator := s3.NewListObjectsV2Paginator(a.client, &s3.ListObjectsV2Input{Bucket: &a.bucket, Prefix: &prefix})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return deleted, err
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, obj := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: obj.Key})
		}
		if len(ids) == 0 {
			continue
		}
		if _, err := a.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: &a.bucket,
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		}); err != nil {
			return deleted, err
		}
		deleted += len(ids)
	}
	return deleted, nil
}
