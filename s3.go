package main

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
)

// assetStore keeps generated images in an S3-compatible bucket (Cloudflare R2)
// encrypted at rest. Each image gets a fresh random AES-256-GCM key that is
// returned to the caller once and never stored — so the bucket (and pintr
// itself) only ever hold ciphertext, and nobody but the caller can decrypt.
type assetStore struct {
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

// newAssetStore builds the store from PINTR_S3_* env vars. It returns (nil, nil)
// when storage isn't configured, so the server can still run (generation just
// reports that storage is unconfigured).
func newAssetStore() *assetStore {
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
	return &assetStore{
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

type storedAsset struct {
	URL       string // presigned GET of the ciphertext
	ObjectKey string // storage key, e.g. assets/<userID>/<id>
	KeyB64    string // AES-256-GCM key, base64 (returned once, never stored)
}

// putEncrypted encrypts png under a fresh key, uploads the ciphertext, and
// returns a presigned download URL plus the key.
func (a *assetStore) putEncrypted(ctx context.Context, userID string, png []byte) (storedAsset, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return storedAsset{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return storedAsset{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return storedAsset{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return storedAsset{}, err
	}
	// Blob layout: nonce || ciphertext(+tag). The decryptor reads the first
	// NonceSize bytes as the nonce.
	blob := gcm.Seal(nonce, nonce, png, nil)

	id, err := randomToken(24)
	if err != nil {
		return storedAsset{}, err
	}
	objectKey := "assets/" + userID + "/" + id

	if _, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &a.bucket,
		Key:         &objectKey,
		Body:        bytes.NewReader(blob),
		ContentType: aws.String("application/octet-stream"),
	}); err != nil {
		return storedAsset{}, err
	}

	downloadURL, err := a.presignGet(ctx, objectKey)
	if err != nil {
		return storedAsset{}, err
	}
	return storedAsset{URL: downloadURL, ObjectKey: objectKey, KeyB64: base64.StdEncoding.EncodeToString(key)}, nil
}

// fetchAndDecrypt downloads a stored object and decrypts it with the given key
// (server-side, so callers only need to open a url). It never stores the key.
func (a *assetStore) fetchAndDecrypt(ctx context.Context, objectKey, keyB64 string) ([]byte, error) {
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

// presignGet returns a presigned download URL — on the public custom domain when
// configured, otherwise on the S3 API endpoint via the SDK.
func (a *assetStore) presignGet(ctx context.Context, objectKey string) (string, error) {
	if a.publicHost != "" {
		return presignGetURL(a.publicHost, a.accessKey, a.secretKey, a.region, objectKey, a.presignTTL, time.Now()), nil
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

// uploadTTL is how long an uploaded reference image is kept before the janitor
// deletes it. Uploads used to be one-shot (deleted on first fetch, before the
// generation even ran), which broke agent retries after a client timeout and
// multi-image runs that reuse the same reference handle.
const uploadTTL = time.Hour

// putUploadEncrypted encrypts an uploaded reference image under a fresh key,
// stores only the ciphertext, and returns a short opaque handle that carries
// the id and key (so no key is stored server-side). The upload stays reusable
// until the janitor expires it after uploadTTL (see sweepExpiredUploads).
func (a *assetStore) putUploadEncrypted(ctx context.Context, userID string, img []byte) (string, error) {
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

	id, err := randomToken(18)
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

// fetchUpload downloads and decrypts an uploaded reference. The object is left
// in place so the same handle keeps working across retries and multiple
// generations; expiry is the janitor's job (uploadTTL).
func (a *assetStore) fetchUpload(ctx context.Context, userID, handle string) ([]byte, error) {
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

// startUploadJanitor sweeps expired reference uploads in the background so a
// forgotten handle doesn't keep ciphertext around forever.
func (a *assetStore) startUploadJanitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			if n, err := a.sweepExpiredUploads(ctx); err != nil {
				log.Printf("upload janitor: %v", err)
			} else if n > 0 {
				log.Printf("upload janitor: deleted %d expired upload(s)", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// sweepExpiredUploads deletes every reference upload older than uploadTTL,
// across all users, and returns how many it removed.
func (a *assetStore) sweepExpiredUploads(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-uploadTTL)
	prefix := "uploads/"
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

// countAssets counts a user's stored objects (for the dashboard).
func (a *assetStore) countAssets(ctx context.Context, userID string) (int, error) {
	prefix := "assets/" + userID + "/"
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

// deleteAll removes every object owned by the user — both generated images and
// any lingering uploads.
func (a *assetStore) deleteAll(ctx context.Context, userID string) (int, error) {
	deleted := 0
	for _, prefix := range []string{"assets/" + userID + "/", "uploads/" + userID + "/"} {
		n, err := a.deletePrefix(ctx, prefix)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

func (a *assetStore) deletePrefix(ctx context.Context, prefix string) (int, error) {
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
