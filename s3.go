package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
	}
}

type storedAsset struct {
	URL    string // presigned GET of the ciphertext
	KeyB64 string // AES-256-GCM key, base64 (returned once, never stored)
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

	presigned, err := a.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &a.bucket,
		Key:    &objectKey,
	}, s3.WithPresignExpires(a.presignTTL))
	if err != nil {
		return storedAsset{}, err
	}
	return storedAsset{URL: presigned.URL, KeyB64: base64.StdEncoding.EncodeToString(key)}, nil
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

// deleteAll removes every object under the user's prefix.
func (a *assetStore) deleteAll(ctx context.Context, userID string) (int, error) {
	prefix := "assets/" + userID + "/"
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

func isDataURL(s string) bool { return strings.HasPrefix(s, "data:") }
