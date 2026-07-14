package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The Codex image-generation client: request building, account failover, and
// reference-image encoding. The SSE stream parser lives in sse.go.

const (
	codexResponsesURL = "https://chatgpt.com/backend-api/codex/responses"
	// Advertise a current Codex version; newer image models (gpt-5.6-terra)
	// 400 if the server thinks the client is too old.
	codexVersion      = "0.144.3"
	codexUserAgent    = "codex_cli_rs/" + codexVersion
	codexInstructions = "You are Codex. Follow the user request exactly."
	defaultImageModel = "gpt-5.6-terra"
)

// Codex rejects requests without the chatgpt.com session cookies, so we prime
// a cookie jar before posting (same trick crevn uses).
var cookiePrimeURLs = []string{"https://chatgpt.com/", "https://chat.openai.com/"}

// generateImageArgs is the MCP tool input. There is deliberately no model field
// (fixed server-side) and no output path (the client never chooses where the
// server writes) — delivery is decided by the server per mode. The
// reference_images description is mode-specific and set in generateImageTool
// (mcp.go); the tag below is only a fallback.
type generateImageArgs struct {
	Prompt          string   `json:"prompt" jsonschema:"the full image prompt to render"`
	ReferenceImages []string `json:"reference_images,omitempty" jsonschema:"optional reference images to anchor a character or style"`
}

type generateImageResult struct {
	AssetURL          string        `json:"asset_url,omitempty"`
	DecryptedAssetURL string        `json:"decrypted_asset_url,omitempty"`
	DecryptionKey     string        `json:"decryption_key,omitempty"`
	MimeType          string        `json:"mime_type,omitempty"`
	SavedPath         string        `json:"saved_path,omitempty"`
	Model             string        `json:"model"`
	Account           string        `json:"account"`
	DurationMs        int64         `json:"duration_ms"`
	SizeBytes         int           `json:"size_bytes,omitempty"`
	Usage             *accountUsage `json:"usage,omitempty"`
}

// generatedImage is the raw result of a generation, before delivery. The caller
// decides how to deliver it (an inline/temp file in stdio mode, or encrypt and
// upload in hosted mode).
type generatedImage struct {
	PNG        []byte
	Model      string
	Account    string
	DurationMs int64
	Usage      *accountUsage
}

// codexAuth is the minimal credential a single request needs.
type codexAuth struct {
	AccessToken string
	AccountID   string
	Fedramp     bool
}

func toCodexAuth(auth storedAuth) codexAuth {
	return codexAuth{AccessToken: auth.AccessToken, AccountID: auth.AccountID, Fedramp: auth.Fedramp}
}

// codexAccount is one linked ChatGPT account that can hand out a fresh access
// token and force a refresh after a 401. Both the local file store and the
// per-user DB rows implement it, so generateImage works the same in stdio and
// hosted modes.
type codexAccount interface {
	fresh(ctx context.Context) (codexAuth, error)
	forceRefresh(ctx context.Context) (codexAuth, error)
	label() string
	cacheKey() string // stable identity for the usage cache
}

func imageModel() string {
	if override := strings.TrimSpace(os.Getenv("PINTR_IMAGE_MODEL")); override != "" {
		return override
	}
	return defaultImageModel
}

func logImage(format string, args ...any) {
	log.Printf("[generate_image] "+format, args...)
}

type codexContent struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL string `json:"image_url,omitempty"`
}

type codexMessage struct {
	Type    string         `json:"type"`
	Role    string         `json:"role"`
	Content []codexContent `json:"content"`
}

type codexTool struct {
	Type string `json:"type"`
}

type codexRequest struct {
	Model        string         `json:"model"`
	Instructions string         `json:"instructions"`
	Input        []codexMessage `json:"input"`
	Tools        []codexTool    `json:"tools"`
	Stream       bool           `json:"stream"`
	Store        bool           `json:"store"`
}

// generateImage runs the generation and returns the PNG bytes. referenceDataURLs
// must already be resolved to data: URLs by the caller (so the hosted server can
// forbid file-path references and only accept inline attachments).
func generateImage(ctx context.Context, accounts []codexAccount, prompt string, referenceDataURLs []string) (generatedImage, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return generatedImage{}, errors.New("prompt is required")
	}
	if len(accounts) == 0 {
		return generatedImage{}, errors.New("no ChatGPT account linked — add one at pintr.giuli.dev")
	}
	model := imageModel()

	content := []codexContent{{Type: "input_text", Text: prompt}}
	for _, dataURL := range referenceDataURLs {
		content = append(content, codexContent{Type: "input_image", ImageURL: dataURL})
	}

	body, err := json.Marshal(codexRequest{
		Model:        model,
		Instructions: codexInstructions,
		Input: []codexMessage{{
			Type:    "message",
			Role:    "user",
			Content: content,
		}},
		Tools:  []codexTool{{Type: "image_generation"}},
		Stream: true,
		Store:  false,
	})
	if err != nil {
		return generatedImage{}, err
	}

	logImage("model=%s accounts=%d refs=%d prompt=%q", model, len(accounts), len(referenceDataURLs), truncate(prompt, 120))

	// Try each linked account in order (default first); fail over on error so
	// one rate-limited account doesn't block generation.
	var lastErr error
	for _, account := range accounts {
		png, durationMs, err := runOneGeneration(ctx, account, body)
		if err == nil {
			logImage("ok account=%s duration_ms=%d bytes=%d", account.label(), durationMs, len(png))
			img := generatedImage{PNG: png, Model: model, Account: account.label(), DurationMs: durationMs}
			// Best-effort: attach the account's remaining limits (cached, 30m).
			if usage, _, uerr := accountUsage30m(ctx, account, false); uerr == nil {
				img.Usage = &usage
			} else {
				logImage("usage fetch failed for %s: %v", account.label(), uerr)
			}
			return img, nil
		}
		lastErr = err
		logImage("account=%s failed: %v", account.label(), err)
	}
	return generatedImage{}, fmt.Errorf("all %d account(s) failed: %w", len(accounts), lastErr)
}

func runOneGeneration(ctx context.Context, account codexAccount, body []byte) ([]byte, int64, error) {
	startedAt := time.Now()

	auth, err := account.fresh(ctx)
	if err != nil {
		return nil, 0, err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, 0, err
	}
	client := &http.Client{Jar: jar}
	primeCookies(ctx, client)

	resp, err := postCodexResponses(ctx, client, auth, body)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if auth, err = account.forceRefresh(ctx); err != nil {
			return nil, 0, err
		}
		if resp, err = postCodexResponses(ctx, client, auth, body); err != nil {
			return nil, 0, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("codex request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	png, err := consumeImageStream(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return png, time.Since(startedAt).Milliseconds(), nil
}

// resolveReferences turns each caller-supplied reference into a data: URL for
// the Codex request. Used only in local stdio mode, where the server runs
// alongside the caller and reads its files straight off disk — so a reference is
// a local file PATH. Inline base64 / data: URLs are rejected on purpose (the
// hosted server takes uploaded ref_ handles instead; see resolveHostedReferences).
func resolveReferences(refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil, errors.New("empty reference image")
		}
		if isDataURL(ref) {
			return nil, errors.New("pass reference images as local file paths, not inline data: URLs — the local server reads them directly off disk")
		}
		dataURL, err := imageFileToDataURL(ref)
		if err != nil {
			return nil, fmt.Errorf("reference image %q: %w", truncate(ref, 64), err)
		}
		out = append(out, dataURL)
	}
	return out, nil
}

func postCodexResponses(ctx context.Context, client *http.Client, auth codexAuth, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexResponsesURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+auth.AccessToken)
	req.Header.Set("ChatGPT-Account-ID", auth.AccountID)
	req.Header.Set("originator", oauthOriginator)
	req.Header.Set("version", codexVersion)
	req.Header.Set("User-Agent", codexUserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	if auth.Fedramp {
		req.Header.Set("X-OpenAI-Fedramp", "true")
	}
	return client.Do(req)
}

func primeCookies(ctx context.Context, client *http.Client) {
	for _, primeURL := range cookiePrimeURLs {
		primeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req, err := http.NewRequestWithContext(primeCtx, http.MethodGet, primeURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("User-Agent", codexUserAgent)
		req.Header.Set("originator", oauthOriginator)
		req.Header.Set("version", codexVersion)

		// Best effort: cookies land in the jar; failures only matter if the
		// generation request itself fails later.
		if resp, err := client.Do(req); err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
		}
		cancel()
	}
}

func bytesToDataURL(b []byte) string {
	return "data:" + http.DetectContentType(b) + ";base64," + base64.StdEncoding.EncodeToString(b)
}

func imageFileToDataURL(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return "data:" + mimeTypeForImage(path) + ";base64," + base64.StdEncoding.EncodeToString(raw), nil
}

func mimeTypeForImage(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	default:
		return "image/png"
	}
}
