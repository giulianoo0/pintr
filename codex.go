package main

import (
	"bufio"
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
// server writes) — delivery is decided by the server per mode.
type generateImageArgs struct {
	Prompt          string   `json:"prompt" jsonschema:"the full image prompt to render"`
	ReferenceImages []string `json:"reference_images,omitempty" jsonschema:"optional reference images to anchor a character or style. In local (stdio) mode pass file paths and pintr reads them. On the hosted server pass the image content itself (a data: URL or base64) — as the agent, read the user's local image file yourself and pass its bytes, since a remote server cannot read files off the user's machine. References are sent to Codex for this one request and never stored."`
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
			// Best-effort: attach the account's remaining limits to the result.
			if usage, uerr := fetchAccountUsage(ctx, account); uerr == nil {
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

// resolveReferences turns caller-provided references into data: URLs. When
// allowFiles is false (hosted server) only base64 / data: URLs are accepted —
// never a filesystem path, so a caller can't make the server read arbitrary
// files.
func resolveReferences(refs []string, allowFiles bool) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		dataURL, err := resolveReference(ref, allowFiles)
		if err != nil {
			return nil, err
		}
		out = append(out, dataURL)
	}
	return out, nil
}

func resolveReference(ref string, allowFiles bool) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("empty reference image")
	}
	if isDataURL(ref) {
		return ref, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(ref); err == nil && len(raw) > 0 {
		if mime := http.DetectContentType(raw); strings.HasPrefix(mime, "image/") {
			return "data:" + mime + ";base64," + ref, nil
		}
	}
	if allowFiles {
		return imageFileToDataURL(ref)
	}
	return "", errors.New("reference image looks like a file path — this is a remote server and can't read your local files; read the image and pass its bytes (a data: URL or base64) instead")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
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

// consumeImageStream reads the Codex SSE stream and returns the latest (finally
// the complete) image bytes. Partial images overwrite earlier ones, so the last
// one is the finished render.
func consumeImageStream(body io.Reader) ([]byte, error) {
	reader := bufio.NewReader(body)

	var event string
	var data strings.Builder
	var latest []byte
	failure := ""

	dispatch := func() error {
		defer func() {
			event = ""
			data.Reset()
		}()
		if data.Len() == 0 && event == "" {
			return nil
		}

		switch event {
		case "response.image_generation_call.partial_image":
			var payload struct {
				PartialImageB64 string `json:"partial_image_b64"`
			}
			if err := json.Unmarshal([]byte(data.String()), &payload); err != nil || payload.PartialImageB64 == "" {
				return nil
			}
			imageBytes, err := base64.StdEncoding.DecodeString(payload.PartialImageB64)
			if err != nil {
				return fmt.Errorf("decoding partial image: %w", err)
			}
			latest = imageBytes
		case "response.failed", "error":
			failure = extractSSEError(data.String())
		}
		return nil
	}

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if err := dispatch(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}

		if readErr != nil {
			if dispatchErr := dispatch(); dispatchErr != nil {
				return nil, dispatchErr
			}
			if readErr != io.EOF {
				return nil, readErr
			}
			break
		}
	}

	if latest == nil {
		if failure != "" {
			return nil, fmt.Errorf("codex failed: %s", failure)
		}
		return nil, errors.New("codex finished without returning image bytes")
	}
	return latest, nil
}

func extractSSEError(raw string) string {
	var payload struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err == nil {
		if payload.Error.Message != "" {
			return payload.Error.Message
		}
		if payload.Message != "" {
			return payload.Message
		}
	}
	if trimmed := strings.TrimSpace(raw); trimmed != "" {
		return trimmed
	}
	return "unknown codex failure"
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
