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
	codexVersion   = "0.144.3"
	codexUserAgent = "codex_cli_rs/" + codexVersion
	codexInstructions = "You are Codex. Follow the user request exactly."
	defaultImageModel = "gpt-5.6-terra"
)

// Codex rejects requests without the chatgpt.com session cookies, so we prime
// a cookie jar before posting (same trick crevn uses).
var cookiePrimeURLs = []string{"https://chatgpt.com/", "https://chat.openai.com/"}

// generateImageArgs is the MCP tool input. There is deliberately no model
// field: the driver model is fixed server-side (gpt-5.6-terra) so callers can't
// pass a hallucinated model id.
type generateImageArgs struct {
	Prompt          string   `json:"prompt" jsonschema:"the full image prompt to render"`
	OutputPath      string   `json:"output_path" jsonschema:"absolute path where the generated PNG will be saved"`
	ReferenceImages []string `json:"reference_images,omitempty" jsonschema:"optional file paths of reference images to send with the prompt"`
}

type generateImageResult struct {
	SavedPath  string `json:"saved_path"`
	Model      string `json:"model"`
	Account    string `json:"account"`
	DurationMs int64  `json:"duration_ms"`
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

func generateImage(ctx context.Context, accounts []codexAccount, args generateImageArgs) (generateImageResult, error) {
	prompt := strings.TrimSpace(args.Prompt)
	if prompt == "" {
		return generateImageResult{}, errors.New("prompt is required")
	}
	outputPath := strings.TrimSpace(args.OutputPath)
	if outputPath == "" {
		return generateImageResult{}, errors.New("output_path is required")
	}
	if len(accounts) == 0 {
		return generateImageResult{}, errors.New("no ChatGPT account linked — add one at pintr.giuli.dev")
	}
	model := imageModel()

	content := []codexContent{{Type: "input_text", Text: prompt}}
	for _, referencePath := range args.ReferenceImages {
		dataURL, err := imageFileToDataURL(referencePath)
		if err != nil {
			return generateImageResult{}, fmt.Errorf("reference image %q: %w", referencePath, err)
		}
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
		return generateImageResult{}, err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return generateImageResult{}, err
	}

	logImage("model=%s accounts=%d refs=%d prompt=%q", model, len(accounts), len(args.ReferenceImages), truncate(prompt, 120))

	// Try each linked account in order (default first); fail over on error so
	// one rate-limited account doesn't block generation.
	var lastErr error
	for _, account := range accounts {
		result, err := runOneGeneration(ctx, account, model, body, outputPath)
		if err == nil {
			logImage("ok account=%s duration_ms=%d saved=%s", account.label(), result.DurationMs, outputPath)
			return result, nil
		}
		lastErr = err
		logImage("account=%s failed: %v", account.label(), err)
	}
	return generateImageResult{}, fmt.Errorf("all %d account(s) failed: %w", len(accounts), lastErr)
}

func runOneGeneration(ctx context.Context, account codexAccount, model string, body []byte, outputPath string) (generateImageResult, error) {
	startedAt := time.Now()

	auth, err := account.fresh(ctx)
	if err != nil {
		return generateImageResult{}, err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return generateImageResult{}, err
	}
	client := &http.Client{Jar: jar}
	primeCookies(ctx, client)

	resp, err := postCodexResponses(ctx, client, auth, body)
	if err != nil {
		return generateImageResult{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if auth, err = account.forceRefresh(ctx); err != nil {
			return generateImageResult{}, err
		}
		if resp, err = postCodexResponses(ctx, client, auth, body); err != nil {
			return generateImageResult{}, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return generateImageResult{}, fmt.Errorf("codex request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	if err := consumeImageStream(resp.Body, outputPath); err != nil {
		return generateImageResult{}, err
	}

	return generateImageResult{
		SavedPath:  outputPath,
		Model:      model,
		Account:    account.label(),
		DurationMs: time.Since(startedAt).Milliseconds(),
	}, nil
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

// consumeImageStream reads the Codex SSE stream, writing every partial_image
// payload over outputPath so the file always holds the latest (finally the
// complete) image.
func consumeImageStream(body io.Reader, outputPath string) error {
	reader := bufio.NewReader(body)

	var event string
	var data strings.Builder
	saved := false
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
			if err := os.WriteFile(outputPath, imageBytes, 0o644); err != nil {
				return err
			}
			saved = true
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
				return err
			}
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}

		if readErr != nil {
			if dispatchErr := dispatch(); dispatchErr != nil {
				return dispatchErr
			}
			if readErr != io.EOF {
				return readErr
			}
			break
		}
	}

	if !saved {
		if failure != "" {
			return fmt.Errorf("codex failed: %s", failure)
		}
		return errors.New("codex finished without returning image bytes")
	}
	return nil
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
