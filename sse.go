package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Parsing of the Codex SSE response stream.

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
