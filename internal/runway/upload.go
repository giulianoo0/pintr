package runway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"path"
	"strings"
)

// MaxReferenceBytes is the largest reference image pintr will forward. It
// matches the reference-upload ticket limit, so anything that made it into
// pintr's own storage can be forwarded.
const MaxReferenceBytes = 10 << 20

// Asset is an uploaded image as the task payload needs it: Runway wants both
// the dataset id and its (signed) URL.
//
// Keyframes are not a separate field in Runway's API — a first/last frame is
// an entry in the same referenceImages array carrying Type "first_frame" or
// "end_frame". An untagged entry is a plain style/character reference.
type Asset struct {
	ID   string `json:"assetId"`
	URL  string `json:"url"`
	Type string `json:"type,omitempty"`
}

// Keyframe tags, as Runway's web app sends them.
const (
	TypeFirstFrame = "first_frame"
	TypeEndFrame   = "end_frame"
)

// UploadReference publishes one reference image into the user's Runway
// workspace and returns the asset to attach to a generation.
//
// Runway's upload is a four-step dance: reserve an upload, PUT the bytes to
// the presigned S3 URL it hands back, tell Runway the part landed (it wants
// the ETag), then wrap the upload in a "dataset" — the thing generations
// actually reference.
func (c *Client) UploadReference(ctx context.Context, filename string, img []byte) (Asset, error) {
	if len(img) == 0 {
		return Asset{}, errors.New("reference image is empty")
	}
	if len(img) > MaxReferenceBytes {
		return Asset{}, fmt.Errorf("reference image exceeds the %d MiB limit", MaxReferenceBytes>>20)
	}
	if c.teamID == 0 {
		return Asset{}, errors.New("no runway team resolved for this account")
	}
	filename = sanitizeFilename(filename)

	var reserved struct {
		ID            string            `json:"id"`
		UploadURLs    []string          `json:"uploadUrls"`
		UploadHeaders map[string]string `json:"uploadHeaders"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/uploads", map[string]any{
		"filename":      filename,
		"numberOfParts": 1,
		"type":          "DATASET",
	}, &reserved); err != nil {
		return Asset{}, fmt.Errorf("reserving upload: %w", err)
	}
	if len(reserved.UploadURLs) == 0 || reserved.ID == "" {
		return Asset{}, errors.New("runway did not return an upload URL")
	}

	etag, err := c.putPart(ctx, reserved.UploadURLs[0], reserved.UploadHeaders, img)
	if err != nil {
		return Asset{}, err
	}

	if err := c.do(ctx, http.MethodPost, "/v1/uploads/"+reserved.ID+"/complete", map[string]any{
		"parts": []map[string]any{{"PartNumber": 1, "ETag": etag}},
	}, nil); err != nil {
		return Asset{}, fmt.Errorf("finalizing upload: %w", err)
	}

	payload := map[string]any{
		"fileCount":        1,
		"name":             filename,
		"uploadId":         reserved.ID,
		"previewUploadIds": []string{}, // required to be an array; may be empty
		"type":             map[string]any{"name": "image", "type": "image", "isDirectory": false},
		"asTeamId":         c.teamID,
		"privateInTeam":    true,
	}
	// Dimensions are optional to Runway; send them when the format is one we
	// can read so the workspace shows a correctly proportioned thumbnail.
	if config, _, err := image.DecodeConfig(bytes.NewReader(img)); err == nil {
		payload["metadata"] = map[string]any{
			"size": map[string]any{"width": config.Width, "height": config.Height},
		}
	}

	var created struct {
		Dataset struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"dataset"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/datasets", payload, &created); err != nil {
		return Asset{}, fmt.Errorf("creating reference asset: %w", err)
	}
	if created.Dataset.ID == "" || created.Dataset.URL == "" {
		return Asset{}, errors.New("runway did not return a usable reference asset")
	}
	return Asset{ID: created.Dataset.ID, URL: created.Dataset.URL}, nil
}

// putPart uploads the bytes to the presigned URL and returns the ETag Runway
// needs to accept the part. The presigned URL already carries its own
// authorization, so the pintr/Runway bearer token is deliberately NOT sent.
func (c *Client) putPart(ctx context.Context, uploadURL string, headers map[string]string, img []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(img))
	if err != nil {
		return "", errors.New("runway returned an unusable upload URL")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.ContentLength = int64(len(img))

	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", errors.New("uploading the reference image to runway failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("uploading the reference image failed with status %d", resp.StatusCode)
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	if etag == "" {
		return "", errors.New("the reference upload did not return an ETag")
	}
	return etag, nil
}

// sanitizeFilename keeps only a plain base name. The value is echoed back by
// Runway and shown in their UI; stripping directories and control characters
// keeps a caller-supplied string from carrying path or newline surprises into
// the request.
func sanitizeFilename(name string) string {
	name = path.Base(strings.TrimSpace(strings.ReplaceAll(name, `\`, "/")))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if name == "" || name == "." || name == "/" {
		return "reference.png"
	}
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}
