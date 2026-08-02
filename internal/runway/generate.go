package runway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MaxVideoBytes caps the generated video pintr will pull back from Runway's
// CDN before re-encrypting it into its own storage.
const MaxVideoBytes = 256 << 20

// Task statuses Runway reports. THROTTLED is Explore mode's queue ("In queue"
// in the web UI) — it is a normal, expected state, not an error.
const (
	StatusThrottled = "THROTTLED"
	StatusPending   = "PENDING"
	StatusRunning   = "RUNNING"
	StatusSucceeded = "SUCCEEDED"
	StatusFailed    = "FAILED"
	StatusCancelled = "CANCELLED"
)

// VideoRequest is one generation. References are untagged style/character
// images; FirstFrame and EndFrame are keyframes, which Runway carries in the
// same array under a type tag. A request may use either, or both on models
// that support both (the Seedance family).
type VideoRequest struct {
	Prompt          string
	Model           string
	DurationSeconds int
	AspectRatio     string
	Resolution      string
	GenerateAudio   bool
	References      []Asset
	FirstFrame      *Asset
	EndFrame        *Asset
}

// Task is the part of a Runway task pintr cares about.
type Task struct {
	ID        string
	Status    string
	Progress  float64
	Error     string
	VideoURL  string
	Filename  string
	Model     string
	Prompt    string
	CreatedAt string
}

// Done reports whether the task reached a terminal state.
func (t Task) Done() bool {
	switch t.Status {
	case StatusSucceeded, StatusFailed, StatusCancelled:
		return true
	}
	return false
}

// Queued reports whether the task is waiting rather than actively rendering.
func (t Task) Queued() bool { return t.Status == StatusThrottled || t.Status == StatusPending }

// CreateVideo submits a generation in Explore mode and returns the task as
// Runway first reports it (normally THROTTLED).
//
// Explore mode is always on: it is what makes generations free on an Unlimited
// plan, at the cost of queueing. pintr never spends a user's credits without
// them asking, and there is no credit-spending path here to ask for.
func (c *Client) CreateVideo(ctx context.Context, req VideoRequest) (Task, error) {
	model, err := LookupModel(req.Model)
	if err != nil {
		return Task{}, err
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return Task{}, errors.New("prompt is required")
	}
	if c.teamID == 0 {
		return Task{}, errors.New("no runway team resolved for this account")
	}
	duration, err := validateDuration(model, req.DurationSeconds)
	if err != nil {
		return Task{}, err
	}
	aspectRatio, err := validateAspectRatio(req.AspectRatio)
	if err != nil {
		return Task{}, err
	}
	resolution, err := validateResolution(model, req.Resolution)
	if err != nil {
		return Task{}, err
	}
	images, err := buildReferenceImages(model, req)
	if err != nil {
		return Task{}, err
	}

	options := map[string]any{
		"name":        taskName(model.Name, req.Prompt),
		"textPrompt":  req.Prompt,
		"duration":    duration,
		"aspectRatio": aspectRatio,
		"resolution":  resolution,
		"exploreMode": true,
		// Explore mode is not a fidelity setting; keep the encoder at the same
		// quality the web tool submits.
		"bitrate_mode":   "high",
		"creationSource": "pintr",
	}
	if model.AudioParam {
		options["generateAudio"] = req.GenerateAudio
	}
	if len(images) > 0 {
		options["referenceImages"] = images
	}

	var created struct {
		Task rawTask `json:"task"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/tasks", map[string]any{
		"taskType": model.Name,
		"options":  options,
		"asTeamId": c.teamID,
	}, &created); err != nil {
		return Task{}, err
	}
	if created.Task.ID == "" {
		return Task{}, errors.New("runway did not return a task id")
	}
	return created.Task.toTask(), nil
}

// buildReferenceImages assembles the single referenceImages array Runway
// expects, checking each part against what the model actually accepts. The
// keyframes go first, in first→end order, matching what the web app sends.
func buildReferenceImages(model Model, req VideoRequest) ([]Asset, error) {
	if req.FirstFrame != nil && !model.FirstFrame {
		return nil, fmt.Errorf("model %s does not accept a first frame", model.Name)
	}
	if req.EndFrame != nil && !model.EndFrame {
		return nil, fmt.Errorf("model %s does not accept an end frame — it supports a first frame only", model.Name)
	}
	if req.EndFrame != nil && req.FirstFrame == nil {
		return nil, errors.New("an end frame needs a first frame too")
	}
	if len(req.References) > model.MaxRefs {
		if model.MaxRefs == 0 {
			return nil, fmt.Errorf("model %s does not accept reference images — use first/end frames instead, "+
				"or pick one of: %s", model.Name, strings.Join(ReferenceModelNames(), ", "))
		}
		return nil, fmt.Errorf("model %s accepts at most %d reference image(s)", model.Name, model.MaxRefs)
	}

	images := make([]Asset, 0, len(req.References)+2)
	if req.FirstFrame != nil {
		first := *req.FirstFrame
		first.Type = TypeFirstFrame
		images = append(images, first)
	}
	if req.EndFrame != nil {
		end := *req.EndFrame
		end.Type = TypeEndFrame
		images = append(images, end)
	}
	for _, ref := range req.References {
		ref.Type = "" // untagged: a plain style/character reference
		images = append(images, ref)
	}
	return images, nil
}

// GetTask fetches one task's current state.
func (c *Client) GetTask(ctx context.Context, taskID string) (Task, error) {
	if !isTaskID(taskID) {
		return Task{}, errors.New("invalid task id")
	}
	var fetched struct {
		Task rawTask `json:"task"`
	}
	path := "/v1/tasks/" + url.PathEscape(taskID) + "?asTeamId=" + strconv.FormatInt(c.teamID, 10)
	if err := c.do(ctx, http.MethodGet, path, nil, &fetched); err != nil {
		return Task{}, err
	}
	if fetched.Task.ID == "" {
		return Task{}, errors.New("runway did not return that task")
	}
	return fetched.Task.toTask(), nil
}

// PollInterval is how often WaitForTask re-checks. Explore-mode work sits in a
// queue for minutes, so polling faster only adds load.
const PollInterval = 5 * time.Second

// WaitForTask polls until the task finishes or ctx ends. On ctx expiry it
// returns the last observed state with no error, so the caller can hand the
// task id back to the user instead of losing the generation.
func (c *Client) WaitForTask(ctx context.Context, taskID string, onUpdate func(Task)) (Task, error) {
	task, err := c.GetTask(ctx, taskID)
	if err != nil {
		return Task{}, err
	}
	for !task.Done() {
		if onUpdate != nil {
			onUpdate(task)
		}
		select {
		case <-ctx.Done():
			return task, nil
		case <-time.After(PollInterval):
		}
		next, err := c.GetTask(ctx, taskID)
		if err != nil {
			// A blip mid-poll shouldn't discard a running generation; report the
			// last good state and let the caller resume by task id.
			if ctx.Err() != nil {
				return task, nil
			}
			return task, err
		}
		task = next
	}
	return task, nil
}

// DownloadVideo fetches a finished task's video from Runway's CDN. The URL
// comes from Runway's own API response (never from a caller), is required to
// be https, and the body is capped.
func (c *Client) DownloadVideo(ctx context.Context, videoURL string) ([]byte, string, error) {
	parsed, err := url.Parse(videoURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return nil, "", errors.New("runway returned an unusable video URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, videoURL, nil)
	if err != nil {
		return nil, "", errors.New("runway returned an unusable video URL")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, "", errors.New("downloading the generated video failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("downloading the generated video returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxVideoBytes+1))
	if err != nil {
		return nil, "", errors.New("could not read the generated video")
	}
	if int64(len(body)) > MaxVideoBytes {
		return nil, "", fmt.Errorf("the generated video exceeds the %d MiB limit", MaxVideoBytes>>20)
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" || !strings.HasPrefix(contentType, "video/") {
		contentType = "video/mp4"
	}
	return body, contentType, nil
}

// ListTasks returns the account's most recent tasks, newest first, keeping
// only the video ones pintr knows about. It is what backs the queue view: a
// generation whose tool call died still shows up here, which is the only way
// to recover its id.
func (c *Client) ListTasks(ctx context.Context, limit int) ([]Task, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	var listed struct {
		Tasks []rawTask `json:"tasks"`
	}
	path := "/v1/tasks?asTeamId=" + strconv.FormatInt(c.teamID, 10) + "&limit=" + strconv.Itoa(limit)
	if err := c.do(ctx, http.MethodGet, path, nil, &listed); err != nil {
		return nil, err
	}
	tasks := make([]Task, 0, len(listed.Tasks))
	for _, raw := range listed.Tasks {
		if _, known := modelsByName[raw.TaskType]; !known {
			continue // image generations, upscales, workflow runs — not ours
		}
		tasks = append(tasks, raw.toTask())
	}
	return tasks, nil
}

// rawTask mirrors Runway's task JSON. progressRatio arrives as a string, and
// error is polymorphic (see taskError) — decoding it as a plain string made
// every FAILED task fail to parse, which took the whole list down with it.
type rawTask struct {
	ID            string    `json:"id"`
	Status        string    `json:"status"`
	TaskType      string    `json:"taskType"`
	CreatedAt     string    `json:"createdAt"`
	ProgressRatio string    `json:"progressRatio"`
	Error         taskError `json:"error"`
	Options       struct {
		TextPrompt string `json:"textPrompt"`
	} `json:"options"`
	Artifacts []struct {
		URL      string `json:"url"`
		Filename string `json:"filename"`
	} `json:"artifacts"`
}

// taskError decodes Runway's task error, which is null on a healthy task, an
// object like {"errorMessage":"…","reason":"SAFETY.OUTPUT.THIRD_PARTY"} on a
// moderated or failed one, and has also been seen as a bare string. Decoding
// is deliberately total: an unrecognized shape yields no message rather than an
// error, because a task's status matters more than the prose explaining it.
type taskError struct {
	Message string
	Reason  string
}

func (e *taskError) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		e.Message = text
		return nil
	}
	var object struct {
		ErrorMessage string `json:"errorMessage"`
		Message      string `json:"message"`
		Reason       string `json:"reason"`
	}
	if err := json.Unmarshal(data, &object); err == nil {
		e.Message = object.ErrorMessage
		if e.Message == "" {
			e.Message = object.Message
		}
		e.Reason = object.Reason
	}
	return nil
}

// String renders the error for an agent, keeping the reason code — it is what
// distinguishes "your prompt was moderated" from a transient failure.
func (e taskError) String() string {
	switch {
	case e.Message == "" && e.Reason == "":
		return ""
	case e.Message == "":
		return e.Reason
	case e.Reason == "":
		return e.Message
	default:
		return e.Message + " (" + e.Reason + ")"
	}
}

func (r rawTask) toTask() Task {
	task := Task{
		ID:        r.ID,
		Status:    strings.ToUpper(strings.TrimSpace(r.Status)),
		Error:     truncate(r.Error.String(), 300),
		Model:     r.TaskType,
		Prompt:    truncate(strings.Join(strings.Fields(r.Options.TextPrompt), " "), 160),
		CreatedAt: r.CreatedAt,
	}
	if ratio, err := strconv.ParseFloat(r.ProgressRatio, 64); err == nil {
		task.Progress = ratio
	}
	if len(r.Artifacts) > 0 {
		task.VideoURL = r.Artifacts[0].URL
		task.Filename = r.Artifacts[0].Filename
	}
	return task
}

// taskName is the label shown in the user's Runway workspace.
func taskName(model, prompt string) string {
	prompt = strings.Join(strings.Fields(prompt), " ")
	if len(prompt) > 80 {
		prompt = prompt[:80]
	}
	return "pintr · " + model + " · " + prompt
}

// isTaskID accepts only the UUID shape Runway issues, so a caller-supplied id
// can't reshape the request path.
func isTaskID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
