package runway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withAPI points the package's API base at a test server for the duration of a
// test.
func withAPI(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	previous := APIBase
	APIBase = server.URL
	t.Cleanup(func() {
		APIBase = previous
		server.Close()
	})
}

func TestGetProfileSendsBearerToken(t *testing.T) {
	var gotAuth, gotAccept string
	withAPI(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"user":{"id":42,"email":"a@b.c","username":"someone","plan":"unlimited"}}`))
	})

	profile, err := NewClient("tok123", 42).GetProfile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q, want bearer token", gotAuth)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if profile.ID != 42 || profile.Username != "someone" {
		t.Errorf("profile = %+v", profile)
	}
}

func TestUnauthorizedIsActionable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
		})
		_, err := NewClient("expired", 1).GetProfile(context.Background())
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("status %d: err = %v, want ErrUnauthorized", status, err)
		}
	}
}

// Explore mode allows one generation at a time; that 429 has to stay
// distinguishable so callers can say "wait" instead of "it failed".
func TestConcurrencyLimitMapsToErrBusy(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"Too many tasks are running or pending at the moment."}`))
	})
	_, err := NewClient("tok", 1).CreateVideo(context.Background(), VideoRequest{Prompt: "hi"})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestCreateVideoPayload(t *testing.T) {
	var payload struct {
		TaskType string         `json:"taskType"`
		AsTeamID int64          `json:"asTeamId"`
		Options  map[string]any `json:"options"`
	}
	withAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tasks" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"task":{"id":"abc","status":"THROTTLED","progressRatio":"0"}}`))
	})

	task, err := NewClient("tok", 77).CreateVideo(context.Background(), VideoRequest{
		Prompt:          "a cat",
		DurationSeconds: 8,
		AspectRatio:     "9:16",
		Resolution:      "1080p",
		GenerateAudio:   true,
		References:      []Asset{{ID: "asset-1", URL: "https://cdn/x.png"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != StatusThrottled || !task.Queued() || task.Done() {
		t.Errorf("task = %+v, want a queued non-terminal task", task)
	}
	if payload.TaskType != DefaultModel {
		t.Errorf("taskType = %q, want %q", payload.TaskType, DefaultModel)
	}
	if payload.AsTeamID != 77 {
		t.Errorf("asTeamId = %d", payload.AsTeamID)
	}
	// Explore mode is the whole point: it must never be omitted or flipped.
	if payload.Options["exploreMode"] != true {
		t.Errorf("exploreMode = %v, want true", payload.Options["exploreMode"])
	}
	if payload.Options["textPrompt"] != "a cat" {
		t.Errorf("textPrompt = %v", payload.Options["textPrompt"])
	}
	if payload.Options["duration"] != float64(8) || payload.Options["aspectRatio"] != "9:16" ||
		payload.Options["resolution"] != "1080p" || payload.Options["generateAudio"] != true {
		t.Errorf("options = %+v", payload.Options)
	}
	refs, _ := payload.Options["referenceImages"].([]any)
	if len(refs) != 1 {
		t.Fatalf("referenceImages = %+v", payload.Options["referenceImages"])
	}
	if ref := refs[0].(map[string]any); ref["assetId"] != "asset-1" || ref["url"] != "https://cdn/x.png" {
		t.Errorf("reference = %+v", ref)
	}
}

func TestCreateVideoDefaults(t *testing.T) {
	var options map[string]any
	withAPI(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Options map[string]any `json:"options"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		options = payload.Options
		_, _ = w.Write([]byte(`{"task":{"id":"abc","status":"THROTTLED"}}`))
	})
	if _, err := NewClient("tok", 1).CreateVideo(context.Background(), VideoRequest{Prompt: "x"}); err != nil {
		t.Fatal(err)
	}
	if options["duration"] != float64(DefaultDuration) || options["aspectRatio"] != DefaultAspectRatio ||
		options["resolution"] != DefaultResolution {
		t.Errorf("defaults not applied: %+v", options)
	}
}

func TestCreateVideoRejectsBadInput(t *testing.T) {
	// No request should ever leave for these; a handler that fires means the
	// validation let something through.
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request sent despite invalid input")
		_, _ = w.Write([]byte(`{"task":{"id":"x"}}`))
	})
	client := NewClient("tok", 1)
	for name, req := range map[string]VideoRequest{
		"empty prompt":      {Prompt: "  "},
		"unknown model":     {Prompt: "x", Model: "workflow_text_to_speech"},
		"bad aspect ratio":  {Prompt: "x", AspectRatio: "7:3"},
		"bad resolution":    {Prompt: "x", Resolution: "4k"},
		"duration too long": {Prompt: "x", DurationSeconds: 60},
		"too many refs":     {Prompt: "x", Model: "gen4", References: []Asset{{ID: "a"}, {ID: "b"}}},
	} {
		if _, err := client.CreateVideo(context.Background(), req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// Keyframes are not their own field: Runway carries them inside
// referenceImages under a type tag, keyframes first. Getting this shape wrong
// silently turns a start/end frame into a plain style reference.
func TestKeyframesRideInReferenceImages(t *testing.T) {
	var options map[string]any
	withAPI(t, func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Options map[string]any `json:"options"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		options = payload.Options
		_, _ = w.Write([]byte(`{"task":{"id":"abc","status":"THROTTLED"}}`))
	})

	_, err := NewClient("tok", 1).CreateVideo(context.Background(), VideoRequest{
		Prompt:     "x",
		FirstFrame: &Asset{ID: "first-id", URL: "https://cdn/a.png"},
		EndFrame:   &Asset{ID: "end-id", URL: "https://cdn/b.png"},
		References: []Asset{{ID: "ref-id", URL: "https://cdn/c.png"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	images, _ := options["referenceImages"].([]any)
	if len(images) != 3 {
		t.Fatalf("referenceImages = %+v, want 3 entries", options["referenceImages"])
	}
	first := images[0].(map[string]any)
	end := images[1].(map[string]any)
	plain := images[2].(map[string]any)
	if first["type"] != TypeFirstFrame || first["assetId"] != "first-id" {
		t.Errorf("entry 0 = %+v, want the first frame", first)
	}
	if end["type"] != TypeEndFrame || end["assetId"] != "end-id" {
		t.Errorf("entry 1 = %+v, want the end frame", end)
	}
	// An untagged entry is what makes it a style reference rather than a frame.
	if _, tagged := plain["type"]; tagged {
		t.Errorf("plain reference must carry no type, got %+v", plain)
	}
}

func TestKeyframeCapabilityRules(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("an unsupported combination was sent to runway")
		_, _ = w.Write([]byte(`{"task":{"id":"x"}}`))
	})
	client := NewClient("tok", 1)
	for name, req := range map[string]VideoRequest{
		// gen4 takes a first frame only.
		"end frame on a first-frame-only model": {
			Prompt: "x", Model: "gen4",
			FirstFrame: &Asset{ID: "a"}, EndFrame: &Asset{ID: "b"},
		},
		// An end frame with nothing to start from is meaningless.
		"end frame without a first frame": {
			Prompt: "x", EndFrame: &Asset{ID: "b"},
		},
		// veo3_1 does keyframes but takes no reference images.
		"references on a keyframe-only model": {
			Prompt: "x", Model: "veo3_1", References: []Asset{{ID: "a"}},
		},
		"more references than the model allows": {
			Prompt: "x", Model: "seedance_2", References: make([]Asset, 10),
		},
	} {
		if _, err := client.CreateVideo(context.Background(), req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// seedance_2 is the one family that takes both at once, and it is what most
// callers will use.
func TestSeedanceAcceptsRefsAndKeyframesTogether(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task":{"id":"abc","status":"THROTTLED"}}`))
	})
	_, err := NewClient("tok", 1).CreateVideo(context.Background(), VideoRequest{
		Prompt:     "x",
		Model:      "seedance_2",
		FirstFrame: &Asset{ID: "a"},
		EndFrame:   &Asset{ID: "b"},
		References: make([]Asset, 9),
	})
	if err != nil {
		t.Fatalf("seedance_2 should accept 9 references plus both keyframes: %v", err)
	}
}

// The catalog drives what the tool advertises, so its shape is worth asserting
// against what was read out of Runway's registry.
func TestModelCapabilities(t *testing.T) {
	for name, want := range map[string]Model{
		"seedance_2": {MaxRefs: 9, FirstFrame: true, EndFrame: true, AudioParam: true},
		"gen4":       {MaxRefs: 0, FirstFrame: true, EndFrame: false},
		"veo3_1":     {MaxRefs: 0, FirstFrame: true, EndFrame: true},
	} {
		got, err := LookupModel(name)
		if err != nil {
			t.Fatal(err)
		}
		if got.MaxRefs != want.MaxRefs || got.FirstFrame != want.FirstFrame ||
			got.EndFrame != want.EndFrame || got.AudioParam != want.AudioParam {
			t.Errorf("%s = refs:%d first:%t end:%t audio:%t, want refs:%d first:%t end:%t audio:%t",
				name, got.MaxRefs, got.FirstFrame, got.EndFrame, got.AudioParam,
				want.MaxRefs, want.FirstFrame, want.EndFrame, want.AudioParam)
		}
	}
	// Only models with a verified reference limit may advertise references.
	for _, name := range ReferenceModelNames() {
		if !strings.HasPrefix(name, "seedance_2") {
			t.Errorf("%s advertises references without a verified limit", name)
		}
	}
}

// generateAudio is only sent where the option mapping was verified; inventing
// it elsewhere risks Runway rejecting the whole task.
func TestAudioOptionOnlySentWhereVerified(t *testing.T) {
	for _, tc := range []struct {
		model string
		want  bool
	}{
		{"seedance_2", true},
		{"veo3_1", false},
		{"gen4", false},
	} {
		var options map[string]any
		withAPI(t, func(w http.ResponseWriter, r *http.Request) {
			var payload struct {
				Options map[string]any `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			options = payload.Options
			_, _ = w.Write([]byte(`{"task":{"id":"abc","status":"THROTTLED"}}`))
		})
		if _, err := NewClient("tok", 1).CreateVideo(context.Background(), VideoRequest{
			Prompt: "x", Model: tc.model, GenerateAudio: true,
		}); err != nil {
			t.Fatal(err)
		}
		if _, sent := options["generateAudio"]; sent != tc.want {
			t.Errorf("%s: generateAudio sent = %t, want %t", tc.model, sent, tc.want)
		}
	}
}

func TestGetTaskRejectsNonUUID(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request sent for an invalid task id")
	})
	for _, id := range []string{"", "../../v1/profile", "abc", strings.Repeat("z", 36)} {
		if _, err := NewClient("tok", 1).GetTask(context.Background(), id); err == nil {
			t.Errorf("task id %q was accepted", id)
		}
	}
}

func TestTaskProgressAndArtifact(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task":{"id":"c2f21ee0-5a4a-4d24-9dad-fea249afa586","status":"SUCCEEDED",
			"progressRatio":"1","artifacts":[{"url":"https://cdn/v.mp4","filename":"v.mp4"}]}}`))
	})
	task, err := NewClient("tok", 1).GetTask(context.Background(), "c2f21ee0-5a4a-4d24-9dad-fea249afa586")
	if err != nil {
		t.Fatal(err)
	}
	if !task.Done() || task.Queued() {
		t.Errorf("task = %+v, want terminal", task)
	}
	if task.Progress != 1 || task.VideoURL != "https://cdn/v.mp4" {
		t.Errorf("task = %+v", task)
	}
}

// A running task reports progress as a decimal string; parsing it must not
// collapse to zero, or callers report no progress for the whole render.
func TestRunningTaskProgressParsed(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task":{"id":"c2f21ee0-5a4a-4d24-9dad-fea249afa586","status":"RUNNING","progressRatio":"0.68"}}`))
	})
	task, err := NewClient("tok", 1).GetTask(context.Background(), "c2f21ee0-5a4a-4d24-9dad-fea249afa586")
	if err != nil {
		t.Fatal(err)
	}
	if task.Progress != 0.68 || task.Done() || task.Queued() {
		t.Errorf("task = %+v", task)
	}
}

// WaitForTask must hand back the last observed state rather than an error when
// the deadline passes: the generation is still running on Runway's side and
// the caller needs the task id to resume.
func TestWaitForTaskReturnsLastStateOnDeadline(t *testing.T) {
	withAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task":{"id":"c2f21ee0-5a4a-4d24-9dad-fea249afa586","status":"THROTTLED","progressRatio":"0"}}`))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	task, err := NewClient("tok", 1).WaitForTask(ctx, "c2f21ee0-5a4a-4d24-9dad-fea249afa586", nil)
	if err != nil {
		t.Fatalf("err = %v, want nil so the caller can resume", err)
	}
	if task.Status != StatusThrottled {
		t.Errorf("task = %+v", task)
	}
}

func TestUploadReferenceFlow(t *testing.T) {
	var (
		putBody     []byte
		datasetBody map[string]any
		completed   bool
	)
	withAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/uploads" && r.Method == http.MethodPost:
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["type"] != "DATASET" || req["numberOfParts"] != float64(1) {
				t.Errorf("upload request = %+v", req)
			}
			_, _ = w.Write([]byte(`{"id":"up-1","uploadUrls":["` + APIBase + `/s3/put"],
				"uploadHeaders":{"Content-Type":"image/png"}}`))
		case r.URL.Path == "/s3/put" && r.Method == http.MethodPut:
			// The presigned URL carries its own auth; the account token must not
			// be forwarded to third-party storage.
			if r.Header.Get("Authorization") != "" {
				t.Error("bearer token leaked to the presigned upload URL")
			}
			if r.Header.Get("Content-Type") != "image/png" {
				t.Errorf("upload Content-Type = %q", r.Header.Get("Content-Type"))
			}
			buf := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(buf)
			putBody = buf
			w.Header().Set("ETag", `"etag-abc"`)
		case r.URL.Path == "/v1/uploads/up-1/complete":
			var req struct {
				Parts []struct {
					PartNumber int    `json:"PartNumber"`
					ETag       string `json:"ETag"`
				} `json:"parts"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if len(req.Parts) != 1 || req.Parts[0].ETag != "etag-abc" || req.Parts[0].PartNumber != 1 {
				t.Errorf("complete request = %+v", req.Parts)
			}
			completed = true
			_, _ = w.Write([]byte(`{"url":"https://cdn/x.png"}`))
		case r.URL.Path == "/v1/datasets":
			_ = json.NewDecoder(r.Body).Decode(&datasetBody)
			_, _ = w.Write([]byte(`{"dataset":{"id":"ds-1","url":"https://cdn/signed.png"}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	png := tinyPNG(t)
	asset, err := NewClient("tok", 99).UploadReference(context.Background(), "ref.png", png)
	if err != nil {
		t.Fatal(err)
	}
	if asset.ID != "ds-1" || asset.URL != "https://cdn/signed.png" {
		t.Errorf("asset = %+v", asset)
	}
	if !completed {
		t.Error("the upload was never finalized")
	}
	if len(putBody) != len(png) {
		t.Errorf("uploaded %d bytes, want %d", len(putBody), len(png))
	}
	// previewUploadIds must be present as an array — Runway 400s without it.
	if _, ok := datasetBody["previewUploadIds"].([]any); !ok {
		t.Errorf("previewUploadIds = %#v, want an array", datasetBody["previewUploadIds"])
	}
	if datasetBody["asTeamId"] != float64(99) || datasetBody["privateInTeam"] != true {
		t.Errorf("dataset body = %+v", datasetBody)
	}
	size, _ := datasetBody["metadata"].(map[string]any)["size"].(map[string]any)
	if size["width"] != float64(2) || size["height"] != float64(2) {
		t.Errorf("dimensions = %+v", size)
	}
}

func TestUploadReferenceRejectsOversized(t *testing.T) {
	withAPI(t, func(http.ResponseWriter, *http.Request) {
		t.Error("oversized reference was sent to runway")
	})
	_, err := NewClient("tok", 1).UploadReference(context.Background(), "big.png", make([]byte, MaxReferenceBytes+1))
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestTokenExpiry(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"id":1,"exp":1788220749}`))
	expires, err := TokenExpiry("header." + payload + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if expires.Unix() != 1788220749 {
		t.Errorf("exp = %v", expires)
	}
	for _, bad := range []string{"", "not-a-jwt", "a.b", "a.!!!.c"} {
		if _, err := TokenExpiry(bad); err == nil {
			t.Errorf("TokenExpiry(%q) accepted a malformed token", bad)
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	for input, want := range map[string]string{
		"ref.png":                         "ref.png",
		"../../etc/passwd":                "passwd",
		`C:\tmp\shot.png`:                 "shot.png",
		"a\nb.png":                        "ab.png",
		"":                                "reference.png",
		"/":                               "reference.png",
		strings.Repeat("a", 200) + ".png": strings.Repeat("a", 120),
	} {
		if got := sanitizeFilename(input); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestLookupModel(t *testing.T) {
	model, err := LookupModel("")
	if err != nil || model.Name != DefaultModel {
		t.Errorf("empty model = %+v, %v", model, err)
	}
	if _, err := LookupModel("gen4"); err != nil {
		t.Errorf("gen4: %v", err)
	}
	if _, err := LookupModel("dynamic_workflow"); err == nil {
		t.Error("a non-video task type was accepted as a model")
	}
}

// tinyPNG is a 2x2 PNG, small enough to inline and real enough for
// image.DecodeConfig.
func tinyPNG(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(
		"iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAFElEQVR4nGP8z4AATAxIYJgIAAAA//8DrgD1JJ0LwAAAAABJRU5ErkJggg==")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
