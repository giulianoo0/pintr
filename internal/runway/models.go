package runway

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultModel is what generate_video uses when the caller doesn't pick one:
// Runway's multi-reference model, the one the web tool defaults to and the
// only family that takes both tagged keyframes and free reference images.
const DefaultModel = "seedance_2"

// Model describes one video model pintr will submit as a taskType.
//
// The list is an allowlist on purpose — taskType is interpolated into an API
// call, and an agent-supplied string should not be able to reach arbitrary
// Runway task types (image generation, upscales, workflow execution, exports).
//
// Every field below was read out of Runway's own web-app model registry
// (`maxReferenceImages`, and whether the model's default inputs include
// `image` / `endFrameImage`) and cross-checked against the capability labels
// the model picker shows. They are NOT guesses — but they are also a snapshot,
// so a model Runway changes underneath us may need this table refreshed.
type Model struct {
	Name    string
	Summary string

	// MaxRefs is how many untagged reference images the model accepts. It is 0
	// for models where Runway declares no reference limit, which includes a few
	// that do accept references in the web UI (kling_o3_*, hailuo): pintr would
	// rather advertise nothing than guess a cap and send payloads it has never
	// validated. Seedance is the multi-reference path.
	MaxRefs int

	// FirstFrame / EndFrame report whether the model accepts keyframes, sent as
	// referenceImages entries tagged `first_frame` / `end_frame`.
	FirstFrame bool
	EndFrame   bool

	// AudioParam is set only where the mapping from the UI's audio toggle to
	// the task option `generateAudio` was actually verified. Elsewhere pintr
	// omits the field and lets Runway apply the model's own default, rather
	// than risk rejecting the task with an option name it invented.
	AudioParam bool
}

var models = []Model{
	{Name: "seedance_2", Summary: "Seedance 2.0 — multi-reference + keyframes, native audio",
		MaxRefs: 9, FirstFrame: true, EndFrame: true, AudioParam: true},
	{Name: "seedance_2_fast", Summary: "Seedance 2.0 Fast — quicker, lower fidelity",
		MaxRefs: 9, FirstFrame: true, EndFrame: true, AudioParam: true},
	{Name: "seedance_2_mini", Summary: "Seedance 2.0 Mini — cheapest Seedance tier",
		MaxRefs: 9, FirstFrame: true, EndFrame: true, AudioParam: true},

	{Name: "gen4", Summary: "Runway Gen-4 — image to video, first frame only", FirstFrame: true},
	{Name: "gen4_turbo", Summary: "Runway Gen-4 Turbo — faster Gen-4, first frame only", FirstFrame: true},

	{Name: "veo3_1", Summary: "Google Veo 3.1 — keyframes, no reference images",
		FirstFrame: true, EndFrame: true},

	{Name: "kling_3_0_standard", Summary: "Kling 3.0 Standard — keyframes", FirstFrame: true, EndFrame: true},
	{Name: "kling_3_0_pro", Summary: "Kling 3.0 Pro — keyframes", FirstFrame: true, EndFrame: true},
	{Name: "kling_3_0_4k", Summary: "Kling 3.0 4K — keyframes", FirstFrame: true, EndFrame: true},
	{Name: "kling_3_0_turbo", Summary: "Kling 3.0 Turbo — first frame only", FirstFrame: true},
	{Name: "kling_o3_standard", Summary: "Kling O3 Standard — keyframes", FirstFrame: true, EndFrame: true},
	{Name: "kling_o3_pro", Summary: "Kling O3 Pro — keyframes", FirstFrame: true, EndFrame: true},
	{Name: "kling_o3_4k", Summary: "Kling O3 4K — keyframes", FirstFrame: true, EndFrame: true},

	{Name: "minimax_hailuo_3_0", Summary: "MiniMax Hailuo 3.0 — keyframes", FirstFrame: true, EndFrame: true},
}

var modelsByName = func() map[string]Model {
	m := make(map[string]Model, len(models))
	for _, model := range models {
		m[model.Name] = model
	}
	return m
}()

// LookupModel resolves a caller-supplied model name, defaulting when empty.
func LookupModel(name string) (Model, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = DefaultModel
	}
	model, ok := modelsByName[name]
	if !ok {
		return Model{}, fmt.Errorf("unknown model %q — supported models: %s", name, strings.Join(ModelNames(), ", "))
	}
	return model, nil
}

// ModelNames lists the allowlisted models in a stable order.
func ModelNames() []string {
	names := make([]string, 0, len(models))
	for _, model := range models {
		names = append(names, model.Name)
	}
	sort.Strings(names)
	return names
}

// Models returns the catalog (for docs and the dashboard).
func Models() []Model { return append([]Model(nil), models...) }

// ReferenceModelNames lists the models that accept untagged reference images.
func ReferenceModelNames() []string {
	names := make([]string, 0, len(models))
	for _, model := range models {
		if model.MaxRefs > 0 {
			names = append(names, model.Name)
		}
	}
	sort.Strings(names)
	return names
}

// Allowed option values. These are validated rather than passed through
// because they land in the task payload verbatim.
var (
	aspectRatios = []string{"16:9", "9:16", "1:1", "4:3", "3:4", "21:9"}
	resolutions  = []string{"480p", "720p", "1080p"}
)

const (
	DefaultAspectRatio = "16:9"
	DefaultResolution  = "720p"
	DefaultDuration    = 5
	// maxDuration is Runway's own ceiling for a single clip on these models.
	maxDuration = 12
)

func validateAspectRatio(value string) (string, error) {
	return oneOf(value, DefaultAspectRatio, aspectRatios, "aspect_ratio")
}

func validateResolution(value string) (string, error) {
	return oneOf(value, DefaultResolution, resolutions, "resolution")
}

func oneOf(value, fallback string, allowed []string, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", fmt.Errorf("unsupported %s %q — use one of: %s", field, value, strings.Join(allowed, ", "))
}

func validateDuration(seconds int) (int, error) {
	if seconds == 0 {
		return DefaultDuration, nil
	}
	if seconds < 1 || seconds > maxDuration {
		return 0, fmt.Errorf("duration_seconds must be between 1 and %d", maxDuration)
	}
	return seconds, nil
}

// AspectRatios and Resolutions expose the allowlists for tool schemas.
func AspectRatios() []string { return append([]string(nil), aspectRatios...) }
func Resolutions() []string  { return append([]string(nil), resolutions...) }
