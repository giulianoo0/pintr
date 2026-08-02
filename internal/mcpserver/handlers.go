package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/giulianoo0/pintr/internal/analytics"
	"github.com/giulianoo0/pintr/internal/assets"
	"github.com/giulianoo0/pintr/internal/codex"
	"github.com/giulianoo0/pintr/internal/oauth"
	"github.com/giulianoo0/pintr/internal/random"
	"github.com/giulianoo0/pintr/internal/referenceupload"
	"github.com/giulianoo0/pintr/internal/runway"
	"github.com/giulianoo0/pintr/internal/store"
)

// --- stdio mode handlers (single local account) ---

// writeLocalPNG saves the image to a pintr-managed cache dir (a path pintr
// chooses, never one the caller supplies) and returns it.
func writeLocalPNG(png []byte) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "pintr", "images")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	id, err := random.Token(12)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, id+".png")
	if err := os.WriteFile(path, png, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// StdioGenerate resolves the single local account, generates, and saves the
// PNG to a pintr-managed path (returned as saved_path).
func StdioGenerate(authStore *codex.AuthStore) GenerateFunc {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		refs, err := codex.ResolveFileReferences(args.ReferenceImages)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := codex.GenerateImage(ctx, []codex.Account{codex.NewFileAccount(authStore)}, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		path, err := writeLocalPNG(img.PNG)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return nil, generateImageResult{
			SavedPath: path, MimeType: "image/png", Model: img.Model, Account: img.Account,
			DurationMs: img.DurationMs, SizeBytes: len(img.PNG), Usage: img.Usage,
		}, nil
	}
}

func StdioUsage(authStore *codex.AuthStore) UsageFunc {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		// get_usage is an explicit check → fetch fresh and reset the cache timer.
		usage, _, err := codex.CachedUsage(ctx, codex.NewFileAccount(authStore), true)
		if err != nil {
			return nil, usageResult{}, err
		}
		return nil, usageResult{Accounts: []codex.AccountUsage{usage}}, nil
	}
}

// --- hosted mode handlers (the authenticated user's linked accounts) ---

type referenceDownloader interface {
	Download(context.Context, string) ([]byte, error)
}

type referenceFetcher interface {
	FetchUpload(context.Context, string, string) ([]byte, error)
}

type uploadIssuer interface {
	Issue(string, referenceupload.Request) (referenceupload.Ticket, error)
}

func HostedReferenceUpload(issuer uploadIssuer) ReferenceUploadFunc {
	return func(ctx context.Context, args referenceUploadArgs) (*mcp.CallToolResult, referenceUploadResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, referenceUploadResult{}, errors.New("unauthenticated")
		}
		ticket, err := issuer.Issue(u.ID, referenceupload.Request{
			Filename: args.Filename, MIMEType: args.MIMEType, SizeBytes: args.SizeBytes,
		})
		if err != nil {
			return nil, referenceUploadResult{}, err
		}
		origin := "the upload URL origin"
		if parsed, err := url.Parse(ticket.UploadURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			origin = parsed.Scheme + "://" + parsed.Host
		}
		instructions := "From Claude's code-execution sandbox, PUT the attached file's raw bytes to upload_url. " +
			"If the sandbox blocks the request, add " + origin + " under Settings → Capabilities → Code execution " +
			"and file creation → Additional allowed domains. The URL expires in five minutes. Read the returned ref " +
			"from the PUT response and pass it to generate_image.reference_images."
		return nil, referenceUploadResult{
			UploadURL: ticket.UploadURL, UploadID: ticket.UploadID, ExpiresIn: ticket.ExpiresIn,
			MaxSizeBytes: ticket.MaxSizeBytes, Instructions: instructions,
		}, nil
	}
}

// resolveHostedReferences turns hosted references into data: URLs. Existing
// ref_ handles are resolved first and remain reusable until they expire. Any
// ChatGPT-provided attachments are downloaded directly into memory and
// appended in argument order; their bytes are never persisted.
func resolveHostedReferences(ctx context.Context, st referenceFetcher, userID string, refs []string, files []referenceImageFile, downloader referenceDownloader) ([]string, error) {
	images, err := resolveHostedReferenceImages(ctx, st, userID, refs, files, downloader)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(images))
	for _, img := range images {
		out = append(out, codex.DataURL(img))
	}
	return out, nil
}

// resolveHostedReferenceImages does the actual resolution and returns raw
// bytes. Codex wants them as data: URLs; Runway uploads the bytes into the
// user's own workspace, so both callers share this and wrap as they need.
func resolveHostedReferenceImages(ctx context.Context, st referenceFetcher, userID string, refs []string, files []referenceImageFile, downloader referenceDownloader) ([][]byte, error) {
	if len(refs) > hostedMaxReferenceImages || len(files) > hostedMaxReferenceImages ||
		len(refs) > hostedMaxReferenceImages-len(files) {
		return nil, fmt.Errorf("hosted generation accepts at most %d total reference images", hostedMaxReferenceImages)
	}
	for i, file := range files {
		if strings.TrimSpace(file.DownloadURL) == "" {
			return nil, fmt.Errorf("attachment %d is missing download_url", i+1)
		}
		if strings.TrimSpace(file.FileID) == "" {
			return nil, fmt.Errorf("attachment %d is missing file_id", i+1)
		}
	}
	if len(files) > 0 && downloader == nil {
		return nil, errors.New("attachments cannot be downloaded")
	}
	out := make([][]byte, 0, len(refs)+len(files))
	totalBytes := 0
	for i, ref := range refs {
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, "ref_") {
			return nil, fmt.Errorf("reference image %d is not an uploaded handle — the hosted server can't read local files or accept inline base64/data: URLs; call request_reference_upload and pass the returned ref_ handle", i+1)
		}
		if st == nil {
			return nil, fmt.Errorf("reference image %d could not be resolved", i+1)
		}
		img, err := st.FetchUpload(ctx, userID, ref)
		if err != nil {
			log.Printf("[generate_image] reference image %d failed", i+1)
			return nil, fmt.Errorf("reference image %d could not be resolved (uploads expire 1 hour after upload — call request_reference_upload again and retry with the new handle)", i+1)
		}
		if err := appendHostedReference(&out, &totalBytes, img, fmt.Sprintf("reference image %d", i+1)); err != nil {
			return nil, err
		}
	}
	for i, file := range files {
		img, err := downloader.Download(ctx, file.DownloadURL)
		if err != nil {
			return nil, fmt.Errorf("attachment %d download failed; retry with the attachment", i+1)
		}
		if err := appendHostedReference(&out, &totalBytes, img, fmt.Sprintf("attachment %d", i+1)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func appendHostedReference(out *[][]byte, totalBytes *int, img []byte, label string) error {
	if len(img) > hostedMaxReferenceImageBytes {
		return fmt.Errorf("%s exceeds the 10 MiB decoded size limit", label)
	}
	if len(img) > hostedMaxReferenceTotalBytes-*totalBytes {
		return errors.New("hosted reference images exceed the 40 MiB total decoded size limit")
	}
	*totalBytes += len(img)
	*out = append(*out, img)
	return nil
}

// viewURL builds the decrypted-view link served by web's /view handler: the
// object key and the decryption key travel as query params so an agent that
// can only open a url gets back the raw image.
func viewURL(publicURL, objectKey, keyB64 string) string {
	return publicURL + "/view?o=" + url.QueryEscape(objectKey) + "&k=" + url.QueryEscape(keyB64)
}

func HostedUsage(st *store.Store, tracker *analytics.Tracker) UsageFunc {
	return func(ctx context.Context, _ getUsageArgs) (*mcp.CallToolResult, usageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, usageResult{}, errors.New("unauthenticated")
		}
		tracker.Event("get_usage")
		accounts, err := codex.UserAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, usageResult{}, err
		}
		out := make([]codex.AccountUsage, 0, len(accounts))
		for _, account := range accounts {
			// get_usage is an explicit check → fetch fresh and reset the timer.
			usage, _, err := codex.CachedUsage(ctx, account, true)
			if err != nil {
				log.Printf("[get_usage] fetch failed for %s: %v", account.Label(), err)
				continue
			}
			out = append(out, usage)
		}
		return nil, usageResult{Accounts: out}, nil
	}
}

// HostedGenerate resolves the authenticated user's accounts, generates,
// encrypts the PNG under a one-time key, uploads the ciphertext, and returns
// a presigned download URL plus the key. It never touches the local
// filesystem or a caller-chosen path.
func HostedGenerate(st *store.Store, assetStore *assets.Store, tracker *analytics.Tracker, publicURL string, downloader referenceDownloader) GenerateFunc {
	return func(ctx context.Context, args generateImageArgs) (*mcp.CallToolResult, generateImageResult, error) {
		u, ok := oauth.UserFromContext(ctx)
		if !ok {
			return nil, generateImageResult{}, errors.New("unauthenticated")
		}
		if assetStore == nil {
			return nil, generateImageResult{}, errors.New("image storage is not configured on this server (set PINTR_S3_*)")
		}
		refs, err := resolveHostedReferences(ctx, assetStore, u.ID, args.ReferenceImages, args.ReferenceImageFiles, downloader)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		accounts, err := codex.UserAccounts(ctx, st, u.ID)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		img, err := codex.GenerateImage(ctx, accounts, args.Prompt, refs)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		stored, err := assetStore.PutEncrypted(ctx, u.ID, img.PNG)
		if err != nil {
			return nil, generateImageResult{}, fmt.Errorf("storing image: %w", err)
		}
		tracker.Event("generate_image")

		result := generateImageResult{
			AssetURL:          stored.URL,
			DecryptedAssetURL: viewURL(publicURL, stored.ObjectKey, stored.KeyB64),
			DecryptionKey:     stored.KeyB64,
			MimeType:          "image/png",
			Model:             img.Model,
			Account:           img.Account,
			DurationMs:        img.DurationMs,
			SizeBytes:         len(img.PNG),
			Usage:             img.Usage,
		}
		callResult, err := hostedCallResult(result)
		if err != nil {
			return nil, generateImageResult{}, err
		}
		return callResult, result, nil
	}
}

// --- generate_video (Runway) ---

// videoPollReserve is held back from the tool's deadline so that when a
// generation finishes near the limit there is still time to download it,
// encrypt it and store it. Without it a video could complete on Runway's side
// and still be reported as queued.
// PollAfterSeconds is the cadence pintr asks agents to re-check a running
// generation on. Explore-mode work moves on the order of minutes, so a minute
// between checks is responsive without hammering Runway.
const PollAfterSeconds = 60

// runwayClientFor resolves the caller's connected Runway account.
func runwayClientFor(ctx context.Context, st *store.Store, assetStore *assets.Store) (*runway.Client, string, error) {
	u, ok := oauth.UserFromContext(ctx)
	if !ok {
		return nil, "", errors.New("unauthenticated")
	}
	if assetStore == nil {
		return nil, "", errors.New("video storage is not configured on this server (set PINTR_S3_*)")
	}
	token, account, err := st.LoadRunwayToken(ctx, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoRunwayAccount) {
			return nil, "", errors.New("no runway account connected — open the pintr dashboard, go to the runway tab, and paste your RW_USER_TOKEN")
		}
		return nil, "", err
	}
	return runway.NewClient(token, account.TeamID), u.ID, nil
}

// HostedGenerateVideo submits a Runway generation and returns immediately with
// its task id.
//
// It deliberately does NOT wait for the video. Explore mode queues for minutes,
// far longer than MCP clients keep a tool call open — a blocking call gets cut
// off by the connector, and because the task id only existed inside that call,
// the generation is left running with no way to find it again. Submitting and
// handing back the id makes the wait the agent's job, via video_queue.
func HostedGenerateVideo(st *store.Store, assetStore *assets.Store, tracker *analytics.Tracker, publicURL string, downloader referenceDownloader) GenerateVideoFunc {
	return func(ctx context.Context, args generateVideoArgs) (*mcp.CallToolResult, generateVideoResult, error) {
		client, userID, err := runwayClientFor(ctx, st, assetStore)
		if err != nil {
			return nil, generateVideoResult{}, err
		}
		startedAt := time.Now()

		// A task_id with no prompt is a status check; keep it working here so an
		// agent holding an id from an older call isn't stranded.
		if taskID := strings.TrimSpace(args.TaskID); taskID != "" {
			task, err := client.GetTask(ctx, taskID)
			if err != nil {
				return nil, generateVideoResult{}, err
			}
			return finishVideoResult(ctx, client, assetStore, tracker, publicURL, userID, task, startedAt)
		}

		task, err := submitVideo(ctx, client, assetStore, userID, args, downloader)
		if err != nil {
			return nil, generateVideoResult{}, err
		}
		tracker.Event("generate_video")

		result := generateVideoResult{
			TaskID:           task.ID,
			Model:            orDefaultModel(args.Model),
			Status:           "queued",
			ProgressPercent:  int(math.Round(task.Progress * 100)),
			PollAfterSeconds: PollAfterSeconds,
			DurationMs:       time.Since(startedAt).Milliseconds(),
			Message: fmt.Sprintf("Generation submitted to Runway as task %s. It is NOT finished — Explore mode "+
				"queues, and the whole job commonly takes 10-20 minutes. Wait about %d seconds, then call "+
				"video_queue with task_id %q to check it, and keep re-checking on that cadence until status is "+
				"succeeded or failed. The video URLs appear in that result, not this one. Runway caps how many "+
				"generations may be in flight at once, so do not fire off a batch while this one is pending.",
				task.ID, PollAfterSeconds, task.ID),
		}
		if task.Status == runway.StatusRunning {
			result.Status = "running"
		}
		callResult, err := hostedVideoCallResult(result)
		if err != nil {
			return nil, generateVideoResult{}, err
		}
		return callResult, result, nil
	}
}

// HostedVideoQueue is the queue view: every recent generation with its status,
// or one task in detail. When a task has finished, this is where its video gets
// pulled from Runway, encrypted and handed back.
func HostedVideoQueue(st *store.Store, assetStore *assets.Store, tracker *analytics.Tracker, publicURL string) VideoQueueFunc {
	return func(ctx context.Context, args videoQueueArgs) (*mcp.CallToolResult, videoQueueResult, error) {
		client, userID, err := runwayClientFor(ctx, st, assetStore)
		if err != nil {
			return nil, videoQueueResult{}, err
		}

		if taskID := strings.TrimSpace(args.TaskID); taskID != "" {
			task, err := client.GetTask(ctx, taskID)
			if err != nil {
				return nil, videoQueueResult{}, err
			}
			_, detail, err := finishVideoResult(ctx, client, assetStore, tracker, publicURL, userID, task, time.Now())
			if err != nil {
				return nil, videoQueueResult{}, err
			}
			result := videoQueueResult{
				Task:             &detail,
				PollAfterSeconds: pollHintFor(detail.Status),
				Message:          detail.Message,
			}
			return queueCallResult(result)
		}

		tasks, err := client.ListTasks(ctx, args.Limit)
		if err != nil {
			return nil, videoQueueResult{}, err
		}
		result := videoQueueResult{Generations: make([]videoQueueEntry, 0, len(tasks))}
		pending := 0
		for _, task := range tasks {
			status := statusLabel(task)
			if status == "queued" || status == "running" {
				pending++
			}
			result.Generations = append(result.Generations, videoQueueEntry{
				TaskID:          task.ID,
				Status:          status,
				ProgressPercent: int(math.Round(task.Progress * 100)),
				Model:           task.Model,
				Prompt:          task.Prompt,
				CreatedAt:       task.CreatedAt,
				Error:           task.Error,
			})
		}
		result.PendingCount = pending
		switch {
		case len(result.Generations) == 0:
			result.Message = "No video generations on this Runway account yet."
		case pending > 0:
			result.PollAfterSeconds = PollAfterSeconds
			result.Message = fmt.Sprintf("%d generation(s) still queued or running. Re-check in about %d seconds. "+
				"Call video_queue with a task_id to get that one's detail and, once it succeeds, its video URLs. "+
				"Runway caps how many generations may be in flight at once — submit more only as these finish.",
				pending, PollAfterSeconds)
		default:
			result.Message = "Nothing pending. Call video_queue with a task_id to fetch a finished generation's video URLs."
		}
		return queueCallResult(result)
	}
}

// pollHintFor tells the agent when to come back, and stays 0 for terminal
// states so a finished generation doesn't invite pointless re-checks.
func pollHintFor(status string) int {
	if status == "queued" || status == "running" {
		return PollAfterSeconds
	}
	return 0
}

func statusLabel(task runway.Task) string {
	switch {
	case task.Status == runway.StatusSucceeded:
		return "succeeded"
	case task.Status == runway.StatusFailed || task.Status == runway.StatusCancelled:
		return "failed"
	case task.Queued():
		return "queued"
	default:
		return "running"
	}
}

func orDefaultModel(model string) string {
	if strings.TrimSpace(model) == "" {
		return runway.DefaultModel
	}
	return strings.TrimSpace(model)
}

// finishVideoResult turns one observed task into a result, delivering the MP4
// when it has succeeded: downloaded from Runway, encrypted under a one-time key
// that is returned once and never stored, exactly like generated images.
func finishVideoResult(ctx context.Context, client *runway.Client, assetStore *assets.Store, tracker *analytics.Tracker, publicURL, userID string, task runway.Task, startedAt time.Time) (*mcp.CallToolResult, generateVideoResult, error) {
	result := generateVideoResult{
		TaskID:          task.ID,
		Model:           orDefaultModel(task.Model),
		Status:          statusLabel(task),
		ProgressPercent: int(math.Round(task.Progress * 100)),
		DurationMs:      time.Since(startedAt).Milliseconds(),
	}
	result.PollAfterSeconds = pollHintFor(result.Status)

	switch result.Status {
	case "succeeded":
		if task.VideoURL == "" {
			return nil, generateVideoResult{}, errors.New("runway reported success but returned no video")
		}
		video, mimeType, err := client.DownloadVideo(ctx, task.VideoURL)
		if err != nil {
			return nil, generateVideoResult{}, err
		}
		stored, err := assetStore.PutEncrypted(ctx, userID, video)
		if err != nil {
			return nil, generateVideoResult{}, fmt.Errorf("storing video: %w", err)
		}
		tracker.Event("video_delivered")
		result.AssetURL = stored.URL
		result.DecryptedAssetURL = viewURL(publicURL, stored.ObjectKey, stored.KeyB64)
		result.DecryptionKey = stored.KeyB64
		result.MimeType = mimeType
		result.SizeBytes = len(video)
		result.ProgressPercent = 100
		result.Message = fmt.Sprintf("Video ready (%d bytes). Open decrypted_asset_url to watch it — it returns "+
			"the decrypted MP4 directly, decrypted server-side. asset_url is the raw encrypted ciphertext; "+
			"decryption_key is its AES-256-GCM key, returned only here and never stored. The stored video "+
			"auto-deletes in 24 hours — download it now if you need it longer.", len(video))
	case "failed":
		result.Message = "Runway reported the generation as " + strings.ToLower(task.Status) + "."
		if task.Error != "" {
			result.Message += " " + task.Error
		}
	default:
		result.Message = fmt.Sprintf("Still %s on Runway (%d%%). This is normal for Explore mode, not a failure. "+
			"Re-check with video_queue and task_id %q in about %d seconds.",
			result.Status, result.ProgressPercent, task.ID, PollAfterSeconds)
	}

	callResult, err := hostedVideoCallResult(result)
	if err != nil {
		return nil, generateVideoResult{}, err
	}
	return callResult, result, nil
}

func queueCallResult(result videoQueueResult) (*mcp.CallToolResult, videoQueueResult, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, videoQueueResult{}, fmt.Errorf("encoding result: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: result.Message},
		&mcp.TextContent{Text: string(resultJSON)},
	}}, result, nil
}

// submitVideo uploads any reference images and keyframes, then creates the
// generation.
func submitVideo(ctx context.Context, client *runway.Client, assetStore *assets.Store, userID string, args generateVideoArgs, downloader referenceDownloader) (runway.Task, error) {
	if strings.TrimSpace(args.Prompt) == "" {
		return runway.Task{}, errors.New("prompt is required to start a generation (or pass task_id to resume one)")
	}

	images, err := resolveHostedReferenceImages(ctx, assetStore, userID, args.ReferenceImages, args.ReferenceImageFiles, downloader)
	if err != nil {
		return runway.Task{}, err
	}
	references := make([]runway.Asset, 0, len(images))
	for i, img := range images {
		asset, err := client.UploadReference(ctx, fmt.Sprintf("reference-%d", i+1), img)
		if err != nil {
			return runway.Task{}, fmt.Errorf("uploading reference image %d to runway: %w", i+1, err)
		}
		references = append(references, asset)
	}

	firstFrame, err := uploadKeyframe(ctx, client, assetStore, userID, args.FirstFrameImage, "first_frame_image", downloader)
	if err != nil {
		return runway.Task{}, err
	}
	endFrame, err := uploadKeyframe(ctx, client, assetStore, userID, args.EndFrameImage, "end_frame_image", downloader)
	if err != nil {
		return runway.Task{}, err
	}

	audio := true
	if args.Audio != nil {
		audio = *args.Audio
	}
	return client.CreateVideo(ctx, runway.VideoRequest{
		Prompt:          args.Prompt,
		Model:           args.Model,
		DurationSeconds: args.DurationSeconds,
		AspectRatio:     args.AspectRatio,
		Resolution:      args.Resolution,
		GenerateAudio:   audio,
		References:      references,
		FirstFrame:      firstFrame,
		EndFrame:        endFrame,
	})
}

// uploadKeyframe resolves one keyframe handle and publishes it to Runway.
// Keyframes go through the same ref_ upload path as references, so the same
// size and expiry rules apply.
func uploadKeyframe(ctx context.Context, client *runway.Client, st referenceFetcher, userID, handle, field string, downloader referenceDownloader) (*runway.Asset, error) {
	if strings.TrimSpace(handle) == "" {
		return nil, nil
	}
	images, err := resolveHostedReferenceImages(ctx, st, userID, []string{handle}, nil, downloader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	asset, err := client.UploadReference(ctx, field+".png", images[0])
	if err != nil {
		return nil, fmt.Errorf("uploading %s to runway: %w", field, err)
	}
	return &asset, nil
}

func hostedVideoCallResult(result generateVideoResult) (*mcp.CallToolResult, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: result.Message},
		&mcp.TextContent{Text: string(resultJSON)},
	}}, nil
}

// hostedCallResult builds the unstructured content for a hosted generation.
// MCP clients disagree on which channel reaches the model: some forward only
// structuredContent (Claude Code, VS Code, Codex), others read only the
// content blocks (opencode, Grok Build, most adapters). The result must
// therefore appear in BOTH — the SDK fills structuredContent from the typed
// result, and per the spec's backwards-compatibility rule the same serialized
// JSON goes here as its own TextContent block (kept pure JSON, no prose mixed
// in, so content-only clients can parse it). Returning a non-nil result
// suppresses the SDK's own JSON fallback, so it must be included by hand.
func hostedCallResult(result generateImageResult) (*mcp.CallToolResult, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	note := fmt.Sprintf(
		"Image generated (%d bytes). To view it, open decrypted_asset_url — it returns the decrypted "+
			"PNG directly (image/png), decrypted server-side. asset_url is the raw encrypted ciphertext; "+
			"decryption_key is the AES-256-GCM key, returned only here and never stored. The stored image "+
			"auto-deletes in 24 hours — download the PNG now if you need it longer.", result.SizeBytes)
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: note},
		&mcp.TextContent{Text: string(resultJSON)},
	}}, nil
}
