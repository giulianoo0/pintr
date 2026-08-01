# Direct Thread Reference Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept ChatGPT thread attachments directly and let Claude.ai/Desktop transfer sandbox attachments through a signed, encrypted upload bridge without user-managed paths, tokens, or base64.

**Architecture:** ChatGPT file descriptors enter `generate_image` through the host-specific `openai/fileParams` metadata and are downloaded by an SSRF-safe, size-bounded resolver. Claude requests a five-minute HMAC-signed `PUT` URL, uploads from its code-execution sandbox, and receives the existing encrypted one-hour `ref_` token. Both lanes converge on the current in-memory data URLs passed to the Codex backend.

**Tech Stack:** Go 1.26, `github.com/modelcontextprotocol/go-sdk/mcp`, `github.com/google/jsonschema-go`, AWS SDK v2/S3-compatible storage, `net/http`, HMAC-SHA256, table-driven Go tests.

## Global Constraints

- Keep local stdio reference paths working; only hosted ingestion changes.
- Keep generated-image encryption, URLs, 24-hour retention, and result compatibility unchanged.
- ChatGPT file inputs are a top-level array named `reference_image_files` and declare all four documented snake-case fields.
- Claude upload URLs expire after 300 seconds; stored reference uploads expire after one hour.
- Reference images are limited to exactly 10 MiB each and to PNG, JPEG, WebP, or GIF.
- Never place image bytes, data URLs, bearer tokens, ChatGPT URLs, or full `ref_` secrets in logs.
- Remove the legacy bearer-authenticated `POST /upload` route and its manual instructions.
- Do not add dependencies; use the standard library and packages already in `go.mod`.

## File Structure

- Create `internal/remoteimage/remoteimage.go`: bounded HTTPS image download and SSRF defenses.
- Create `internal/remoteimage/remoteimage_test.go`: URL, IP, MIME, and response-limit tests.
- Create `internal/referenceupload/referenceupload.go`: signed upload tickets and HTTP endpoint.
- Create `internal/referenceupload/referenceupload_test.go`: signature, expiry, validation, and single-use tests.
- Modify `internal/assets/assets.go`: conditional encrypted writes under a caller-provided upload ID.
- Modify `internal/mcpserver/mcpserver.go`: ChatGPT file schema/metadata and Claude upload-request tool.
- Modify `internal/mcpserver/handlers.go`: resolve ChatGPT file URLs and issue Claude upload tickets.
- Modify `internal/mcpserver/mcpserver_test.go`: exact host-facing schema and handler behavior.
- Modify `internal/app/app.go`: construct shared downloader/upload manager, register endpoint, and wire tools.
- Modify `internal/web/web.go`: remove the legacy `/upload` route.
- Modify `internal/web/actions.go`: remove the legacy bearer upload handler.
- Modify `README.md`, `internal/web/llms.txt`, and `.env.example`: document the two supported hosted lanes and Claude allowlisting.
- Modify `internal/web/views_test.go` only if legacy `/upload` prose is asserted; retain dashboard upload-count and purge behavior.

---

### Task 1: Safe ChatGPT Image Downloader

**Files:**
- Create: `internal/remoteimage/remoteimage.go`
- Create: `internal/remoteimage/remoteimage_test.go`

**Interfaces:**
- Produces: `remoteimage.Downloader` with `Download(context.Context, string) ([]byte, error)`.
- Produces: `remoteimage.MaxBytes` equal to `10 << 20`.
- Depends only on the Go standard library.

- [ ] **Step 1: Write failing tests for accepted images and bounded responses**

Create tests in package `remoteimage` using a fake `http.RoundTripper`:

```go
func TestDownloadValidPNG(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nvalid-enough-for-sniffing")
	d := newTestDownloader(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(png)),
		}, nil
	}))
	got, err := d.Download(context.Background(), "https://files.example/image.png")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, png) {
		t.Fatalf("download mismatch: %x", got)
	}
}

func TestDownloadRejectsOversizeAndNonImage(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "oversize", body: make([]byte, MaxBytes+1), want: "10 MiB"},
		{name: "not image", body: []byte("plain text"), want: "not a supported image"},
	}
	// Run each body through newTestDownloader and assert the error contains want.
}
```

- [ ] **Step 2: Write failing SSRF and redirect-validation tests**

Add table tests for `validateURL` and `validateIPs`:

```go
func TestValidateURLRequiresPublicHTTPS(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/a.png",
		"https://user:pass@example.com/a.png",
		"https://127.0.0.1/a.png",
		"https://[::1]/a.png",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("validateURL(%q) succeeded", raw)
		}
	}
}

func TestValidateIPsRejectsPrivateDestinations(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"} {
		if err := validateIPs([]net.IPAddr{{IP: net.ParseIP(raw)}}); err == nil {
			t.Errorf("validateIPs(%s) succeeded", raw)
		}
	}
}
```

Also assert that the production client's `CheckRedirect` calls the same URL validation for every redirect target.

- [ ] **Step 3: Run the package tests and verify RED**

Run: `go test ./internal/remoteimage -v`

Expected: FAIL because `Downloader`, `MaxBytes`, `validateURL`, and `validateIPs` do not exist.

- [ ] **Step 4: Implement the minimal safe downloader**

Implement these concrete elements:

```go
const MaxBytes int64 = 10 << 20

type Downloader struct {
	client *http.Client
}

func New() *Downloader
func (d *Downloader) Download(ctx context.Context, rawURL string) ([]byte, error)
func validateURL(rawURL string) error
func validateIPs(addrs []net.IPAddr) error
```

`New` must build a client with a 30-second timeout and a custom `http.Transport.DialContext`. The dialer resolves the original hostname, rejects every non-public address, and connects to a validated IP while TLS continues to verify the original hostname. `CheckRedirect` must reject invalid schemes, credentials, hosts, and private destinations on every hop.

`Download` must require status 200, read at most `MaxBytes+1`, reject an oversized body, and allow only `image/png`, `image/jpeg`, `image/webp`, or `image/gif` as detected by `http.DetectContentType`. Error messages must not echo signed query strings.

Keep an unexported `newTestDownloader(http.RoundTripper)` constructor so successful response tests do not need public network access. The production constructor remains the only exported constructor.

- [ ] **Step 5: Run tests, formatting, and package vet**

Run:

```bash
gofmt -w internal/remoteimage
go test ./internal/remoteimage -v
go vet ./internal/remoteimage
```

Expected: all commands succeed.

- [ ] **Step 6: Commit the downloader**

```bash
git add internal/remoteimage
git commit -m "feat: safely download ChatGPT reference images"
```

---

### Task 2: Signed, Single-Use Claude Upload Bridge

**Files:**
- Create: `internal/referenceupload/referenceupload.go`
- Create: `internal/referenceupload/referenceupload_test.go`
- Modify: `internal/assets/assets.go`

**Interfaces:**
- Consumes: `assets.ErrUploadExists` and `assets.Store.PutUploadEncryptedWithID` created in this task.
- Produces: `referenceupload.Manager.Issue(string, Request) (Ticket, error)`.
- Produces: `referenceupload.Manager.ServeHTTP(http.ResponseWriter, *http.Request)`.
- Produces: `referenceupload.Request`, `referenceupload.Ticket`, `referenceupload.MaxBytes`, and `referenceupload.UploadTTL`.

- [ ] **Step 1: Write failing tests for tickets, tampering, and expiry**

Use a mutable clock and fake store:

```go
type fakeStore struct {
	seen map[string]bool
}

func (s *fakeStore) PutUploadEncryptedWithID(_ context.Context, userID, id string, _ []byte) (string, error) {
	key := userID + "/" + id
	if s.seen[key] {
		return "", assets.ErrUploadExists
	}
	s.seen[key] = true
	return "ref_" + id + ".test-key", nil
}

func TestIssueAndUpload(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{seen: map[string]bool{}}
	m := newTestManager([]byte("01234567890123456789012345678901"), "https://pintr.example", store, func() time.Time { return now })
	png := []byte("\x89PNG\r\n\x1a\nvalid-enough-for-sniffing")
	ticket, err := m.Issue("user-1", Request{Filename: "ref.png", MIMEType: "image/png", SizeBytes: int64(len(png))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, ticket.UploadURL, bytes.NewReader(png))
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
}
```

Add separate tests that mutate one token character and advance the clock past five minutes. Assert tampering returns 401 and expiry returns 410 without calling the store.

- [ ] **Step 2: Write failing validation and replay tests**

Cover:

- non-`PUT` request returns 405;
- unsupported declared MIME returns an `Issue` error;
- declared size zero or over 10 MiB returns an `Issue` error;
- uploaded byte count different from the claim returns 400;
- actual MIME different from the claim returns 400;
- a second `PUT` with the same ticket returns 409;
- success JSON contains only `ref` and `expires_in` and never a user ID or encryption key outside the `ref` token.

- [ ] **Step 3: Run tests and verify RED**

Run: `go test ./internal/referenceupload -v`

Expected: FAIL because the package and asset interfaces do not exist.

- [ ] **Step 4: Add conditional encrypted upload storage**

In `internal/assets/assets.go`:

```go
var ErrUploadExists = errors.New("reference upload already exists")

func (a *Store) PutUploadEncryptedWithID(ctx context.Context, userID, id string, img []byte) (string, error)
```

Reuse the existing AES-256-GCM layout. Write to `uploads/<userID>/<id>` with `IfNoneMatch: aws.String("*")`. Translate S3 `PreconditionFailed` and `ConditionalRequestConflict` API errors to `ErrUploadExists`. Return `ref_<id>.<base64url-key>` exactly as the existing resolver expects. Remove `PutUploadEncrypted` only after Task 4 removes its last caller.

- [ ] **Step 5: Implement ticket signing and the HTTP endpoint**

Create:

```go
const (
	MaxBytes int64 = 10 << 20
	UploadTTL       = 5 * time.Minute
)

type Request struct {
	Filename  string
	MIMEType  string
	SizeBytes int64
}

type Ticket struct {
	UploadURL   string
	UploadID    string
	ExpiresIn   int64
	MaxSizeBytes int64
}

type uploadStore interface {
	PutUploadEncryptedWithID(context.Context, string, string, []byte) (string, error)
}

type Manager struct {
	secret    []byte
	publicURL string
	store     uploadStore
	now       func() time.Time
	onStored  func()
}

func New(secret []byte, publicURL string, store uploadStore, onStored func()) *Manager
func (m *Manager) Issue(userID string, req Request) (Ticket, error)
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

Encode JSON claims containing upload ID, user ID, filename, MIME, size, and Unix expiry with base64url. Authenticate `payload.signature` using HMAC-SHA256 and `hmac.Equal`. Put the token in `/reference-upload/<token>` so no bearer header is required.

`ServeHTTP` must use `http.MaxBytesReader`, verify the exact length and detected MIME, map `assets.ErrUploadExists` to 409, call `onStored` only after storage succeeds, set `Content-Type: application/json`, and return status 201.

- [ ] **Step 6: Run tests and focused verification**

Run:

```bash
gofmt -w internal/assets/assets.go internal/referenceupload
go test ./internal/referenceupload ./internal/assets -v
go vet ./internal/referenceupload ./internal/assets
```

Expected: all commands succeed.

- [ ] **Step 7: Commit the bridge**

```bash
git add internal/assets/assets.go internal/referenceupload
git commit -m "feat: add signed reference upload bridge"
```

---

### Task 3: ChatGPT File Parameters and Reference Resolution

**Files:**
- Modify: `internal/mcpserver/mcpserver.go`
- Modify: `internal/mcpserver/handlers.go`
- Modify: `internal/mcpserver/mcpserver_test.go`
- Modify: `internal/app/app.go`

**Interfaces:**
- Consumes: `remoteimage.Downloader.Download` from Task 1.
- Produces: hosted `generate_image.reference_image_files` and `_meta["openai/fileParams"]`.
- Produces: `HostedGenerate(st *store.Store, assetStore *assets.Store, tracker *analytics.Tracker, publicURL string, downloader referenceDownloader) GenerateFunc` with direct ChatGPT resolution.

- [ ] **Step 1: Write a failing exact-schema test**

Extend `TestGenerateImageToolPerMode` and marshal the hosted tool to generic JSON. Assert:

```go
meta := hosted.Meta["openai/fileParams"].([]string)
if !slices.Equal(meta, []string{"reference_image_files"}) {
	t.Fatalf("file params = %#v", meta)
}
if _, ok := stdio.Meta["openai/fileParams"]; ok {
	t.Fatal("stdio tool advertises ChatGPT file params")
}
```

Inspect `reference_image_files` in the hosted JSON Schema. It must be an optional array whose item object declares exactly `download_url`, `file_id`, `mime_type`, and `file_name`; only the first two are required. Assert the stdio schema omits `reference_image_files` entirely.

- [ ] **Step 2: Write failing resolution tests with a fake downloader**

Define:

```go
type fakeReferenceDownloader struct {
	data  map[string][]byte
	calls []string
}

func (d *fakeReferenceDownloader) Download(_ context.Context, rawURL string) ([]byte, error) {
	d.calls = append(d.calls, rawURL)
	b, ok := d.data[rawURL]
	if !ok {
		return nil, errors.New("missing test image")
	}
	return b, nil
}
```

Call the hosted resolver with no `ref_` tokens and two `referenceImageFile` values. Assert it downloads each URL once, preserves order, and returns two `data:image/...;base64,` values. Add failure cases for a missing `download_url` or `file_id`, and assert errors identify the attachment by safe file name or ordinal without printing its signed URL.

- [ ] **Step 3: Run the MCP tests and verify RED**

Run: `go test ./internal/mcpserver -run 'TestGenerateImageToolPerMode|TestResolveHostedChatGPTFiles' -v`

Expected: FAIL because the file schema and downloader integration do not exist.

- [ ] **Step 4: Add the ChatGPT file schema and metadata**

In `mcpserver.go` add:

```go
type referenceImageFile struct {
	DownloadURL string `json:"download_url"`
	FileID      string `json:"file_id"`
	MIMEType    string `json:"mime_type,omitempty"`
	FileName    string `json:"file_name,omitempty"`
}

type generateImageArgs struct {
	Prompt              string               `json:"prompt" jsonschema:"the full image prompt to render"`
	ReferenceImages     []string             `json:"reference_images,omitempty" jsonschema:"optional reference images to anchor a character or style"`
	ReferenceImageFiles []referenceImageFile `json:"reference_image_files,omitempty" jsonschema:"ChatGPT-provided attached reference images"`
}
```

For hosted tools, set:

```go
tool.Meta = mcp.Meta{"openai/fileParams": []string{"reference_image_files"}}
```

For stdio, delete `reference_image_files` from the generated schema and do not set metadata. Update hosted copy to say ChatGPT should pass attachments directly and Claude should call `request_reference_upload`; remove manual bearer/curl instructions from `generate_image`.

- [ ] **Step 5: Resolve direct files in hosted generation**

Add:

```go
type referenceDownloader interface {
	Download(context.Context, string) ([]byte, error)
}
```

Extend hosted resolution to fetch and validate every file object, call `codex.DataURL` on bytes, and append these after any resolved `ref_` handles in stable argument order. Change `HostedGenerate` to accept the interface and pass it to the resolver. Never persist ChatGPT inputs.

Construct `remoteimage.New()` in `internal/app/app.go` and pass it into `HostedGenerate`. Do not yet change `mcpserver.New`; Task 4 owns the new Claude tool registration.

- [ ] **Step 6: Run focused and package tests**

Run:

```bash
gofmt -w internal/mcpserver internal/app/app.go
go test ./internal/mcpserver ./internal/app -v
go vet ./internal/mcpserver ./internal/app
```

Expected: all commands succeed.

- [ ] **Step 7: Commit direct ChatGPT ingestion**

```bash
git add internal/mcpserver internal/app/app.go
git commit -m "feat: accept ChatGPT reference attachments"
```

---

### Task 4: Register the Claude Tool and Replace Legacy `/upload`

**Files:**
- Modify: `internal/mcpserver/mcpserver.go`
- Modify: `internal/mcpserver/handlers.go`
- Modify: `internal/mcpserver/mcpserver_test.go`
- Modify: `internal/app/app.go`
- Modify: `internal/web/web.go`
- Modify: `internal/web/actions.go`
- Modify: `internal/assets/assets.go`

**Interfaces:**
- Consumes: `referenceupload.Manager.Issue` and `.ServeHTTP` from Task 2.
- Produces: hosted-only MCP tool `request_reference_upload`.
- Produces: public signed endpoint `/reference-upload/<token>`.
- Removes: bearer-authenticated `POST /upload` and `assets.Store.PutUploadEncrypted`.

- [ ] **Step 1: Write failing tool-definition and handler tests**

Add tests that assert `referenceUploadTool()` has required `filename`, `mime_type`, and `size_bytes` fields, contains no path/data/base64 input, and documents:

- Claude's sandbox upload;
- the `pintr.giuli.dev` Additional allowed domains setting using the configured public origin;
- five-minute URL expiry;
- passing returned `ref` to `generate_image.reference_images`.

Use a fake issuer:

```go
type fakeUploadIssuer struct {
	userID string
	req    referenceupload.Request
}

func (f *fakeUploadIssuer) Issue(userID string, req referenceupload.Request) (referenceupload.Ticket, error) {
	f.userID, f.req = userID, req
	return referenceupload.Ticket{
		UploadURL: "https://pintr.example/reference-upload/token",
		UploadID: "upload-1", ExpiresIn: 300, MaxSizeBytes: referenceupload.MaxBytes,
	}, nil
}
```

Put an OAuth user in context, call the hosted handler, and assert typed output mirrors the ticket. Add an unauthenticated test expecting `unauthenticated`.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `go test ./internal/mcpserver -run 'TestReferenceUpload' -v`

Expected: FAIL because the tool and handler do not exist.

- [ ] **Step 3: Implement and register the hosted-only upload tool**

Add typed arguments/results and function type:

```go
type referenceUploadArgs struct {
	Filename  string `json:"filename"`
	MIMEType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
}

type referenceUploadResult struct {
	UploadURL    string `json:"upload_url"`
	UploadID     string `json:"upload_id"`
	ExpiresIn    int64  `json:"expires_in"`
	MaxSizeBytes int64  `json:"max_size_bytes"`
	Instructions string `json:"instructions"`
}

type ReferenceUploadFunc func(context.Context, referenceUploadArgs) (*mcp.CallToolResult, referenceUploadResult, error)
```

`HostedReferenceUpload` extracts the authenticated user, calls the issuer, and returns the ticket plus concise sandbox instructions. Change the constructor to `New(hosted bool, generate GenerateFunc, usage UsageFunc, referenceUpload ReferenceUploadFunc) *mcp.Server`; register `request_reference_upload` only when `hosted` and the function is non-nil. Pass `nil` from stdio and the hosted handler from `ServeHTTP`.

- [ ] **Step 4: Wire the shared manager and signed route**

In `ServeHTTP` construct one manager with the existing `PINTR_SECRET`, `PINTR_PUBLIC_URL`, asset store, and analytics callback. Pass it to `HostedReferenceUpload` and register:

```go
mux.Handle("/reference-upload/", uploadManager)
```

Register the signed endpoint without `provider.RequireAuth`; the short-lived HMAC token is its narrowly scoped authorization. Keep `/mcp` bearer-authenticated.

- [ ] **Step 5: Remove the legacy route and dead implementation**

Delete:

- `mux.HandleFunc("/upload", h.handleUpload)` from `internal/web/web.go`;
- `handleUpload` and now-unused imports from `internal/web/actions.go`;
- `assets.Store.PutUploadEncrypted` after confirming `rg 'PutUploadEncrypted\('` has no callers.

Do not delete `FetchUpload`, upload counting, purging, encryption, or the one-hour janitor; the Claude bridge still uses them.

- [ ] **Step 6: Run focused, web, and full tests**

Run:

```bash
gofmt -w internal/mcpserver internal/app internal/web internal/assets
go test ./internal/mcpserver ./internal/referenceupload ./internal/web ./internal/app -v
go test ./...
```

Expected: all commands succeed and `rg -n 'HandleFunc\("/upload"|func .*handleUpload|PutUploadEncrypted\(' internal` returns no legacy matches.

- [ ] **Step 7: Commit the Claude integration**

```bash
git add internal/mcpserver internal/app internal/web internal/assets
git commit -m "feat: upload Claude thread references in chat"
```

---

### Task 5: Documentation and Hosted Guidance Cleanup

**Files:**
- Modify: `README.md`
- Modify: `internal/web/llms.txt`
- Modify: `.env.example`
- Test: `internal/mcpserver/mcpserver_test.go`
- Test: `internal/web/views_test.go`

**Interfaces:**
- Documents the exact public contract produced by Tasks 3 and 4.
- Keeps dashboard reference-upload retention and deletion surfaces intact.

- [ ] **Step 1: Write failing documentation assertions**

Add focused assertions that hosted tool copy includes `reference_image_files` and `request_reference_upload`, while it excludes the legacy manual `POST /upload`, bearer-token curl example, local hosted paths, and inline base64 guidance as a workflow.

Keep the existing stdio assertion that local paths are documented only in local mode. Keep web view assertions for encrypted upload counts, purge, and one-hour retention.

- [ ] **Step 2: Run tests and verify RED**

Run: `go test ./internal/mcpserver ./internal/web -v`

Expected: FAIL on old `/upload` wording.

- [ ] **Step 3: Rewrite README and hosted `llms.txt`**

Document these exact user flows:

1. ChatGPT: attach image and call `generate_image`; the host fills `reference_image_files`.
2. Claude.ai/Desktop: attach image, let Claude call `request_reference_upload`, allow the pintr origin once under Settings → Capabilities → Code execution and file creation → Additional allowed domains, then let Claude upload and reuse the returned `ref` for one hour.
3. Stdio: local paths remain local-only.

State that upload URLs expire in five minutes, reference tokens in one hour, and generated outputs in 24 hours. Explain that Claude's bytes travel from its sandbox over HTTPS and never through model-authored JSON.

Remove every user-facing bearer `POST /upload` example and any suggestion that a remote server can read a local filesystem path. Update `.env.example` analytics comments only if event wording still names the removed endpoint; keep the `reference_upload` event name if the new endpoint still emits it.

- [ ] **Step 4: Run docs-related tests and scans**

Run:

```bash
go test ./internal/mcpserver ./internal/web -v
rg -n 'POST /upload|--data-binary @|upload the raw bytes to /upload' README.md internal/web/llms.txt internal/mcpserver
git diff --check
```

Expected: tests pass; `rg` returns no legacy hosted instructions; diff check succeeds.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md internal/web/llms.txt .env.example internal/mcpserver/mcpserver_test.go internal/web/views_test.go
git commit -m "docs: explain direct thread reference images"
```

---

### Task 6: Final Verification and Review

**Files:**
- Review all files changed since design commit `02e11de`.

**Interfaces:**
- Confirms every success criterion in the design spec.
- Produces no new feature surface unless review finds a concrete defect.

- [ ] **Step 1: Run formatting and inspect whether it changes files**

Run:

```bash
gofmt -w cmd internal
git status --short
```

Expected: no unexpected formatting-only changes outside touched Go files.

- [ ] **Step 2: Run the complete verification suite**

Run:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
git diff --check 02e11de..HEAD
```

Expected: every command exits 0.

- [ ] **Step 3: Run security and contract scans**

Run:

```bash
rg -n 'POST /upload|--data-binary @|HandleFunc\("/upload"|func .*handleUpload' README.md internal .env.example
rg -n 'openai/fileParams|reference_image_files|request_reference_upload|reference-upload' internal README.md
git status --short
```

Expected: the first scan has no legacy route/instructions; the second finds tool metadata, schemas, route, tests, and docs; the worktree is clean.

- [ ] **Step 4: Request two-stage code review**

First request a spec-compliance review against `docs/superpowers/specs/2026-08-01-direct-thread-reference-images-design.md`. After resolving any finding, request a code-quality/security review focused on SSRF, signed URL replay, secret leakage, body limits, user scoping, and compatibility with both MCP hosts.

- [ ] **Step 5: Re-run verification after review fixes**

Repeat Step 2 exactly. Do not claim completion from a prior run.

- [ ] **Step 6: Commit any review fixes**

If review required changes:

```bash
git add -u
git commit -m "fix: harden direct reference uploads"
```

If review found no changes, do not create an empty commit.
