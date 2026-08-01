# Fast Image Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver browser images directly from object storage and stream authenticated raw PNG chunks through Pintr without waiting for the complete storage download.

**Architecture:** Generated assets move from one whole-object AES-GCM record to a versioned sequence of independently authenticated 64 KiB records. The asset layer authenticates the first record before returning a streaming reader; `/raw` flushes that reader while `/view` serves a cacheable WebCrypto viewer that fetches ciphertext directly from storage. Legacy assets keep the buffered decoder for their remaining 24-hour lifetime.

**Tech Stack:** Go 1.26, `net/http`, AES-256-GCM, AWS SDK v2/S3-compatible storage, browser WebCrypto, Go table-driven tests.

## Global Constraints

- Generated objects and server storage contain ciphertext only; do not retain plaintext or keys after a request.
- Use a fresh random 256-bit key and random eight-byte nonce prefix for every generated image.
- Never emit plaintext from a record until that record authenticates successfully.
- Keep legacy generated assets readable until their existing 24-hour expiry.
- Keep reference-upload encryption unchanged.
- Keep the 64 MiB generated-image plaintext limit.
- `decrypted_asset_url` must remain a raw image URL for agents; add `browser_view_url` for humans.
- Do not log object keys, decryption keys, signed URLs, or URL fragments.
- No provider-specific edge worker and no plaintext server/CDN cache.
- Execute inline in this session; the user explicitly prohibited sub-agents.

---

### Task 1: Versioned Chunked AEAD Codec

**Files:**
- Create: `internal/assets/chunked.go`
- Create: `internal/assets/chunked_test.go`

**Interfaces:**
- Consumes: raw plaintext, a 32-byte AES key, and an eight-byte nonce prefix.
- Produces: `sealChunked([]byte, []byte, []byte) ([]byte, error)`, `openChunked(io.ReadCloser, []byte) (*DecryptedObject, error)`, `DecryptedObject{Body io.ReadCloser, Size int64, Chunked bool}`, and format constants used by the store and browser viewer.

- [ ] **Step 1: Write failing boundary and corruption tests**

Add table-driven tests for plaintext lengths `0`, `1`, `assetChunkSize-1`, `assetChunkSize`, `assetChunkSize+1`, and `3*assetChunkSize+17`. Use fixed key/prefix bytes, call `sealChunked`, then `openChunked(io.NopCloser(bytes.NewReader(blob)), key)`, read `Body`, and require exact plaintext and `Size`. Add independent mutations for the header, first tag, middle record, truncation, and trailing bytes and require an error either from `openChunked` or reading `Body`.

```go
func TestChunkedRoundTripBoundaries(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	prefix := bytes.Repeat([]byte{0x22}, 8)
	for _, size := range []int{0, 1, assetChunkSize - 1, assetChunkSize, assetChunkSize + 1, 3*assetChunkSize + 17} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{byte(size)}, size)
			blob, err := sealChunked(plain, key, prefix)
			if err != nil { t.Fatal(err) }
			opened, err := openChunked(io.NopCloser(bytes.NewReader(blob)), key)
			if err != nil { t.Fatal(err) }
			defer opened.Body.Close()
			got, err := io.ReadAll(opened.Body)
			if err != nil { t.Fatal(err) }
			if opened.Size != int64(size) || !bytes.Equal(got, plain) {
				t.Fatalf("size/body mismatch: metadata=%d body=%d want=%d", opened.Size, len(got), size)
			}
		})
	}
}
```

- [ ] **Step 2: Run the codec tests and verify RED**

Run: `go test ./internal/assets -run 'TestChunked' -v`

Expected: compilation fails because `assetChunkSize`, `sealChunked`, and `openChunked` do not exist.

- [ ] **Step 3: Implement the header, sealing loop, and decrypting reader**

Create `chunked.go` with an eight-byte `PINTRC01` marker, 28-byte header, 64 KiB chunks, and 64 MiB limit. Encode lengths big-endian. Construct each nonce as `prefix || uint32(index)` and each AAD as `header || uint32(index)`. Emit one authenticated empty record for zero-length plaintext.

```go
const (
	assetMagic         = "PINTRC01"
	assetHeaderSize    = 28
	assetChunkSize     = 64 << 10
	maxAssetPlaintext  = 64 << 20
)

type DecryptedObject struct {
	Body    io.ReadCloser
	Size    int64
	Chunked bool
}

func chunkNonce(prefix []byte, index uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

func chunkAAD(header []byte, index uint32) []byte {
	aad := make([]byte, len(header)+4)
	copy(aad, header)
	binary.BigEndian.PutUint32(aad[len(header):], index)
	return aad
}
```

`openChunked` must parse and validate the header, create AES-GCM, read and authenticate the first record before returning, and return a custom `io.ReadCloser` that yields the buffered first plaintext then authenticates subsequent records on demand. Before yielding the final record, read one extra byte and reject trailing data. On `Close`, close the original storage body.

- [ ] **Step 4: Add a failing streaming-timing test**

Wrap the encrypted bytes in a reader that records when EOF is observed. Open a multi-chunk object, read exactly one plaintext byte, and assert the source has not reached EOF. The production change that would break this test is replacing record reads with `io.ReadAll`.

```go
opened, err := openChunked(&observedReadCloser{Reader: bytes.NewReader(blob), sawEOF: &sawEOF}, key)
if err != nil { t.Fatal(err) }
one := make([]byte, 1)
if _, err := io.ReadFull(opened.Body, one); err != nil { t.Fatal(err) }
if sawEOF { t.Fatal("first plaintext byte required reading the complete encrypted object") }
```

- [ ] **Step 5: Run codec tests and benchmark GREEN**

Run: `go test ./internal/assets -run 'TestChunked' -v`

Add `BenchmarkChunkedRoundTrip` for 1 MiB, 4 MiB, and 16 MiB payloads, calling `sealChunked` and reading `openChunked`. Run: `go test ./internal/assets -run '^$' -bench BenchmarkChunkedRoundTrip -benchmem`.

- [ ] **Step 6: Commit the codec**

```bash
git add internal/assets/chunked.go internal/assets/chunked_test.go
git commit -m "feat: add streaming chunked asset encryption"
```

---

### Task 2: Store Chunked Generated Assets and Open Legacy Assets

**Files:**
- Modify: `internal/assets/assets.go`
- Modify: `internal/assets/assets_test.go`

**Interfaces:**
- Consumes: `sealChunked`, `openChunked`, and `DecryptedObject` from Task 1.
- Produces: `(*Store).OpenDecrypted(context.Context, string, string) (*DecryptedObject, error)`; `PutEncrypted` writes the new format; reference upload methods retain the old format.

- [ ] **Step 1: Write failing S3 integration tests**

Extend the existing `httptest.Server` S3 pattern. For `PutEncrypted`, capture the PUT body, decode the returned key, assert the body begins with `assetMagic`, and round-trip it through `openChunked`. For `OpenDecrypted`, serve a hand-built legacy `nonce || ciphertext || tag` body and assert the returned `DecryptedObject` has `Chunked == false`, the correct size, and exact plaintext.

```go
func TestPutEncryptedWritesChunkedAsset(t *testing.T) {
	plain := bytes.Repeat([]byte("p"), assetChunkSize+9)
	// Fake S3 accepts PUT and a subsequent presign operation; capture PUT bytes.
	stored, err := testAssetStore(server.URL).PutEncrypted(context.Background(), "user-1", plain)
	if err != nil { t.Fatal(err) }
	key, _ := base64.StdEncoding.DecodeString(stored.KeyB64)
	opened, err := openChunked(io.NopCloser(bytes.NewReader(gotBody)), key)
	if err != nil { t.Fatal(err) }
	got, err := io.ReadAll(opened.Body)
	if err != nil || !bytes.Equal(got, plain) { t.Fatalf("round trip: %v", err) }
}
```

- [ ] **Step 2: Run store tests and verify RED**

Run: `go test ./internal/assets -run 'TestPutEncryptedWritesChunkedAsset|TestOpenDecryptedSupportsLegacy' -v`

Expected: `PutEncrypted` body lacks the marker and `OpenDecrypted` is undefined.

- [ ] **Step 3: Switch generated writes and add format-detecting reads**

In `PutEncrypted`, generate the key and eight-byte prefix, call `sealChunked`, and upload the returned ciphertext. Leave `PutUploadEncryptedWithID` and `FetchUpload` unchanged.

Implement `OpenDecrypted`:

```go
func (a *Store) OpenDecrypted(ctx context.Context, objectKey, keyB64 string) (*DecryptedObject, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 { return nil, errors.New("invalid key") }
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &a.bucket, Key: &objectKey})
	if err != nil { return nil, err }
	buffered := bufio.NewReader(out.Body)
	prefix, err := buffered.Peek(len(assetMagic))
	if err != nil { out.Body.Close(); return nil, err }
	if string(prefix) == assetMagic {
		return openChunked(&bufferedReadCloser{Reader: buffered, Closer: out.Body}, key)
	}
	// Legacy: bounded full read, nonce split, one-shot GCM Open, bytes.Reader result.
}
```

Read at most `maxAssetPlaintext + 12 + 16 + 1` bytes for the legacy path and reject overflow. Close the S3 body on every constructor error. Keep `FetchAndDecrypt` temporarily as a compatibility wrapper over `OpenDecrypted` and `io.ReadAll`, then remove it after `/raw` is wired.

- [ ] **Step 4: Run all asset tests GREEN**

Run: `go test ./internal/assets -v`

- [ ] **Step 5: Commit store integration**

```bash
git add internal/assets/assets.go internal/assets/assets_test.go
git commit -m "feat: store streamable generated assets"
```

---

### Task 3: Stream the Raw Image Endpoint

**Files:**
- Modify: `internal/web/web.go`
- Modify: `internal/web/viewer.go`
- Create: `internal/web/viewer_test.go`

**Interfaces:**
- Consumes: `assets.DecryptedObject` and `(*assets.Store).OpenDecrypted` from Task 2.
- Produces: `GET /raw?o=<objectKey>&k=<key>` returning raw PNG bytes with incremental flushes; `/view` is freed for the browser shell in Task 4.

- [ ] **Step 1: Write failing raw-handler tests with a narrow fake**

Add a `decryptedAssetOpener` interface to the wished-for test API and a fake returning `assets.DecryptedObject`. Test successful output, explicit `Content-Length`, `image/png`, `nosniff`, CSP, and `private, max-age=86400, immutable`. Use a recording response writer implementing `http.Flusher` and a two-part reader to assert at least one flush occurs before the reader returns its terminal error. Test invalid object paths and opener errors both omit secrets and return the current generic message.

```go
type decryptedAssetOpener interface {
	OpenDecrypted(context.Context, string, string) (*assets.DecryptedObject, error)
}

func TestRawStreamsDecryptedImage(t *testing.T) {
	opener := fakeOpener{object: &assets.DecryptedObject{
		Body: io.NopCloser(bytes.NewReader(testPNG)), Size: int64(len(testPNG)), Chunked: true,
	}}
	h := &Handlers{viewerAssets: opener}
	w := newFlushRecorder()
	h.handleRaw(w, httptest.NewRequest(http.MethodGet, "/raw?o=assets/u/id&k=secret", nil))
	if !bytes.Equal(w.Body.Bytes(), testPNG) { t.Fatal("raw body differs") }
	if w.flushes == 0 { t.Fatal("raw response was never flushed") }
}
```

- [ ] **Step 2: Run raw-handler tests and verify RED**

Run: `go test ./internal/web -run 'TestRaw' -v`

Expected: `viewerAssets`, `handleRaw`, and `/raw` do not exist.

- [ ] **Step 3: Implement and register `/raw`**

Keep the concrete `assets *assets.Store` field for dashboard operations and add `viewerAssets decryptedAssetOpener`, initialized from the same store in `web.New`. Move the current query validation into `handleRaw`, call `OpenDecrypted`, and only set success headers after it returns (the first record is authenticated by then).

```go
func (h *Handlers) handleRaw(w http.ResponseWriter, r *http.Request) {
	objectKey, keyB64 := r.URL.Query().Get("o"), r.URL.Query().Get("k")
	if h.viewerAssets == nil { http.Error(w, "asset storage is not configured", http.StatusServiceUnavailable); return }
	if !validAssetKey(objectKey) { http.Error(w, "bad asset reference", http.StatusBadRequest); return }
	opened, err := h.viewerAssets.OpenDecrypted(r.Context(), objectKey, keyB64)
	if err != nil { http.Error(w, "could not decrypt this asset (wrong or missing key)", http.StatusBadRequest); return }
	defer opened.Body.Close()
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.FormatInt(opened.Size, 10))
	w.Header().Set("Cache-Control", "private, max-age=86400, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	// Read, write, and Flush each authenticated chunk; stop on read/write error.
}
```

Log only `[raw] stream failed after response started` for late failures. Register `/raw`; do not log query parameters. Remove the obsolete `FetchAndDecrypt` wrapper after all callers move.

- [ ] **Step 4: Run web and asset tests GREEN**

Run: `go test ./internal/web ./internal/assets -v`

- [ ] **Step 5: Commit the raw endpoint**

```bash
git add internal/assets/assets.go internal/web/web.go internal/web/viewer.go internal/web/viewer_test.go
git commit -m "feat: stream decrypted images from raw endpoint"
```

---

### Task 4: Add the Direct Browser Viewer and Scoped Storage CORS

**Files:**
- Create: `internal/assets/cors.go`
- Create: `internal/assets/cors_test.go`
- Modify: `internal/assets/assets.go`
- Modify: `internal/web/viewer.go`
- Modify: `internal/web/viewer_test.go`
- Modify: `internal/app/app.go`

**Interfaces:**
- Consumes: the chunk format constants and the configured public/storage origins.
- Produces: `(*Store).AssetOrigin() string`, `(*Store).ConfigureViewerCORS(context.Context, string) error`, a cacheable `/view` shell, and a browser decoder for both encrypted formats.

- [ ] **Step 1: Write failing CORS merge and viewer-shell tests**

Test a pure `mergeViewerCORS([]types.CORSRule, origin)` helper: replace the rule whose ID is `pintr-browser-viewer`, preserve other rules byte-for-byte, and append exactly one rule allowing only `GET` from the normalized Pintr origin with a 3600-second max age.

Test `/view` without query parameters and require HTML, `public, max-age=3600`, `Referrer-Policy: no-referrer`, a CSP whose `connect-src` is exactly the asset origin, and no asset URL/key/raw URL in the body. Assert the static script reads `u`, `k`, and `r` from `location.hash`, calls `fetch(u)`, supports `PINTRC01`, uses `crypto.subtle.decrypt`, and sets the fallback anchor from `r`.

- [ ] **Step 2: Run viewer/CORS tests and verify RED**

Run: `go test ./internal/assets ./internal/web -run 'TestMergeViewerCORS|TestViewServesBrowserDecryptor' -v`

Expected: the CORS helper and browser viewer do not exist; current `/view` rejects missing query parameters.

- [ ] **Step 3: Implement origin tracking and best-effort CORS merging**

Store the normalized origin selected by `PINTR_S3_PUBLIC_BASE` or
`PINTR_S3_ENDPOINT` in `Store.assetOrigin`. Implement `AssetOrigin` and
`ConfigureViewerCORS`. `GetBucketCors` errors with code
`NoSuchCORSConfiguration` mean an empty existing rule list; other errors return
without writing. Filter only the stable Pintr rule ID, append the replacement,
and call `PutBucketCors` with all preserved rules.

```go
var viewerRuleID = aws.String("pintr-browser-viewer")

func viewerCORSRule(origin string) types.CORSRule {
	return types.CORSRule{
		ID: viewerRuleID, AllowedMethods: []string{http.MethodGet},
		AllowedOrigins: []string{origin}, MaxAgeSeconds: aws.Int32(3600),
	}
}
```

In `ServeHTTP`, call `ConfigureViewerCORS(context.Background(), publicURL)` once before starting the janitor. Log only the provider error, never URLs containing signatures.

- [ ] **Step 4: Implement the cacheable browser/WebCrypto viewer**

Replace `handleView` with a static HTML handler. Build CSP from a normalized asset origin plus SHA-256 hashes of the static inline script/style:

```go
w.Header().Set("Content-Type", "text/html; charset=utf-8")
w.Header().Set("Cache-Control", "public, max-age=3600")
w.Header().Set("Referrer-Policy", "no-referrer")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("Content-Security-Policy", viewerCSP(h.assetOrigin))
_, _ = io.WriteString(w, viewerHTML)
```

The JavaScript must bound ciphertext/plaintext at 64 MiB plus format overhead, decode standard base64 keys, implement both `nonce || ciphertext || tag` legacy decryption and `PINTRC01` record decryption with header/index AAD, require exact record consumption, create an `image/png` blob URL, revoke it on unload, and expose only fixed error messages. It must never interpolate fragment values into HTML; assign the raw fallback through the anchor's `href` property.

- [ ] **Step 5: Run browser/CORS tests GREEN**

Run: `go test ./internal/assets ./internal/web ./internal/app -v`

- [ ] **Step 6: Commit the browser fast path**

```bash
git add internal/assets/assets.go internal/assets/cors.go internal/assets/cors_test.go internal/web/viewer.go internal/web/viewer_test.go internal/app/app.go
git commit -m "feat: deliver browser images directly from storage"
```

---

### Task 5: Publish Separate Browser and Raw URLs

**Files:**
- Modify: `internal/mcpserver/mcpserver.go`
- Modify: `internal/mcpserver/handlers.go`
- Modify: `internal/mcpserver/mcpserver_test.go`

**Interfaces:**
- Consumes: stored ciphertext URL/object key/key and the `/view` and `/raw` contracts.
- Produces: `browser_view_url`, `decrypted_asset_url`, `rawAssetURL`, and `browserViewURL`.

- [ ] **Step 1: Write failing URL/result tests**

Add a `BrowserViewURL string \`json:"browser_view_url,omitempty"\`` field to the expected API in tests. Require `rawAssetURL` to produce `/raw?o=...&k=...`. Parse the `browserViewURL` fragment with `url.ParseQuery` and require exact `u`, `k`, and `r` values while asserting the server-visible query is empty.

Update `TestHostedCallResultCarriesJSON` to require both fields and note text that tells browsers to use `browser_view_url` and agents/raw clients to use `decrypted_asset_url`.

- [ ] **Step 2: Run MCP tests and verify RED**

Run: `go test ./internal/mcpserver -run 'TestDeliveryURLs|TestHostedCallResultCarriesJSON|TestGenerateImageToolPerMode' -v`

Expected: browser field/helpers do not exist and current raw URL still uses `/view`.

- [ ] **Step 3: Implement URL construction and result copy**

```go
func rawAssetURL(publicURL, objectKey, keyB64 string) string {
	q := url.Values{"o": {objectKey}, "k": {keyB64}}
	return strings.TrimRight(publicURL, "/") + "/raw?" + q.Encode()
}

func browserViewURL(publicURL, ciphertextURL, keyB64, rawURL string) string {
	fragment := url.Values{"u": {ciphertextURL}, "k": {keyB64}, "r": {rawURL}}
	return strings.TrimRight(publicURL, "/") + "/view#" + fragment.Encode()
}
```

Add `BrowserViewURL` to `generateImageResult`. In `HostedGenerate`, construct the raw URL once, assign it to `DecryptedAssetURL`, and construct `BrowserViewURL` from the presigned ciphertext URL, key, and raw URL. Update hosted tool prose and the content note without changing stdio output.

- [ ] **Step 4: Run MCP tests GREEN**

Run: `go test ./internal/mcpserver -v`

- [ ] **Step 5: Commit result contract changes**

```bash
git add internal/mcpserver/mcpserver.go internal/mcpserver/handlers.go internal/mcpserver/mcpserver_test.go
git commit -m "feat: expose fast browser and raw image URLs"
```

---

### Task 6: Documentation, Version, and Full Verification

**Files:**
- Modify: `README.md`
- Modify: `internal/web/llms.txt`
- Modify: `internal/web/static.go`
- Modify: `internal/mcpserver/mcpserver.go`

**Interfaces:**
- Consumes: final browser/raw URL contract and chunked storage format.
- Produces: accurate public documentation and MCP version `0.3.0`.

- [ ] **Step 1: Write the documentation/version assertions**

Extend an existing MCP tool test to assert `Version == "0.3.0"`. Add route smoke assertions that `/view` and `/raw` remain disallowed in `robots.txt`. These fail against the current version and current robots content.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `go test ./internal/mcpserver ./internal/web -run 'TestVersion|TestRobots' -v`

Expected: version remains `0.2.0` and `/raw` is absent from robots rules.

- [ ] **Step 3: Update public documentation and version**

Set `Version` to `0.3.0`. In README and `llms.txt`, document:

- `browser_view_url` for the direct-storage WebCrypto viewer;
- `decrypted_asset_url` as the streamed `/raw` PNG for agents;
- `/view` and `/raw` endpoint behavior;
- the `PINTRC01` chunked AES-GCM layout for generated images and legacy 24-hour compatibility;
- private immutable raw caching and no plaintext server/CDN cache;
- storage CORS requirement and the best-effort startup configuration;
- updated decryption examples that understand the chunked format rather than assuming a single leading nonce.

Add `Disallow: /raw` beside `/view` in `internal/web/static.go`.

- [ ] **Step 4: Format and run the complete verification suite**

Run:

```bash
gofmt -w internal/assets internal/web internal/mcpserver internal/app
go test ./...
go vet ./...
go test ./internal/assets -run '^$' -bench BenchmarkChunkedRoundTrip -benchmem
git diff --check
```

Expected: all tests pass, vet exits zero, benchmark reports all three sizes, and diff check is empty.

- [ ] **Step 5: Review the final diff against the design**

Confirm every spec requirement maps to code/tests: direct browser storage fetch, first-record raw streaming, legacy compatibility, scoped CORS preservation, secret-free errors/logs, private-only raw caching, both MCP URLs, reference-upload non-change, and public docs. Search for stale claims:

```bash
rg -n 'GET /view\?o=|/view\?o=|12-byte nonce is the first|Always open `decrypted_asset_url`' README.md internal docs --glob '!docs/superpowers/plans/2026-08-01-fast-image-delivery.md'
```

Expected: no stale runtime/public documentation matches outside historical design documents.

- [ ] **Step 6: Commit final documentation**

```bash
git add README.md internal/web/llms.txt internal/web/static.go internal/mcpserver/mcpserver.go internal/web internal/assets internal/app
git commit -m "docs: explain fast encrypted image delivery"
```
