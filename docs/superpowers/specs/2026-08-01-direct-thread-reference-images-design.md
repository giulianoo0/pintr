# Direct Thread Reference Images

Date: 2026-08-01  
Status: approved for implementation

## Goal

Let users supply reference images while staying inside ChatGPT or Claude.ai/Claude Desktop. ChatGPT should hand an attached image directly to `generate_image`. Claude should transfer an attached image from its code-execution sandbox through a short-lived, server-issued upload URL, without asking the user to copy a path, bearer token, or base64 payload.

The hosted server will have exactly two ingestion lanes because the hosts expose different capabilities:

1. ChatGPT's documented `_meta["openai/fileParams"]` extension.
2. A signed, one-time upload bridge for Claude.ai/Claude Desktop.

Core MCP does not yet define portable client-to-server file inputs. The active MCP file-transfer work remains draft, so pretending that one standard attachment schema works in both hosts would make the Claude flow unreliable.

## Scope

This change covers hosted reference-image ingestion and its public documentation. It keeps image generation, ChatGPT account selection, generated-image encryption, output delivery, and retention unchanged.

The local stdio server remains supported and keeps its local-path reference behavior. A local path is not an upload strategy in stdio mode: the MCP server and caller share a machine. The remote ChatGPT and Claude tools will not accept local paths.

## Hosted Tool Contract

### `generate_image`

Keep:

- `prompt`: required text prompt.
- `reference_images`: optional `ref_` tokens produced by the Claude upload bridge. These remain reusable for one hour and never contain image bytes in MCP context.

Add:

- `reference_image_files`: optional array of ChatGPT file objects. The tool descriptor marks this top-level field with `_meta["openai/fileParams"]`.

Each file object declares:

```json
{
  "download_url": "required temporary HTTPS URL",
  "file_id": "required ChatGPT file identifier",
  "mime_type": "optional MIME type",
  "file_name": "optional original name"
}
```

ChatGPT populates the array from attachments. Pintr downloads every temporary URL during the same tool call, validates the bytes, converts them to the existing upstream data-URL representation in server memory, and does not persist the input.

### `request_reference_upload`

Add a hosted-only MCP tool with:

- `filename`: required display name.
- `mime_type`: required supported image MIME type.
- `size_bytes`: required exact byte count, capped at 10 MiB.

The result contains:

- `upload_url`: an HTTPS `PUT` URL on the pintr origin.
- `upload_id`: an opaque identifier useful for diagnostics.
- `expires_in`: 300 seconds.
- `max_size_bytes`: the server limit.
- concise instructions telling Claude to upload the attached sandbox file and use the returned `ref` in `generate_image.reference_images`.

The tool never accepts a local path. Claude discovers the sandbox path itself, calls this tool, and runs the returned upload using its code-execution environment. Users must allow the pintr origin under Claude's code-execution “Additional allowed domains” setting.

## Data Flow

### ChatGPT

1. User attaches one or more images and asks for generation or editing.
2. ChatGPT authorizes the files and fills `reference_image_files` with temporary descriptors.
3. Pintr downloads each image immediately through a bounded, SSRF-safe HTTPS client.
4. Pintr validates size and detected image type.
5. Pintr converts the bytes to data URLs in memory and sends the existing Codex image request.

There is no `/upload`, local path, base64 tool argument, object-storage write, or `ref_` token in this lane.

### Claude.ai / Claude Desktop

1. User attaches an image. Claude places it in its code-execution sandbox.
2. Claude calls `request_reference_upload` with metadata only.
3. Pintr returns a five-minute HMAC-signed `PUT` URL.
4. Claude uploads the file from its sandbox directly to that URL.
5. The endpoint validates and encrypts the image, stores only ciphertext, and returns a reusable one-hour `ref_` token.
6. Claude passes the token to `generate_image.reference_images`.

Only the short token enters model context. The image bytes move over HTTPS outside MCP tool arguments.

## Upload Authorization and Storage

The upload URL contains an authenticated token carrying:

- a random upload ID;
- the authenticated pintr user ID;
- expected filename, MIME type, and byte count;
- an expiry timestamp.

The token is authenticated with HMAC-SHA256 using `PINTR_SECRET`. The endpoint rejects malformed signatures, expired tokens, unsupported image types, size mismatches, and oversized bodies.

The upload ID becomes the object ID. Storage uses a conditional create so the signed URL is single-use even across multiple server processes. The existing AES-256-GCM reference encryption and one-hour janitor remain in place. The returned `ref_` token continues to carry the decryption key; logs expose only its public ID segment.

The legacy bearer-authenticated `POST /upload` endpoint is removed. It is replaced by the narrow signed `PUT` endpoint, which grants permission only to create one bounded reference object for one user before expiry.

## Remote Download Security

ChatGPT's `download_url` is still untrusted tool input at the server boundary. The downloader must:

- accept HTTPS only;
- reject credentials and malformed hosts;
- resolve DNS and reject loopback, private, link-local, multicast, and unspecified addresses;
- pin the validated destination for the connection;
- re-run validation for every redirect;
- enforce timeouts and a 10 MiB response limit;
- accept only detected PNG, JPEG, WebP, or GIF content.

Pintr consumes temporary URLs immediately and does not assume a numeric ChatGPT URL lifetime or a backend refresh API for `file_id`.

## Errors and Recovery

- Missing Claude domain allowlist: return instructions naming the exact setting and origin to allow.
- Expired upload URL: Claude calls `request_reference_upload` again.
- Reused upload URL: return a conflict and tell Claude to request a new URL.
- Size or MIME mismatch: return an actionable validation error without storing an object.
- Expired `ref_`: tell Claude to repeat the upload bridge.
- Failed ChatGPT temporary download: tell ChatGPT to retry with the attachment; never fall back to a local path or inline base64.
- One bad reference prevents generation so the user never pays for a request made with incomplete inputs.

## Removed Hosted Strategies

- Manual bearer-token `POST /upload` instructions.
- Asking remote clients to pass filesystem paths.
- Inline base64 or `data:` values in MCP arguments.
- Mode-specific prose that teaches several competing upload procedures inside `generate_image`.

The encrypted reference object and `ref_` token remain only because Claude needs a portable side channel until MCP gains a supported file-input contract.

## Documentation and UI

Update README and hosted `llms.txt` to describe:

- direct ChatGPT attachment usage;
- Claude's automatic signed-upload flow;
- the one-time Claude domain allowlist requirement;
- five-minute upload URL and one-hour reference lifetimes;
- the fact that local stdio paths apply only to local clients.

Keep dashboard upload counts, purge controls, encryption language, and retention copy because Claude references still use encrypted temporary storage.

## Testing

Tests will cover:

- exact `openai/fileParams` metadata and the required file-object schema;
- hosted-only registration of `request_reference_upload`;
- token signing, tamper rejection, expiry, and metadata round trips;
- method, size, MIME, and single-use enforcement on the upload endpoint;
- SSRF rejection, redirect validation, response-size limits, and valid image downloads;
- ChatGPT file and Claude `ref_` references converging on the same upstream reference list;
- removal of legacy hosted `/upload` guidance while preserving stdio guidance;
- existing hosted result compatibility and dashboard behavior.

Full verification remains `go test ./...`, `go vet ./...`, `gofmt`, and `go build ./...`.

## Success Criteria

- In ChatGPT, an attached image reaches `generate_image` in one tool call without a manual upload.
- In Claude.ai/Desktop, the agent transfers an attached sandbox image and calls `generate_image` without asking the user for a path, token, or terminal command.
- No image bytes are emitted through model-authored MCP JSON.
- Reference inputs are size- and type-bounded, protected against SSRF, encrypted at rest when persisted, and automatically deleted.
- Existing prompt-only generation and generated-image delivery continue to work.
