# Fast Image Delivery Design

## Goal

Make generated images open as quickly as possible in browsers and raw-image
clients without weakening encryption at rest or retaining plaintext on the
server. Browser delivery should avoid the Pintr proxy entirely. Raw delivery
must begin returning authenticated image bytes before the complete encrypted
object has downloaded from storage.

## Existing Bottleneck

The current `/view` handler downloads the complete AES-256-GCM object from
S3-compatible storage, buffers up to 64 MiB, authenticates and decrypts the
whole payload, and only then writes the PNG. The storage-to-server and
server-to-client transfers therefore run sequentially. `private, no-store`
also forces every open to repeat that work.

The optimization must retain these properties:

- generated objects contain ciphertext only;
- every generated image has a fresh random 256-bit key;
- keys are returned to the caller and are not persisted by Pintr;
- an unauthenticated plaintext chunk is never sent;
- existing generated images remain readable until their normal 24-hour expiry;
- raw clients continue to receive an ordinary image response.

## Public Result and Endpoint Contract

Hosted generation results add `browser_view_url` and retain all existing
fields. Delivery becomes:

- `browser_view_url` points to `/view` and carries the ciphertext URL, key, and
  raw fallback URL in the URL fragment. `/view` serves a small, cacheable
  HTML/WebCrypto viewer. Because fragments are not sent in HTTP requests,
  Pintr does not receive those values when it serves the viewer shell.
- `decrypted_asset_url` points to `/raw?o=...&k=...`. It remains the URL agents
  and other raw-image consumers should open and returns the decrypted image
  directly.
- `asset_url` remains the presigned ciphertext URL, and `decryption_key`
  remains the one-time AES key for callers that handle decryption themselves.

The tool description and result note will direct humans to `browser_view_url`
and raw-image clients to `decrypted_asset_url`. `/view` no longer serves raw
bytes; `/raw` owns that behavior.

## Browser Fast Path

`/view` returns a static page with no request-specific data. It is safe to
cache publicly for one hour and keeps its existing restrictive CSP, expanded
only for the configured asset origin. Its script:

1. reads `u` (the presigned ciphertext URL), `k` (the key), and `r` (the raw
   fallback URL) from the fragment;
2. downloads the ciphertext directly from object storage;
3. detects the legacy or chunked encrypted format;
4. authenticates and decrypts it with WebCrypto;
5. displays the resulting PNG through a blob URL;
6. shows a concise error and a link to the raw endpoint when direct delivery
   fails.

The storage bucket must allow browser `GET` requests from the configured Pintr
origin. Pintr will install a narrowly scoped CORS rule at startup on a
best-effort basis and log a clear warning if the storage provider or credentials
do not permit it. Existing unrelated CORS rules must be preserved. A CORS
failure affects only the browser fast path; `/raw` remains functional.

The fragment values must never be copied into logs, analytics, HTML responses,
or server-side redirects.

## Chunked Encrypted Object Format

New generated assets use a versioned chunked format. Reference uploads remain
on the existing whole-object format because they are not served through the
viewer and changing them would not improve display latency.

The binary header contains:

- an eight-byte magic/version marker;
- the plaintext length as an unsigned 64-bit big-endian value;
- the plaintext chunk size as an unsigned 32-bit big-endian value;
- a random eight-byte nonce prefix.

The initial chunk size is 64 KiB. For chunk index `i`, the 12-byte AES-GCM nonce
is the random eight-byte prefix followed by `i` as an unsigned 32-bit
big-endian value. Each encrypted record contains at most 64 KiB of plaintext
plus the GCM authentication tag. Even an empty plaintext has one authenticated
empty record, so the header is always authenticated. The complete header and
chunk index are the record's additional authenticated data. Lengths are
derived from the header, so records need no separate length field.

This structure authenticates the format metadata, chunk position, and every
plaintext byte. The decoder rejects invalid magic, unsupported versions,
impossible sizes, nonce counter overflow, truncated records, trailing bytes,
and authentication failures. The existing 64 MiB plaintext limit remains.

Objects without the new marker are legacy `nonce || ciphertext || tag` blobs
and use the existing full-buffer decoder. Because generated objects expire
after 24 hours, this compatibility path naturally disappears from active use.

## Raw Streaming Path

`/raw` validates the object reference and key exactly as `/view` does today,
then opens the storage object and examines its header.

For a chunked object the asset layer parses the header and authenticates the
first record before returning a decrypted `io.ReadCloser` and the plaintext
length. The handler can therefore reject malformed objects or incorrect keys
before committing an HTTP success response. It then sets `Content-Type:
image/png`, `Content-Length`, and security headers, repeatedly reads one
authenticated plaintext chunk, writes it, and flushes it. This overlaps the
storage-to-Pintr and Pintr-to-client transfers and makes time-to-first-byte
depend on only the first encrypted chunk rather than the complete image. If a
later chunk is corrupt, the response ends immediately; no bytes from that
corrupt chunk are emitted.

Legacy objects are fully buffered and decrypted before headers are committed,
matching current behavior. Both paths return the same generic error before a
response starts so missing objects and incorrect keys do not become an oracle.

Successful raw responses use `Cache-Control: private, max-age=86400,
immutable`. The URL is unique to one immutable object and key, so repeat opens
can use the client's private cache. Shared/CDN plaintext caching remains
disabled. No plaintext is retained in a Pintr process after the request.

## Components and Boundaries

- `internal/assets` owns the binary format, encryption, format detection,
  legacy compatibility, and streaming decryption. Its streaming API returns a
  decrypted `io.ReadCloser` plus trusted metadata after authenticating the
  first record, keeping HTTP concerns out of storage code.
- `internal/web` owns `/view` and `/raw`, response headers, flushing, viewer
  HTML, and user-facing errors. The asset dependency is represented by the
  smallest interface needed by these handlers so they can be tested without a
  live bucket.
- `internal/mcpserver` constructs both delivery URLs and documents which one
  each client should use.
- `internal/app` supplies the public origin for viewer CSP/CORS setup and
  registers both routes.

## Error Handling

Before response headers are committed, `/raw` maps missing objects, malformed
keys, invalid formats, and authentication failures to the same generic error.
After streaming starts, HTTP status cannot change; any subsequent read or
authentication failure stops the response and is logged without including the
object key, key, or signed URL.

The browser viewer distinguishes missing fragment data, download/CORS failure,
unsupported format, authentication failure, and non-image output without
displaying secret values. It always offers the raw URL as a fallback.

## Testing and Performance Evidence

Tests will be written before implementation and cover:

- deterministic round trips across empty, partial, exact, and multi-chunk
  boundaries;
- rejection of header, ordering, truncation, trailing-data, and tag corruption;
- legacy object compatibility;
- proof that the streaming decoder writes the first plaintext chunk before it
  reaches EOF on the encrypted input;
- `/view` fragment secrecy, CSP, caching, and viewer error behavior;
- `/raw` content type, length, security/cache headers, generic pre-stream
  errors, and streamed output;
- generation-result URL construction and compatibility fields;
- CORS merging that preserves unrelated rules.

A focused benchmark will report chunked encryption/decryption throughput and
allocations for representative PNG sizes. The acceptance criterion is
architectural rather than dependent on external network conditions: for new
objects, `/raw` must emit authenticated plaintext after reading at most the
header plus one encrypted 64 KiB record, and browser delivery must fetch image
bytes directly from the asset origin rather than through Pintr.

## Out of Scope

- plaintext server or CDN caches;
- changing the one-key-per-image or 24-hour retention model;
- migrating already stored objects;
- changing reference-upload encryption;
- deploying a provider-specific edge worker.
