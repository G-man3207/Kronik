# M25 streaming bodies: design

Status: accepted design for M25 (v0.5), 2026-11-13. It fixes what the implementation
slices of §18 build, so that none of them has to decide anything again. It
builds on [M1 core](m1-core.md), [M2 effects](m2-effects.md),
[M3 fork](m3-fork.md), [M6 storage](m6-storage.md),
[M8 privacy](m8-privacy.md) and [ADR 0070](../adr/0070-wasi-http-outgoing-handler.md).
The decisions are ADRs [0117](../adr/0117-blob-store.md) (the store),
[0118](../adr/0118-sealed-blob-identity.md) (identities and metadata),
[0119](../adr/0119-blob-reference-graph.md) (references),
[0120](../adr/0120-blob-gc-roots-and-leases.md) (collection),
[0121](../adr/0121-blob-interface-and-wasi-0-3.md) (the interface) and
[0122](../adr/0122-shipping-and-restoring-blobs.md) (shipping). ADR 0113 of
the M24 design (the v0.5 actor ABI) sets the rule both milestones follow:
v0.5 is `kronik:actor@0.1.1`, which grows only by new interfaces (and M24's
one optional export), each complete when it first appears. M26 ([blob storage for apps](m26-blobs.md)) completes ownership,
collection, privacy and shipping; both milestones land before v0.5.0.

## 1. Scope

The brief's M25 bullets, as requirements:

| | Requirement |
| --- | --- |
| R1 | Bodies above a threshold, 1 MiB by default, are stored content-addressed in the blob store; the log holds only the hash and the size. |
| R2 | An upload is streamed into the blob store before the turn starts, so the turn sees a complete body with a known hash. |
| R3 | An `http.fetch` response above the threshold is streamed to the blob store and the guest gets a handle; a large outgoing request body is given as a handle and streamed from the store; the recording holds only the hash, so replay gives the same blob. |
| R4 | A reference from an HTTP body or an effect result is borrowed: read access during the turn; the blob then lives as long as a log record within retention references it. A reference the actor has not received or created during the turn gives `BLOB_NOT_HELD`, even with the right hash. |
| R5 | The guest reads a large body in chunks through a handle, lazily, so replay fetches only what the guest reads. |
| R6 | Large responses are written to the store during the turn and streamed to the client after commit. Streaming while the turn works is SSE or `send-now` (M24). |

Acceptance criteria (the brief's, numbered for §17):

1. A 300 MB upload is received with constant memory and appears to the actor
   as a handle with hash and size.
2. An `http.fetch` of a 40 MB PDF is streamed to the blob store with constant
   memory, the guest gets a handle, and replay gives the same hash.
3. The log holds only the hash for bodies above the threshold, and replay
   reads the same bytes from the blob store.
4. A 1 GB response is streamed with constant memory.
5. A reference the actor has not received or created during the turn, for
   example a hash from an earlier turn, gives `BLOB_NOT_HELD`.

Outside M25: owning blobs (`put`, `retain`, `release`), blobs in messages,
collection of every root, privacy and the full shipping story are M26. Range
requests answered by the gateway, operator uploads through the API and blobs
in a cluster are outside v0.5 (§19).

## 2. Terms

| Term | Meaning |
| --- | --- |
| Inline body | Bytes inside the record (`Body.inline`), as before M25. |
| Blob body | `Body.blob`: a reference to a blob; the bytes are in the store. |
| Threshold | `Limits.blob_threshold_bytes`, per kind, 1 MiB by default. |
| Reads blobs | A component that imports `kronik:actor/blobs` (ADR 0119 §1). Only such a component gets blob bodies. |
| The turn's references, `T` | The references a turn may use (ADR 0119 §2): held ones (M26), those in its input, and those it obtained. |
| Borrowed | In `T` but not held: usable in this turn only. |
| Space | Where a blob is written: main's store, a fork's space, or an isolated replay's scratch space. |
| Lease | An in-memory root with an expiry, renewed by its holder (ADR 0120 §4). |

## 3. The paths at a glance

```text
upload:    client ─▶ gateway: route, M24 classification, body phase ──▶ spool ─▶ store
                                           │ (fsync, name, dir sync)          │
                                           └▶ root input with Body.blob ─▶ mailbox ─▶ turn
fetch:     turn ─▶ gate: TurnBegin ─▶ Net (stream) ─▶ scrub ─▶ spool ─▶ store ─▶ EffectResult ─▶ guest: blob-ref
request:   guest blob-ref ─▶ gate: check T, record ref ─▶ Net streams the body from the store
response:  guest writer ─▶ store ─▶ output::http(blob) ─▶ TurnRecord (fsync) ─▶ gateway streams from store
read:      guest blobs.get(ref, offset, len) ─▶ check T ─▶ store frames (lazy)
```

## 4. The `kronik-blob` crate

### 4.1 Interface

The crate depends on `kronik-core` (Env), `kronik-proto` (`BlobRef`),
`blake3`, `chacha20poly1305`, `crc32c`, `bytes`, `zeroize`, `thiserror` and
`tracing`; all are in the workspace. It holds no key and never reads
`keystore.db`.

```rust
/// "b3:<hex>" (no subject) or "b3s:<hex>" (keyed, ADR 0118).
pub struct BlobId { pub keyed: bool, pub digest: [u8; 32] }
impl BlobId {
    pub fn parse(s: &str) -> Result<BlobId, BlobError>;
    pub fn file_name(&self) -> String;                 // "b3-<hex>" or "b3s-<hex>"
    pub fn shard(&self) -> u8;                         // digest[0]
}
/// A complete reference (ADR 0118 §3).
pub struct BlobMeta { pub id: BlobId, pub size: u64, pub subject: Option<String>, pub key_version: u32 }
impl BlobMeta {
    pub fn to_pb(&self) -> pb::BlobRef;
    pub fn from_pb(r: &pb::BlobRef) -> Result<BlobMeta, BlobError>;   // validates ADR 0118 §3
}
/// Keys of one subject's blobs, from `Sealer::blob_keys` (§4.6).
pub struct BlobKeys {
    pub subject: String,
    pub key_version: u32,
    pub identity: Zeroizing<[u8; 32]>,          // K_id
    pub seal: Option<Zeroizing<[u8; 32]>>,      // the blob key derived from K(s, v), when privacy mode is on
}
/// Opens sealed frames: the blob key of (subject, version), or why not.
pub trait KeyAccess: Send + Sync {
    fn open_key(&self, subject: &str, version: u32) -> KeyAnswer;   // Found(blob key) | Erased | Missing
}
pub enum Space { Main, Fork(String), Scratch(PathBuf) }

pub struct BlobStore { /* env, paths, claim lock, dirty shards, leases, reserve */ }
impl BlobStore {
    /// Creates the layout if missing, syncs the 256 shard directories,
    /// deletes tmp/ (ADR 0117 §4.4).
    pub async fn open(env: Env, data_dir: &Path, cfg: StoreConfig) -> Result<Arc<BlobStore>, BlobError>;
    pub async fn writer(self: &Arc<Self>, space: Space, keys: Option<BlobKeys>, lease: Lease)
        -> Result<BlobWriter, BlobError>;
    pub async fn reader(&self, space: &Space, meta: &BlobMeta, keys: &dyn KeyAccess)
        -> Result<BlobReader, BlobError>;
    /// One sync_dir per dirty shard directory holding `ids` (ADR 0117 §4.3).
    pub async fn ensure_durable(&self, ids: &[BlobId]) -> Result<(), BlobError>;
    pub fn leases(&self) -> &Leases;
    /// Free bytes when below `[blobs] disk_reserve`, else None.
    pub fn below_reserve(&self) -> Option<u64>;
    pub async fn delete_space(&self, space: &Space) -> Result<(), BlobError>;
    /// M26: the sweep and erasure (m26-blobs §6, §9).
    pub async fn sweep(&self, roots: &dyn Roots, opts: SweepOptions) -> Result<SweepReport, BlobError>;
    pub async fn delete(&self, ids: &[BlobId]) -> Result<u64, BlobError>;
}
impl BlobWriter {
    pub async fn write(&mut self, chunk: &[u8]) -> Result<(), BlobError>;  // checks the limit and the reserve
    pub fn written(&self) -> u64;
    /// Header, sync_data, rename or claim (ADR 0117 §4.2, §6).
    pub async fn finish(self) -> Result<BlobMeta, BlobError>;
}
impl BlobReader {
    pub fn meta(&self) -> &BlobMeta;
    /// Up to `len` bytes from `offset`, reading and checking only the frames touched.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes, BlobError>;
    /// Sequential frames from `offset`, for the gateway and the shipper.
    pub fn frames(self, offset: u64) -> BlobFrames;
}
pub enum BlobError {
    NotFound(BlobId), Corrupt { id: BlobId, why: String }, StoreFull { free: u64, reserve: u64 },
    Erased, KeyMissing, TooLarge { limit: u64 }, Invalid(String), Io(String),
}
```

`StoreConfig { reserve: u64, max_blob: u64 }`. Errors map to codes in §14:
`Corrupt` is `STORAGE_CORRUPT`, `NotFound` of a committed reference is
`BLOB_MISSING`, `StoreFull` is `BLOB_STORE_FULL`, `Erased` is
`SUBJECT_ERASED`.

### 4.2 Layout and format

As [ADR 0117](../adr/0117-blob-store.md) §1–§3: `<data>/blobs/objects/<2
hex>/<name>`, a 512-byte header, frames of 64 KiB with a CRC32C (plain) or an
AEAD tag (sealed). A fork's space is `<data>/branches/<fork>/blobs/`, an
isolated replay's scratch space `<data>/branches/<fork>/blobs/scratch/<tree>/`.

### 4.3 Writing and durability

The write protocol is ADR 0117 §4. Who calls `ensure_durable`, and when:

| Record appended | Blobs it references | Caller |
| --- | --- | --- |
| `TurnBegin` (an upload's input) | the request body | the gateway, when the spool finishes, before admission |
| `EffectResult` | request and response bodies | the effect gate, before `record()` |
| `TurnRecord` | input, output, effects, messages, timers, `blob_refs` | `Node::commit` of a turn record: the turn's created blobs |
| `StateRebase` turn parts (M13) | the rebased turns' references | rebase staging, after it copied every fork-space blob the turns reference into main's store |

A rebased turn may reference blobs in the rebase fork's space; staging copies
them into main's store (reader to writer, same identity) before it appends,
because the fork's space is deleted with the fork.

### 4.4 Reading

`reader` opens the object in the given space, then in main's store; checks
the header; `read_at` reads only the touched frames. A sealed file needs
`KeyAccess::open_key`: `Erased` gives `BlobError::Erased`, `Missing` gives
`KeyMissing` (`KEYSTORE_INCOMPLETE` at the API, a host failure in a turn, as
for sealed values today).

### 4.5 Spaces

| Writer | Space |
| --- | --- |
| main's turns, main's gateway | `Main` |
| a fork's continuous replay, catch-up, `send_to_fork`, a preview's requests | `Fork(name)` |
| one root input's tree in isolated replay | `Scratch`, deleted when the tree's result is merged |
| `kronik upgrade check` | `Scratch` under `--scratch-dir` (default the system temporary directory), never the data directory |

### 4.6 Keys

`kronik-privacy` adds:

```rust
impl Keystore {
    /// The subject's oldest key version that is not erased, created (after
    /// the erasure floor) when there is none: the identity version (ADR 0118).
    pub fn identity_key(&self, subject: &str, fresh: [u8; 32], nonce: [u8; 24], wall_ms: u64)
        -> Result<SubjectKey, PrivacyError>;
}
impl Sealer {
    /// K_id and, when the mode is on, the sealing key of that version.
    pub fn blob_keys(&self, subject: &str, fill: Fill<'_>, wall_ms: u64) -> Result<BlobKeys, PrivacyError>;
    /// `KeyAccess` for readers: the key of an exact version, never created.
    pub fn blob_key_access(&self) -> impl KeyAccess + '_;
}
```

Both go through the existing revision-bound key cache. `Sealer::plain()`
(tests, the simulator) derives `K_id` from a fixed test key and the subject;
a production node without a keystore refuses a blob with a subject
(`KEYSTORE_INCOMPLETE`).

### 4.7 A full store

As ADR 0117 §9: the gateway refuses a body that would become a blob with 503
`BLOB_STORE_FULL`; a turn whose blob write hits the reserve is abandoned
without a record and retried in place by the actor's worker; an effect
response that cannot be stored is treated like a crash after the request
left. The worker loop (`Node::worker`) gains the retry: on the internal error
`BLOB_STORE_FULL` it sleeps with backoff (100 ms doubling to 30 s) and runs
the job again, as a re-run from its `TurnBegin` and `open_effects` when it
wrote one, else unchanged, while `kronik_blob_turn_retries_total` counts.

## 5. The WIT and the turn host

### 5.1 The interface

`wit/kronik-actor.wit` becomes `package kronik:actor@0.1.1`, adds the
`blobs` interface of [ADR 0121](../adr/0121-blob-interface-and-wasi-0-3.md)
§1 with `@since(version = 0.1.1)`, and `world actor` imports it. No existing
type or function changes: `blob-ref`, `message.blobs` and `http-body.blob`
are used as they are. The SDKs' WIT copies (`sdk/python/wit`, `sdk/go/wit`)
follow. `allowlist.rs` accepts `kronik:actor/blobs` at 0.1.x (its test that
refuses it flips). Wasmtime 50 resolves 0.1.0 imports and exports against
0.1.1 definitions in both directions, so one binding generation serves old
and new components.

| Function | M25 | M26 |
| --- | --- | --- |
| `get(blob, offset, len)` | works | works |
| `writer`: `constructor`, `write`, `finish` | works; the result is borrowed | works |
| `put(bytes)` | traps `NOT_IMPLEMENTED` | works; the actor holds the result |
| `retain(blob)`, `release(blob)` | trap `NOT_IMPLEMENTED` | work |

### 5.2 Semantics

- `get`: `len` 1 to 1 MiB, else `invalid`; a reference not in `T` is
  `not-held`; an erased subject's blob is `erased`. Returns
  `min(len, size - offset)` bytes, an empty list at or past the end.
- `writer`: the constructor records the default subject; `write` takes at
  most 1 MiB per call and fails with `quota-exceeded` when the bytes the turn
  created would pass `blob_bytes_per_actor`; `finish` makes the blob durable
  (ADR 0117 §4) and adds the reference to `T` as borrowed. A writer that is
  dropped or still open when the turn ends is discarded.
- Every function is denied in `describe` (it traps, like `state`).
- Bytes moved by `get` and `write` count against the turn's blob budget,
  `fuel × 64` bytes; exceeding it traps with `FUEL_EXHAUSTED`.
- A writer's bytes are scrubbed of the secret values the turn has revealed so
  far, with the stream scrubber of §7.4; a value revealed later cannot be in
  bytes written before the guest had it. A turn that revealed nothing pays
  nothing.

### 5.3 Who reads blobs

`kronik_runtime::Program` computes `reads_blobs()` when it is created: whether
the component imports `kronik:actor/blobs`. `Node`'s per-kind state keeps
it, and `RouteEntry` gains `blobs: Option<BodyLimits { threshold, upload }>`
(from the program and the limits of the current epoch) for the gateway.
Forks and replays use the flag of the code they run.

### 5.4 The turn's references

`kronik-runtime` defines the host side as a trait the scheduler and the fork
engine implement:

```rust
pub trait BlobHost: Send + Sync {
    fn get(&self, r: &BlobRefWit, offset: u64, len: u32) -> BoxFuture<'_, Result<Result<Vec<u8>, BlobErr>, GateError>>;
    fn open_writer(&self, subject: Option<String>) -> BoxFuture<'_, Result<WriterId, GateError>>;
    fn write(&self, w: WriterId, chunk: Vec<u8>) -> BoxFuture<'_, Result<Result<(), BlobErr>, GateError>>;
    fn finish(&self, w: WriterId) -> BoxFuture<'_, Result<Result<BlobRefWit, BlobErr>, GateError>>;
    fn drop_writer(&self, w: WriterId);
    /// Completes references the guest put into an output or a record;
    /// Err(the first one not in T).
    fn complete(&self, refs: &[BlobRefWit]) -> Result<Vec<pb::BlobRef>, BlobRefWit>;
    /// M26: put, retain, release, and the net operations at commit.
}
```

`TurnHost` holds `Option<Arc<dyn BlobHost>>` (none in `describe`). The
scheduler's implementation, `TurnBlobs` in `kronik-sched`, owns:

- `T` as a map from identity to complete metadata, seeded with the input's
  references (§5.5); held references (M26) are looked up in `blob_refs` on
  first use rather than loaded;
- the turn's lease (ADR 0120 §4), which covers `T` and every blob the turn
  created, until the turn's record is applied;
- open writers, the created bytes and the blob budget.

### 5.5 Bodies in and out of the guest

- **Input.** `input_to_wit` already maps `Body.blob` to `http-body::blob`;
  `TurnBlobs` adds the reference to `T` as borrowed.
- **Output.** `committed()` (runtime `turn.rs`) maps `http-body::blob(r)` to
  `Body.blob(complete(r))`; a reference not in `T` fails the turn: outcome
  `TRAP` with code `BLOB_NOT_HELD`. `http-body::inline` keeps its
  `message_bytes` limit.
- **`http-client.fetch`.** `FetchRequest.body` becomes
  `enum FetchBody { Inline(Vec<u8>), Blob(pb::BlobRef) }` (a complete
  reference, so `kronik-runtime` needs no dependency on `kronik-blob`); a
  `blob` request body
  not in `T` reaches the gate as a denial (§7.2). `FetchResponse.body`
  becomes the same enum; a `Blob` response is added to `T` and given to the
  guest as `http-body::blob`.
- **Messages.** Until M26, a message, timer, call or reply with `blobs`
  still traps with `NOT_IMPLEMENTED` (`check_message`).
- **Traps.** `classify_error` maps a host message starting with
  `BLOB_NOT_HELD` to outcome code `BLOB_NOT_HELD`, like `NOT_IMPLEMENTED`.

A component that does not read blobs never receives a blob body; if one
arrives anyway (a deployment switched to such code between admission and
turn start), the guest gets the `blob` variant it cannot read, which its SDK
reports as an error: documented, not prevented.

## 6. The gateway

### 6.1 The request path

The service function stays callable from the simulator. Its request and
response types change (`crates/kronik-gateway/src/body.rs`, owned by this
milestone; M24 adds one response variant):

```rust
pub enum RequestBody {
    Inline(Bytes),                     // the simulator, tests, small bodies
    Stream(Box<dyn BodySource>),       // hyper's Incoming, adapted in server.rs
}
pub enum ResponseBody {
    Inline(Vec<u8>),
    Blob(BlobBody),                    // streamed from the store after commit
    // Events(connections::sse::EventStream)   added by M24
}
```

`server.rs` no longer collects the body; it hands `Incoming` over as a
`BodySource` and turns a `ResponseBody` into one `http_body::Body`
implementation. The order of `Gateway::serve`:

1. Route match (404 without reading the body).
2. M24's classification: a WebSocket upgrade or an SSE route takes the
   connection path, which never reads a body.
3. `node.check_running()` (the log's reserve), before reading a byte.
4. The body phase (§6.2).
5. Admission (`Node::ingress`), the wait, the response (§6.5).

### 6.2 The body phase

For a kind that does not read blobs, the body is read into memory up to
`[gateway] max_body` exactly as today (413 above it).

For a kind that reads blobs (`RouteEntry.blobs = Some(limits)`):

1. A `content-length` above `upload_bytes` is 413 `PAYLOAD_TOO_LARGE` at
   once, naming the limit and the hint
   `kronik limits set <kind> --upload-size <size> --reason '...'`.
2. With an `Idempotency-Key`, the gateway first asks the node whether the key
   has a saved response or a turn in flight (`Node::ingress_peek`). If so, the
   body is only hashed, never spooled, and admission continues with that hash
   (§6.3).
3. Up to `threshold + 1` bytes are read into memory. A body that ends there
   is inline.
4. Otherwise, below the blob reserve the request is 503 `BLOB_STORE_FULL`.
   Else the gateway opens a writer in main's space (a preview's space for a
   preview request) with the request's subject (`privacy.subject_from`,
   known before the body) and its keys (§4.6), under an upload lease, writes
   what it read and streams the rest: each chunk as hyper delivers it, at
   most 64 KiB buffered, BLAKE3 of the plaintext computed on the way.
5. More than `upload_bytes` is 413 (the part file is deleted); no data for
   `[gateway] body_idle_timeout` (30 s) is 400 `BAD_REQUEST` ("the request
   body stopped arriving"); a client that goes away aborts the spool.
6. `finish` (fsync, name), then `ensure_durable`: the blob is durable before
   the input exists. The input's body is `Body.blob` with the complete
   reference; the upload lease goes into the job and ends when the turn's
   record is applied (a join or saved answer ends it at once, and the blob
   is loose).

The whole-body timeout of today (`BODY_TIMEOUT`, 30 s) keeps applying to
inline bodies; a spooled upload has the idle timeout instead, so a slow
300 MB upload is not cut off while bytes keep arriving.

### 6.3 Idempotency with large bodies

`HttpInput.request_hash` version 4 (`INGRESS_HASH_VERSION = 4`) hashes
`BLAKE3(body)` (32 bytes) where version 3 hashed the body itself; method,
path, query and requester are as before, keyed as before. The digest is the
same for an inline and a spooled body, so a retry matches whatever the
threshold says. Saved version-3 rows stay valid during their TTL: for an
inline body the gateway also computes the version-3 hash and passes it,
unrecorded, to `Node::ingress`, which matches a version-3 row with it. A
version-3 row never matches a blob body (none existed). After
`idempotency_ttl` no version-3 row is left.

### 6.4 Previews

A preview request whose actor reads blobs spools into the preview fork's
space: `PreviewRouter` gains `blob_space(id) -> Space`. The preview turn reads
it there; the space is deleted with the preview.

### 6.5 Streaming the response after commit

`turn_response` maps an `Outcome` whose HTTP body is `Body.blob` to
`ResponseBody::Blob`: before any header is sent, the gateway opens the
reader under a streaming lease (an erased blob is 410 `SUBJECT_ERASED`, a
missing one 500 `BLOB_MISSING`, both with the turn id), sets the length to
the blob's size, and streams frames as hyper polls: one 64 KiB frame in
memory at a time, decrypted when sealed. A frame that fails its check after
the headers went out aborts the connection (the client sees a short body).
The lease ends with the stream. A saved idempotent response with a blob body
streams the same way; its ingress row pins the blob (ADR 0120 §2). `HEAD`
and `kronik-turn-id` behave as for inline bodies. A prefix preview keeps its
header filter and sandbox.

### 6.6 The simulator

The DST harness calls `Gateway::handle` with `RequestBody::Inline` or with a
`BodySource` that yields seeded chunks, and reads `ResponseBody::Blob`
through the same frames, so the spool, the admission and the streaming run
under the simulated disk.

## 7. Effects

### 7.1 Streaming in `Net`

`kronik_core::env` gains streaming next to the buffered calls, with a default
implementation that buffers (so test nets keep working):

```rust
pub enum HttpBody { Bytes(Bytes), Stream { len: u64, source: Box<dyn BodySource> } }
pub trait BodySource: Send + 'static {
    /// The next chunk, None at the end.
    fn next(&mut self) -> BoxFuture<'_, io::Result<Option<Bytes>>>;
}
pub struct HttpStreamRequest { pub method: String, pub url: String, pub headers: Vec<(String, String)>, pub body: HttpBody }
pub struct HttpStreamResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Box<dyn BodySource> }
pub trait Net {
    // existing methods ...
    fn http_stream_authorized(&self, req: HttpStreamRequest, original: AuthLease)
        -> BoxFuture<'static, Result<HttpStreamResponse, NetError>>;   // default: buffers through http_authorized
}
```

The real implementation (`env/real/authorized.rs`) sends a `StreamBody` and
returns hyper's `Incoming` as a `BodySource` without collecting it. The
simulated network yields the simulated service's response in seeded chunk
sizes, so chunk boundaries vary across seeds. `ForeignHost` gains the same
method with a buffering default; the gVisor bridge implements it through its
hyper client.

### 7.2 A blob request body

In `TurnFx::fetch` (`kronik-sched/src/effects.rs`), for `FetchBody::Blob(m)`:

- `m` not in `T`: a `DENIED` effect with error `BLOB_NOT_HELD`, noted
  without fsync like a missing capability; the guest gets
  `fetch-error::denied("BLOB_NOT_HELD")`.
- The recorded `HttpEffectRequest` has an empty `body` and `body_blob = m`;
  `EffectRecord.blobs` lists `m`. The fingerprint's body component is the
  identity digest where an inline body's is BLAKE3 of the bytes: for `b3:`
  that is the same value, so the same bytes sent inline or as a blob match
  exactly; for `b3s:` they differ (and match approximately).
- The wire request streams the blob from the store (`HttpBody::Stream`, the
  blob's size as `content-length`), decrypting a sealed one.
- A blob's bytes were scrubbed when it was written (§5.2, §7.4); the request
  record holds no bytes to scrub.

### 7.3 A response above the threshold

For a kind that reads blobs, the gate reads up to `threshold + 1` bytes of
the response. A response that ends there is inline, exactly as today
(`prepare_inline_fetch_response`). A longer one, under the effect timeout
that covers the whole exchange:

1. Opens a writer in the turn's space with the request's subject
   (`FetchRequest.subject`) and its keys, under the turn's lease.
2. Writes the buffered bytes and the rest of the stream through the stream
   scrubber (§7.4), stopping with `TooLarge` past `effect_response_bytes`
   (the part file is deleted, `TOO_LARGE` is recorded as today).
3. `finish`, `ensure_durable`.
4. Records `HttpEffectResponse { status, headers, body: empty, body_blob }`,
   lists the reference in `EffectRecord.blobs`, appends the `EffectResult`
   (fsync), and only then returns `FetchOutcome::Ok` with `FetchBody::Blob`.

For a kind that does not read blobs, nothing changes: inline up to
`effect_response_bytes`.

### 7.4 Scrubbing a stream

`kronik_effects::http::StreamScrubber` wraps a `CompiledScrubber` (the
leftmost-longest Aho-Corasick matcher of today) for data that arrives in
chunks. It keeps the last `longest pattern - 1` bytes back; a match is
replaced as soon as it starts before that tail, since every longer
alternative starting there is then visible. Its output equals
`scrub(whole input)` for every way of splitting the input, which a property
test checks with random splits, matches across chunk borders and overlapping
patterns. Without patterns it passes chunks through without copying. The
blob's identity and size are those of the scrubbed bytes.

### 7.5 Recording and re-runs

- A re-run (an open turn after a crash) and a fork read the recorded
  `body_blob` back (`outcome_of_fetch`) and give the guest the same
  reference; a blob the store does not have is `BLOB_MISSING`, a host
  failure, never another result.
- A crash after the blob was written and before the `EffectResult` leaves a
  loose blob; the re-run applies the delivery class as for any effect without
  a recorded result (I17).
- An `EffectResult` is never appended before its blobs are durable.

### 7.6 Standard `fetch` (`wasi:http`)

As [ADR 0121](../adr/0121-blob-interface-and-wasi-0-3.md) §6, in
`kronik-runtime/src/host/wasi_http.rs`:

- `answer()` maps a `FetchBody::Blob` response to an incoming body backed by
  a reader. Its frames are filled only by `drive`: at each guest wait, every
  blob-backed body with an empty buffer gets exactly the next frame (at most
  64 KiB). A non-blocking read returns what is buffered. What a read returns
  depends only on the guest's waits.
- `drive` spools a request body that passes the threshold into a writer (the
  turn's subject; the turn's created-bytes quota as its limit, else
  `HTTP-request-body-size`) instead of growing `Pending.bytes`; the effect's
  request is then `FetchBody::Blob`.
- The determinism test of ADR 0070 (100 runs, jittered latency) runs again
  with a 3 MiB response and a 3 MiB streamed request body.

## 8. Log format

### 8.1 Changes

All additive in log format v1 (I16: added fields need no new reader); no new
envelope kind. The numbers M24 takes are listed so both stay apart.

| Message | Field | Milestone |
| --- | --- | --- |
| `BlobRef` (common.proto) | `optional string subject = 3`, `uint32 key_version = 4` | M25 |
| `EffectRecord` (turn.proto) | `repeated BlobRef blobs = 14`: every blob its request and response reference, outside the sealed payloads | M25 |
| `HttpEffectRequest` (effects.proto) | `BlobRef body_blob = 6` | M25 |
| `HttpEffectResponse` (effects.proto) | `BlobRef body_blob = 4` | M25 |
| `Limits` (config.proto) | `optional uint64 blob_threshold_bytes = 11`, `upload_bytes = 12`, `blob_bytes_per_actor = 13`; 14–15 reserved | M25 |
| `TurnRecord` | `blob_refs = 19` (exists) used; 24–29 reserved | M26 |
| `HttpInput.request_hash` | version byte 4 (§6.3) | M25 |
| reserved for M24 | `Input` case 5, `TurnRecord` 30–34, `Outcome.output` case 6, `EffectStatus` 12, envelope kind 18 if ever | M24 |
| reserved for blobs | envelope kind 19 (ADR 0118, if review prefers a record of its own) | — |

### 8.2 Validation

`kronik_proto` gains `blobs::refs(&Record) -> impl Iterator<Item = &BlobRef>`
(every reference outside sealed payloads: input body, outcome bodies,
messages, timers, compensations, `blob_refs`, `EffectRecord.blobs`, rebased
turns) and validates on decode:

- `hash` is `b3:` or `b3s:` followed by 64 lowercase hex characters;
- `b3:` has no subject and key version 0; `b3s:` has a valid subject
  (`valid_subject`) and key version ≥ 1;
- `BlobRefOp.kind` 0 or unknown is `STORAGE_CORRUPT` (as the brief says);
- an `HttpEffectRequest` or `HttpEffectResponse` with both `body` and
  `body_blob` is `STORAGE_CORRUPT`, and its `body_blob` must also be listed
  in `EffectRecord.blobs`.

### 8.3 Fixtures

`crates/kronik-proto/tests/fixtures/`: a `TurnRecord` with an uploaded
`Body.blob` (`b3:`) and a blob response, an `EffectResult` with a `b3s:`
request and response blob, and a `Limits` record with the new fields; each
decodes with this version, and a v0.4.1 record decodes unchanged. The
compatibility corpus (`tests/compatibility`) gets a v0.5 directory with
blobs when v0.5.0 is frozen. Blob file fixtures (a plain and a sealed file
with a fixed test key) live in `crates/kronik-blob/tests/fixtures/`.

### 8.4 What the log holds for a large body

A body above the threshold leaves only its reference in the log:
`{hash, size, subject, key_version}`, about 80 to 350 bytes. Turn records,
effect results and the API's turn JSON show the reference, never the bytes.

## 9. Replay and forks

- **Recorded responses.** An exact or approximate match returns the
  recorded `body_blob`; the fork's guest reads it lazily from main's store.
  A live allowlisted GET (`[fork] live_allowlist`) that answers above the
  threshold is spooled into the fork's space. Stub rules stay inline.
- **New blobs** go to the fork's space or an isolated tree's scratch space
  (§4.5). Identities are computed as in production, so equal bytes give equal
  references and no difference.
- **Prepared bodies.** The disclosure guards that check prepared inline
  bodies for secret values (`prepared_outcome_safe`,
  `disclose_neighbor`) treat `Body.blob` and `body_blob` as prepared when
  their blob was written (§5.2, §7.4) and never read the blob; they no
  longer refuse a blob body as unavailable.
- **The diff.** Bodies compare by reference: equal identity and size is
  unchanged; otherwise `responses` and `effects` show
  `{"op": "replace", "path": "", "prod": {"blob": "b3:…", "size": N}, "fork": …}`.
  `docs/reference/diff-v1.schema.json` allows that value next to text and
  base64 (additive, `kronik.diff/v1`).
- **Erased blobs.** A fork read of an erased subject's blob returns
  `erased` and marks the turn erased: unverifiable, not divergent
  (ADR 0109).
- **`--no-pii` forks.** A read of a subject's blob returns, at offset 0, its
  pseudonym (`Pseudonyms::of(subject, identity digest)`, 16 bytes), and
  nothing after; the turn counts as `pii-masked`.
- **Leases.** A replay holds a floor lease at its fork point, renewed per
  root input (ADR 0120 §4).

## 10. Keeping borrowed blobs

A borrowed blob is kept while a record within retention references it, a
saved idempotent response or an open turn pins it, a snapshot indexes it, or
a lease covers it. The index, the floor, the leases, the sweep, the snapshot
index and the shipping order are specified in
[M26 §5–§8](m26-blobs.md#5-materialized-state), and the slices that build
them for borrowed blobs (B11, B12) are part of M25: no slice that creates
blobs is released without them (§18.2).

## 11. Memory

| Path | Bound per request or turn |
| --- | --- |
| upload | `threshold` + one 64 KiB chunk, plus hyper's read buffer |
| fetch response | `threshold` + one chunk + the scrubber's tail (longest secret) |
| fetch request from a blob | one frame |
| response to a client | one frame (hyper's write buffer aside) |
| `blobs.get`, `write` | 1 MiB per call (the guest's own memory aside) |
| `wasi:http` body | one frame per body |
| shipping a blob | one 8 MiB part |

Concurrency is bounded by what already bounds it: gateway connections and the
turn permits.

## 12. Configuration and limits

`kronik.toml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `[blobs] disk_reserve` | `"2x"` | A multiple of `[log] disk_reserve`, or a size. Below it, bodies that would become blobs are refused with 503 `BLOB_STORE_FULL`, and blob writes in turns wait (§4.7) |
| `[blobs] gc_interval` | `"1h"` | The collector's pass (M26 §6); `"0s"` runs it only on `kronik blobs gc` |
| `[blobs] lease_ttl` | `"5m"` | How long a lease lives without renewal |
| `[gateway] body_idle_timeout` | `"30s"` | An upload that sends nothing for this long is refused |

Limits per kind (history, `kronik limits set`, `POST /v1/limits`):

| Field | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `blob_threshold_bytes` | `--blob-threshold` | 1 MiB | Bodies above it become blobs; at most `message_bytes` (`BAD_REQUEST` otherwise) |
| `upload_bytes` | `--upload-size` | 64 MiB | The largest request body for a kind that reads blobs |
| `blob_bytes_per_actor` | `--blob-size-per-actor` | 1 GiB | Held bytes per actor, and created bytes per turn (§5.2) |
| `effect_response_bytes` | `--effect-response-size` | 10 MiB | Unchanged; now also bounds blob responses |
| `effect_timeout_ms` | `--effect-timeout` | 10 s | Unchanged; covers a blob response's whole transfer |

## 13. Metrics

Added to the metrics catalog (`kronik-metrics`), without subject or hash
labels:

| Metric | Type | Labels |
| --- | --- | --- |
| `kronik_blob_objects`, `kronik_blob_bytes` | gauge | |
| `kronik_blob_written_bytes_total` | counter | `source`: `upload`, `effect`, `guest` |
| `kronik_blob_read_bytes_total` | counter | `reader`: `guest`, `gateway`, `ship`, `api` |
| `kronik_blob_store_below_reserve` | gauge | |
| `kronik_blob_turn_retries_total` | counter | |
| `kronik_gateway_uploads_total` | counter | `outcome`: `inline`, `blob`, `too_large`, `store_full`, `aborted` |
| `kronik_blob_missing_total` | counter | |

`/v1/health` and `/healthz` add `"blobs_low_disk": true` below the blob
reserve.

## 14. Error codes

| Code | Status | Milestone | When |
| --- | --- | --- | --- |
| `BLOB_NOT_HELD` | 403 | M25 | A reference outside the turn's references (outcome code, effect error, API) |
| `BLOB_STORE_FULL` | 503 | M25 | The blob store is below `[blobs] disk_reserve` |
| `BLOB_MISSING` | 500 | M25 | A committed reference's bytes are not in the store (never expected; a restore with `--allow-missing-blobs` can cause it) |
| `BLOB_NOT_FOUND` | 404 | M25 | The API knows no such blob (`/v1/blobs/{hash}`) |
| `BLOB_QUOTA_EXCEEDED` | 409 | M26 | Over `blob_bytes_per_actor` |

Each gets its catalog entry (status, title, hint) in `kronik-core` and an
explanation in `crates/kronik-core/explain/codes/`, and `docs/errors.md` is
regenerated in the same commit. `PAYLOAD_TOO_LARGE` (413) also covers
uploads, and `SUBJECT_ERASED` (410) erased blobs. A concept page
`kronik explain blob` explains blobs, borrowing and holding.

## 15. API, CLI and MCP

| Surface | Scope | M25 |
| --- | --- | --- |
| `GET /v1/turns/{id}`, `kronik history`, `trace` | `read` | A blob body renders as `{"blob": {"hash", "size", "subject"}}` (subject only with `pii:read`); history summaries show `blob b3:4f1c09ab77e9 (300.0 MB)`. `docs/reference/turn.schema.json` grows the alternative |
| `GET /v1/blobs/{hash}` / `kronik blobs inspect <hash> [--verify]` | `read` | Size, subject (with `pii:read`), sealed, first and last referencing LSN, roots (M26), state (`live`, `erased`, `missing`); `--verify` checks the whole file |
| `GET /v1/blobs/{hash}/content?offset=&len=` / `kronik blobs get <hash> [-o FILE]` | `read`, and `pii:read` for a subject's blob | The bytes, streamed through the current secret output matcher; `BLOB_NOT_FOUND`, `SUBJECT_ERASED` |
| `GET /v1/blobs` / `kronik blobs status` | `read` | Objects, bytes, free disk, reserve, below reserve, per space |
| `POST /v1/limits` / `kronik limits set` | `operate` | The three new fields and flags |
| MCP `inspect_blob` | `read` | As `GET /v1/blobs/{hash}` |

Every command has `--json`; the CLI, JSON and OpenAPI references and their
examples are regenerated in the slice that adds the route (the
documentation-surface gate checks it).

## 16. SDKs

The same names in all four SDKs; reading a body never changes for small
bodies.

| Need | Rust | TypeScript | Python | Go |
| --- | --- | --- | --- | --- |
| whole body, inline or blob | `req.read_body()?` | `req.body` (lazy) | `req.body` (lazy) | `req.Body()` |
| is it a blob | `req.body_blob()` | `req.blob` | `req.blob` | `req.Blob()` |
| read a range | `ctx.blobs().get(&b, off, len)` | `ctx.blobs.get(b, off, len)` | `ctx.blobs.get(b, off, n)` | `ctx.Blobs().Get(b, off, n)` |
| read in chunks | `ctx.blobs().reader(&b)` (`Read + Seek`) | `ctx.blobs.stream(b)` (`ReadableStream`) | `ctx.blobs.reader(b)` (`io.RawIOBase`) | `ctx.Blobs().Reader(b)` (`io.ReaderAt`, `io.Reader`) |
| write a large body | `ctx.blobs().writer()` (`Write`), `.finish()` | `ctx.blobs.writer()`, `.write()`, `.finish()` | `ctx.blobs.writer()` | `ctx.Blobs().Writer()` (`io.Writer`), `.Finish()` |
| respond with a blob | `HttpResponse::blob(200, &b, "application/pdf")` | `ctx.blob(200, b, 'application/pdf')` | `ctx.blob(200, b, ...)` | `kronik.BlobResponse(200, b, ...)` |
| fetch with a blob body | `Request::post(url).body_blob(&b)` | `ctx.http.fetch({ url, method: 'POST', body: b })` | `ctx.http.fetch(url, method="POST", body=b)` | `kronik.FetchRequest{Body: …, BodyBlob: &b}` |
| fetch response | `res.read_body()?`, `res.blob()` | `res.body` (lazy), `res.blob` | `res.body`, `res.blob` | `res.Body()`, `res.Blob()` |

Rust keeps `body_bytes()` (inline only) and makes `text()` and `json()` on a
blob body return `Error::BlobBody` ("the body is a blob of N bytes; read it
with `read_body()` or a reader"), pointing to `kronik explain blob`; the
other SDKs read lazily. A whole-body read is bounded by the guest's memory
limit (64 MiB by default). Blob errors map to errors with the codes of §14.
The test kits implement the interface in memory with the same `T` rules.
`docs/guides/actors.md` gets a section on large bodies.

## 17. Acceptance plan

Tests use the test guest `tests/guests/test-actor` with a new feature
`blobs` (kind `media`, built by `scripts/build-test-guests.sh` into
`tests/guests/blobs.wasm`): routes to upload, fetch, read ranges, write a
blob of a requested size, respond with a blob and store a hash string.
Memory is the daemon's peak RSS (`VmHWM` from `/proc/<pid>/status`,
sampled every 50 ms); "constant" means two sizes a factor of ten apart grow
the peak by the same amount within 16 MiB, and neither by more than
`threshold` + 48 MiB over a warm-up request. CI runs the scaled sizes; the
full sizes run on the test VPS (2 vCPU, about 4 GiB of RAM, NVMe) through
`scripts/acceptance-m25.sh`, which prints the peaks for `docs/perf.md`.

| # | Test (crate, file) | What it does | CI size / VPS size |
| --- | --- | --- | --- |
| 1 | `kronik`, `tests/blobs_streaming.rs` `an_upload_is_a_blob_with_constant_memory` | `kronik serve`; `limits set media --upload-size 512MiB`; the client streams seeded bytes; the actor answers `{hash, size}` of its `blob` body; compares with the client's BLAKE3; memory as above | 8 and 80 MB / 30 and 300 MB |
| 2 | same file, `a_fetched_pdf_is_a_blob_and_replays_to_the_same_hash` | a local server streams a generated `%PDF-1.7` file; `grant media http:127.0.0.1`; the actor fetches it and answers the reference; then `fork create` and `replay` (both modes): empty diff, and the fork turn's recorded response has the same hash; the server saw one request | 4 and 40 MB / 40 MB |
| 3 | same file, `the_log_holds_only_the_hash_above_the_threshold` | after 1 and 2: no 4 KiB window of the seeded bodies occurs in any segment file; the records decode to `Body.blob` and `body_blob` with the hash and size; a body of `threshold` bytes stays inline, one byte more does not; an identity replay of a turn that reads three ranges and answers their BLAKE3 has an empty diff | as 1 and 2 |
| 4 | same file, `a_large_response_streams_with_constant_memory` | the actor fetches a blob from the local server and responds with it; the client streams and hashes it; memory as above; a second variant writes 16 MiB with `writer` (raised fuel) and responds with it | 12 and 120 MB / 100 MB and 1 GB (`#[ignore]` above 120 MB) |
| 5 | `kronik-sched`, `tests/blobs.rs` `a_reference_from_an_earlier_turn_is_not_held` | turn 1 gets an upload and stores the hash string in state; turn 2 builds the `blob-ref` and calls `get` (`not-held`), responds with it (outcome code `BLOB_NOT_HELD`) and fetches with it as body (a `DENIED` effect with `BLOB_NOT_HELD`); a fork replay gives the same | in-process |

Further tests by slice (§18): the store's crash behaviour under the
simulated disk (`kronik-sim/tests/blob_store.rs`: every crash point between
`write` and `ensure_durable` leaves either nothing referenced or the whole
blob), the stream scrubber's property test, the `wasi:http` transcript test,
the idempotent retry of an upload (one turn, the same response, no second
spool), previews, and the format fixtures.

## 18. Implementation plan

### 18.1 Slices

Each slice is one commit or a short series, keeps `scripts/ci.sh fmt clippy
hygiene test docs book` green, and updates the docs, the error catalog and
the references it touches. "M24" says whether it can run in parallel with
M24's slices.

| Slice | Touches | Proven by | M24 |
| --- | --- | --- | --- |
| **B1** store core | new `crates/kronik-blob` (layout, format v1, identity type, writer, reader, `ensure_durable`, claims, start sweep, reserve, leases), workspace `Cargo.toml` | unit tests on a temporary directory; `kronik-sim/tests/blob_store.rs` crash tests; fixtures; nothing else changes | parallel |
| **B2** subject keys for blobs | `kronik-privacy` (`identity_key`, `blob_keys`, `blob_key_access`), sealed frames in `kronik-blob` | keystore tests (off mode creates the key once; erase gives `Erased`; a restored backup covers it); a sealed fixture | parallel |
| **B3** log format | `proto/kronik/log/v1/{common,turn,effects,config}.proto`, `kronik-proto` (`blobs::refs`, validation), fixtures, `docs/design/m1-core.md` note | decode fixtures; v0.4.1 fixtures unchanged | rebase on M24's proto edits (different fields) |
| **B4** WIT 0.1.1 and `blobs` | `wit/kronik-actor.wit`, SDK WIT copies, `allowlist.rs` (+ its test), host stubs (`NOT_IMPLEMENTED`), `docs/reference/wit.md`, `wit-examples.md` | allowlist tests; a v0.4 component still runs; the doc-surface gate | **serialize** with M24's WIT slice: the first bumps to 0.1.1 |
| **B5** runtime blob host | `kronik-runtime` (`BlobHost`, `reads_blobs`, bodies in and out, `FetchBody`, budget, trap codes) | runtime tests with an in-memory `BlobHost` | parallel (textual edits in `host.rs`) |
| **B6** node wiring | `kronik-sched` (store in `Node`, `TurnBlobs`, leases, `ensure_durable` in commit, worker retry, limits in `Config`), `kronik-effects` (`KindLimits`), `kronik-store` (`blobs` and `blob_pins` sources 4, 6, 7), `kronik` (`[blobs]`, `limits set` flags), `kronik-api` (limits), error codes `BLOB_NOT_HELD`, `BLOB_STORE_FULL`, `BLOB_MISSING`, metrics | `kronik-sched/tests/blobs.rs`: a writer's blob in a response; a crash before commit leaves it loose; a record never precedes its blob; criterion 5 | parallel |
| **B7** effects | `kronik-core` (`http_stream_authorized`, real and default), `kronik-sim` (streaming `SimNet`), `kronik-effects` (`StreamScrubber`), `kronik-sched/src/effects.rs` (§7.2–§7.5), `ForeignHost` | property test; effects tests with a blob response and request in the simulator; re-run after a crash between blob and `EffectResult` | parallel |
| **B8** gateway | `kronik-gateway` (`body.rs`, `server.rs`, body phase, response streaming, previews), `kronik-sched` (`ingress_peek`, version 4 hash, upload lease in `Job`), `kronik` (`body_idle_timeout`) | gateway tests; idempotent retry of an upload; criterion 1 at CI size | **coordinate** with M24's gateway slices (`body.rs` either order, agreed) |
| **B9** `wasi:http` bodies | `kronik-runtime/src/host/wasi_http.rs` | the 100-run transcript test with 3 MiB bodies | parallel |
| **B10** replay and forks | `kronik-fork` (gate, spaces, scratch, disclosure guards, diff, erased and `--no-pii` reads), `diff-v1.schema.json` | identity replay with blob bodies (criterion 2's replay half); `--no-pii` fork test | **coordinate**: M24 edits `replay.rs` and `diff.rs` too |
| **B11** index, floor, leases, sweep, snapshot index | `kronik-blob` (sweep), `kronik-store` (compaction of `blobs`), `kronik-sched/src/snapshots.rs` (`blobs.idx`, manifest field, sweep after retention), fork `blobs.roots`, replay leases, API/CLI `kronik blobs status`, `inspect`, `get`, `gc` (M26 §12), error code `BLOB_NOT_FOUND` | sweep tests; snapshot fixture with `blobs.idx`; dry run | parallel |
| **B12** shipping and restore | `kronik-ship` (order of ADR 0122, `ship-blobs.db`, multipart, restore), `kronik` (`restore --allow-missing-blobs`) | MinIO test: restore of uploaded and fetched blobs; a round stopped between steps | parallel |
| **B13** SDKs and acceptance | `sdk/{rust,ts,python,go}` (§16), test kits, `tests/guests` (`blobs` feature), `crates/kronik/tests/blobs_streaming.rs`, `scripts/acceptance-m25.sh`, `docs/perf.md`, `docs/guides/{actors,operations}.md` | criteria 1–5; `scripts/ci.sh ts sdks examples` | textual conflicts in SDK files |

### 18.2 Keeping `main` releasable

Between B4 and the last slice of M26, `main` can run components that create
blobs while collection, privacy or shipping are incomplete. Until then the
allowlist accepts `kronik:actor/blobs` only when `NodeConfig::blobs` is set:
tests set it, `kronik serve` sets it from an undocumented
`[blobs] enabled = true` that defaults to false. M26's last slice (B20)
removes the switch and the key.

### 18.3 Order

B1, B2 and B3 first (in parallel), then B4, then B5 and B6, then B7, B8,
B9, B10 and B11 (largely in parallel), then B12 and B13. M26's slices
(B14–B20) follow B6 and B11; [M26 §18.2](m26-blobs.md#182-order-and-parallel-work)
has the full dependency table.

Parallel work with M24 is development order only. The brief's rule for the
road to v1.0 ("within a track the milestones' order applies") still decides
when a milestone is closed: M25 is closed after M24, and M26 after M25, each
when all its criteria pass.

## 19. Risks

| Risk | Mitigation |
| --- | --- |
| A blob-backed `wasi:http` body makes `poll` results depend on disk timing | Frames are filled only during drive, one per body per wait (§7.6); the 100-run transcript test |
| Memory grows with body size somewhere unexpected (hyper buffers, the scrubber, `object_store` parts) | Measured by criteria 1, 2 and 4 at two sizes; bounds in §11 |
| Anyone can fill the disk with uploads that retention keeps for 7 days | `upload_bytes` defaults to 64 MiB; the blob reserve stops blobs before the log; docs recommend an authenticating proxy in front of upload routes |
| The stream scrubber differs from whole-buffer scrubbing at chunk borders | Property test over random splits (§7.4) |
| The turn-record ceiling of issue #26 and the open-turn fix of #35 (other branches) change the same code paths | References count toward the ceiling; open-turn pins follow #35's stored `TurnBegin` |
| A subject's request body sent as a blob matches its inline form only approximately | Documented; the same bytes inline or as a `b3:` blob match exactly |
| Decrypting 64 KiB frames costs CPU on sealed blobs | Measured in `docs/perf.md`; XChaCha20-Poly1305 runs at several hundred MB/s per core |

Outside this design: answering `Range` requests in the gateway (an actor can
answer 206 itself with `get`), operator messages and uploads with blobs
through the API, compressing blobs, and blobs in a cluster (M16: a blob must
be on a majority of the shard's replicas before the record that references
it commits; the self-describing references allow it).

## 20. Open questions

Decided on 2026-11-13: the maintainers accepted both recommendations below
and those of M26 §20, and ADRs 0117–0122 are Accepted.

Two questions decide defaults; the rest are in [M26 §20](m26-blobs.md#20-open-questions).

1. **The default upload limit.** Recommendation: 64 MiB per kind, raised
   with `kronik limits set --upload-size`. A larger default (1 GiB) suits
   media apps but lets anyone who reaches an upload route keep gigabytes on
   disk for the retention window.
2. **The default effect response limit for components that read blobs.**
   Recommendation: keep 10 MiB for every component, so nothing changes
   without an operator's decision; criterion 2's 40 MB PDF then needs
   `--effect-response-size 64MiB`. The alternative is a higher default
   (256 MiB) for components that read blobs only, which makes one limit mean
   two things.
