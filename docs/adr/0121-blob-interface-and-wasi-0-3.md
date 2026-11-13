# 0121. Reading and writing blobs on WASI 0.2, and the path to WASI 0.3 streams

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The build brief, M25: the guest reads a large body in chunks through a
handle, "with WASI 0.3 streams once M22 exists"; handles are read lazily, so
replay fetches only the bytes the guest actually reads; large responses are
written to the blob store during the turn and streamed to the client after
commit. M26 adds `blobs.put`, `blobs.get`, `blobs.retain` and `blobs.release`
with `BlobRef` as a type of its own.

WASI 0.3 is not available: Wasmtime 50, which Kronik pins, ships `p3` as
"experimental, unstable and incomplete", and the gate of ADR 0070 §5 is
closed (M22's third criterion is deferred). A WASI 0.3 guest would also need
an `async` `handle` export, a breaking ABI generation (ADR 0070, amendment,
blocker 1).

ADR 0113 (M24) keeps v0.5 on `kronik:actor@0.1.1`: new interfaces only, and
an interface never gains functions after it first appears. So the `blobs`
interface must be complete when it lands.

Determinism (I1) rules out any read whose result depends on timing: a
`wasi:io` `input-stream.read` may return fewer bytes, or none, depending on
readiness, and ADR 0070 needed its *drive* design to make `wasi:http` bodies
deterministic.

## Decision

### 1. The interface

```wit
/// Large bodies and apps' blobs (M25, M26). A blob-ref is an identity, not a
/// permission: every call checks the turn's references (kronik explain blob).
@since(version = 0.1.1)
interface blobs {
  use types.{blob-ref};

  variant blob-error {
    /// the turn neither holds nor borrows this reference (BLOB_NOT_HELD)
    not-held,
    /// over the actor's blob quota (BLOB_QUOTA_EXCEEDED)
    quota-exceeded,
    /// the blob belonged to an erased subject (SUBJECT_ERASED)
    erased,
    /// a call outside the limits, such as more than 1 MiB in one call
    invalid(string),
  }

  /// Up to `len` bytes (at most 1 MiB) from `offset`. Fewer only at the end
  /// of the blob; empty at or past the end.
  get: func(blob: blob-ref, offset: u64, len: u32) -> result<list<u8>, blob-error>;

  /// Stores `bytes` (at most 1 MiB) with the turn's default subject; the
  /// actor holds the result once the turn commits.
  put: func(bytes: list<u8>) -> result<blob-ref, blob-error>;

  /// Holds a reference the turn may use, from commit on.
  retain: func(blob: blob-ref) -> result<_, blob-error>;
  /// Ends the actor's own hold at commit.
  release: func(blob: blob-ref) -> result<_, blob-error>;

  /// Writes a blob of any size in chunks, with the default subject at
  /// construction. The reference `finish` returns is borrowed by the turn:
  /// retain it, send it, or return it as a body.
  resource writer {
    constructor();
    write: func(chunk: list<u8>) -> result<_, blob-error>;
    finish: func() -> result<blob-ref, blob-error>;
  }
}
```

The world `actor` imports it. It lands whole in M25's first WIT change;
`put`, `retain` and `release` trap with `NOT_IMPLEMENTED` until M26's slices
make them work, and no release ships in between.

### 2. Reads are functions of their arguments

`get` takes an explicit offset. Its result depends only on the blob's bytes,
the offset and the length: no stream position, no readiness, no partial
reads except at the end. Random access serves the common cases (a header, a
page of a PDF, a range for a client) without reading what comes before.
Lazy by construction: the host reads the frames the range touches
(ADR 0117 §5).

### 3. Writes go through a resource

`writer` lives in the turn's instance like every resource (I3): one that is
dropped without `finish`, or that is open when the turn ends, is discarded
and its bytes are deleted. `finish` makes the blob durable (ADR 0117 §4) and
returns its reference.

### 4. Limits and cost

- 1 MiB of data per `get`, `put` and `write` call, so host memory per call is
  bounded whatever the guest's memory limit.
- A per-turn budget of blob bytes moved, derived from fuel: the kind's fuel
  limit × 64 bytes (3.2 GB at the default 50 million). Exceeding it traps
  with `FUEL_EXHAUSTED`, as SQL's separate budget does (ADR 0005 §5): host
  calls are not metered by Wasm fuel, and this keeps a turn's disk I/O
  bounded and deterministic.
- `describe` may not use the interface.

### 5. Language streams are SDK adapters

The SDKs wrap `get` and `writer` in each language's own stream types: Rust
`std::io::Read + Seek` and `Write`, a TypeScript `ReadableStream` and an
async iterator, Python `io.RawIOBase`, Go `io.ReaderAt`, `io.Reader` and
`io.Writer`. Application code uses those and does not change when the
binding underneath does.

### 6. Standard `fetch` on WASI 0.2

The `wasi:http` 0.2 path (ADR 0070) keeps its drive design:

- A response body above the threshold, for a component that reads blobs, is
  a blob; the guest reads it through the `incoming-body` stream, which the
  host fills during drive with exactly the next frame of at most 64 KiB, and
  only when the guest waits on it. What a read returns therefore depends
  only on the guest's calls, as for every other wait.
- A request body that grows past the threshold during drive is spooled into
  a blob instead of host memory; the effect's request then carries the blob
  reference.

### 7. The path to WASI 0.3

When ADR 0070's gate opens and the asynchronous `handle` generation is
decided (its own ADR, after M24 and M25), that generation adds to `blobs`:

```wit
open: func(blob: blob-ref) -> result<stream<u8>, blob-error>;
create: func(data: stream<u8>) -> future<result<blob-ref, blob-error>>;
```

implemented on the same store reader and writer. The host produces a
stream's items in frames of at most 64 KiB and completes a read only after
the bytes are read, never on a timer, so that what the guest sees depends on
what it awaited, not on when the disk answered; the determinism suite of
ADR 0001 must show it. `wasi:http@0.3` bodies are `stream<u8>` and map onto
the same reader and spool. `get`, `put` and `writer` stay: random access and
small blobs do not need streams. The SDK adapters switch their
implementation and keep their API.

## Alternatives

- **`wasi:io/streams` `input-stream` from a `blobs.open` today.** Its `read`
  may return fewer bytes or none depending on readiness, it seeks only
  forward (`skip`), and binding a WASI resource type through a Kronik
  interface adds toolchain risk in four SDKs. The drive machinery could make
  it deterministic, as for `wasi:http`, at a cost every reader would pay.
- **A reader resource with `read(len)` and `seek`.** A position the host must
  track, for nothing an offset does not give.
- **Whole-blob `get` only.** A 300 MB upload would not fit the 64 MiB guest
  memory limit.
- **Waiting for WASI 0.3.** Not available in the pinned Wasmtime, and M25
  does not depend on it.

## Consequences

- Every SDK binds five functions and one resource; test kits implement them
  in memory.
- The interface is fixed for the 0.1 track; streams arrive with the next
  ABI generation without changing application code.
- The `wasi:http` 0.2 change is covered by the determinism transcript test of
  ADR 0070 (100 runs with jittered latency) with a body above the threshold.
- Revisit when the WASI 0.3 gate opens.
