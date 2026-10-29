# 0081. OTLP over HTTP with vendored protos, no OpenTelemetry crates

- **Status:** Proposed
- **Date:** 2026-10-27

## Context

The traces and metrics must reach "en vanlig OpenTelemetry-backend": an
OpenTelemetry Collector, Jaeger, Grafana Tempo, or a vendor's endpoint. All
of them accept OTLP. OTLP comes in three wire forms: gRPC, HTTP with
protobuf, and HTTP with JSON.

Constraints:
- **Hygiene (ADR 0004):** a new crate may not enable tokio's runtime
  features and has to use `Env` for clock, spawning and network.
- **One rustls provider:** the tree uses ring. aws-lc-rs must not slip in,
  and reqwest's `rustls` feature and `opentelemetry-otlp/reqwest-rustls`
  would bring it in.
- **No new C code:** only the bundled SQLite and the existing zstd, blake3,
  ring and wasmtime C.
- **cargo-deny:** licenses as allowed, no unmaintained crates.
- **Justify every new dependency.**

The candidates are the 0.33.1 OpenTelemetry crates:
- `opentelemetry` and `opentelemetry_sdk`;
- `opentelemetry-otlp`, `opentelemetry-proto` and `opentelemetry-http`;
- `opentelemetry-prometheus` and `tracing-opentelemetry`.

None of them is in the offline crate cache, and their API breaks between 0.x
releases.

## Decision

- **Transport:** OTLP/HTTP with protobuf only. `POST <endpoint>/v1/traces`
  and `POST <endpoint>/v1/metrics`, `content-type: application/x-protobuf`.
- **Messages:** compiled from the `.proto` files of
  `open-telemetry/opentelemetry-proto` (Apache-2.0):
  - the common, resource, trace and metrics files, and the trace and
    metrics service requests;
  - vendored under `proto/opentelemetry/` with their tag recorded;
  - compiled by the workspace's protox and prost-build, as `kronik-proto`
    is. NOTICE carries the attribution.
- **HTTP:** sent through `Env::net()`, the hyper and hyper-rustls client
  with ring that effects already use.
- **Batching, retries and `Retry-After`:** in `kronik-otel` (m28-otel
  §3.6).
- **Metrics:** come from `kronik-metrics` through a new `snapshot()`.
  `GET /metrics` stays as it is.
- **New third-party crates: none.**

## Alternatives

- **The OpenTelemetry SDK with `opentelemetry-otlp`.**
  - The SDK's model is live spans timed by the process. Ours are built from
    records (ADR 0080), so we would bypass most of it.
  - Its batch processor wants its own thread or tokio runtime (hygiene).
  - Its HTTP clients are reqwest or hyper with their own TLS features.
  - It is about ten crates for what amounts to five message types and one
    POST.
- **`opentelemetry-proto` alone** (`default-features = false, features =
  ["gen-tonic-messages", "trace", "metrics"]`, prost only).
  - Acceptable, and the fallback if the vendored files ever drift from the
    spec.
  - Rejected for now because it ties prost upgrades to its release train,
    for files that change rarely and stay compatible within OTLP 1.x.
- **OTLP/gRPC** (`tonic`): adds tonic, tower and the gRPC stack. Every
  backend above also takes OTLP/HTTP, and the Collector translates.
- **OTLP/HTTP with JSON:** protobuf is the default in the spec and smaller,
  and we already have the protobuf toolchain.
- **`opentelemetry-prometheus`:** `/metrics` already exists, with no
  dependencies.

## Consequences

- `kronik-otel` builds offline with the crates already in the tree, and
  cargo-deny is unchanged except for the NOTICE line.
- We implement OTLP's small HTTP contract ourselves:
  - status codes;
  - `Retry-After`;
  - partial success, which we log.

  Covered by unit tests and by the in-process receiver test.
- **No gzip:** flate2 would be a new crate. Batches are small, and a
  Collector can compress onward.
- **Phase B spike:** compile the vendored protos with protox 0.10 and prost
  0.14, and confirm that Jaeger and the Collector's `otlphttp` receiver
  accept a recorded batch.
- Revisit if OTLP 2 changes the wire format, or if users need gRPC-only
  endpoints without a Collector in between.
