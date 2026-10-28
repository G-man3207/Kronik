# 0008. The MCP server: rmcp over the in-process API

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

The brief (SPEC.md, "Agent interface: API, CLI and MCP") asks for `kronik
mcp` on stdio and Streamable HTTP on the API listener, built with the
official Rust MCP SDK "if it is sufficient", with the tools of its table and
resources for concepts, the WIT, the error catalog, the configuration and
`AGENT_GUIDE.md`. The CLI and MCP are thin layers over the same JSON API, so
agents get the same results and the same stable error codes as humans.

The MCP specification changed under us. Revision 2026-07-28 drops the
`initialize` handshake and sessions: every request carries its protocol
version and capabilities in `_meta.io.modelcontextprotocol/*`, which
Streamable HTTP mirrors into headers (`MCP-Protocol-Version`, `Mcp-Method`,
…). Clients that still speak the initialization-based revisions (2024-11-05
to 2025-11-25) must keep working, through the fallback rules in the spec's
versioning page.

The official SDK is `rmcp`. At 3.7.0 (2026-10-22) it implements every
revision up to 2026-07-28 with the backward-compatible fallback, a
`StreamableHttpService` (a tower service) with a stateless mode
(`NeverSessionManager`, no `Mcp-Session-Id`) and JSON responses, a stdio
server transport, and a Streamable HTTP client over a Unix socket. It is
Apache-2.0, and its dependencies (`schemars`, `chrono`, `tokio-util`,
`tokio-stream`, `sse-stream`, `tower-service`, `uuid`, `rand`, …) pass
`cargo deny` without changes to `deny.toml`. It depends on tokio's `rt`
and `time` features and spawns tasks internally.

## Decision

- **rmcp, pinned exactly** (`=3.7.0`): following the protocol, its
  revisions and their fallbacks is the SDK's job. An upgrade is a reviewed
  change that reruns `crates/kronik/tests/mcp.rs`.
- **One implementation.** `kronik-mcp` implements `rmcp::ServerHandler`
  over the in-process `kronik_api::Api`: each tool call is an `ApiRequest`
  with the caller's token id, so results, dry runs, `REASON_REQUIRED` and the
  error JSON (`code`, `message`, `hint`, `docs`) are the API's. A tool result
  is the API response as `structuredContent`. A failed call is a result with
  `isError` and the stable error JSON, not a protocol error; only an unknown
  tool is one. `explain` and the concept and error-catalog resources read
  `kronik_core::explain`, as `kronik explain` does.
- **Streamable HTTP at `/mcp` on the API listener.** `kronik_api::server`
  gained `serve_with(listener, api, mount)`: requests to the mount's path go
  to a handler that gets the caller's token id (`SO_PEERCRED` now, tokens in
  M5) and the request with its body read under the API's size limit.
  Responses became a boxed body so that a mount may stream. `kronik-mcp`'s
  `mount` wraps the `StreamableHttpService`: stateless, JSON responses, no
  SSE keep-alive. It passes the token id to the handler through the request
  extensions.
- **`kronik mcp` is a protocol-level proxy.** It serves MCP on stdio with
  rmcp and answers each request with the daemon's answer, through an rmcp
  client on the API socket. Each side negotiates its own protocol revision
  with rmcp, so a host on any supported revision works, and no tool logic
  lives in the CLI.
- **Schemas and scopes.** Every tool has a hand-written input schema
  (mutations require `reason` and accept `dry_run`) and an output schema
  that admits the stable error object. Every tool records the scope it needs
  in `_meta["kronik/scope"]` and in its description. Enforcement comes with
  M5 tokens: the API checks the scope of every route, and MCP calls go
  through the API as the caller.
- **Shell, not core.** `kronik-mcp` serves HTTP like `kronik-api`'s server
  module (ADR 0004 §3). rmcp's tasks and timers run on the daemon's tokio
  runtime; nothing in the deterministic core or the simulator uses them.

## Alternatives

- **Implementing the protocol subset ourselves.** The subset we need is
  small, and it would avoid ~100 crates. But it would mean the 2026-07-28
  per-request metadata and header mirroring, the initialization-based
  fallback, and following the spec as it moves, for both the server and the
  bridge. The SDK already does this.
- **rmcp's model types only**, with our own dispatch: still pulls in rmcp's
  non-optional tokio `rt`/`time` and `chrono`, and leaves the protocol
  handling to us.
- **A byte-level stdio bridge** (stdin lines to `POST /mcp`): it would have
  to derive `MCP-Protocol-Version` and `Mcp-Method` headers per message, and
  remember the negotiated revision for older clients. The rmcp proxy is the
  same size and stays correct across revisions.
- **MCP over the socket with stdio framing** (allowed by the 2026-07-28
  spec for custom transports): one more transport for clients to support;
  Streamable HTTP is what hosts speak.

## Consequences

- An agent gets the same tools on stdio (`kronik mcp`) and HTTP (`/mcp`),
  answered by the same code, with the CLI's error codes and hints.
- The tools whose API endpoints do not exist yet are not listed:
  `trace_turn` (no trace endpoint), `send_to_fork` (no endpoint for messages
  into a fork) and `request_approval` (no pending-approval record), and
  there is no `AGENT_GUIDE.md` resource until the guide exists. Each one
  arrives with its endpoint or document.
- When TCP with tokens arrives (M5), the rmcp host and origin allowlists
  must be configured for the listener's names; on the Unix socket only
  `localhost` is accepted, which is what the bridge and rmcp's Unix-socket
  client send.
- rmcp's minor releases have changed its API. Pinning keeps the protocol
  behavior fixed between reviewed upgrades.
