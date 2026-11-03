# Threat model and security assurance boundaries

## Status and scope

This is an engineering threat model, not an external audit or a statement that
Kronik is ready for production. The source baseline is `d9b946f` on 2026-10-30:
Wasm execution, M22 WASI HTTP, M28 export and M23 B1 KMS custody are present.
The current source and the component contracts were also inspected read-only;
incomplete areas are distinguished below from the baseline. A source path or
regression test is evidence of a control's implementation or intended
invariant, **not evidence that the test passed on the current revision**. No builds,
tests, fuzz campaigns, deployments or external systems were exercised for this
document. Release tags do not automatically contain newer `main` behavior.

This analysis is based on the historical source and regression evidence at
that baseline. Its observations are not a new assessment of the current
integrated system. The integration sections must be reconciled against the
final coherent source and the shipped product.

The build brief requires an updated threat model **and an
independent external security review** for M31. Code reviews, regression tests
and fuzzing do not replace that external review. No completed
independent external review, published advisory, assigned CVE, continuous
crash-free fuzz campaign or absence of serious weaknesses is asserted here.
Historical review notes do not close that gate.

Covered surfaces are the single-node daemon and its guest/foreign execution,
HTTP gateway, JSON API/MCP, policy and proposals, key custody, privacy,
persistence, restore and export. Cluster, fleet, rootless isolation, external
secret backends and the optional PKCS#11 helper introduce additional boundaries;
only their observed baseline behavior or explicitly labeled integration
contracts are described. Supported versions and private vulnerability handling
remain in the root `SECURITY.md`. Operational guidance remains in the
[security guide](../guides/security.md), [privacy guide](../guides/privacy.md)
and [operations guide](../guides/operations.md).

## Principals and assets

| Principal | Authority and trust assumption |
| --- | --- |
| Anonymous gateway client, webhook sender or preview visitor | Controls request paths, headers and bodies; deployed actor routes authenticate their own users. Reaching the gateway is not administrative authorization. Preview proposal code is unapproved and its visitors are untrusted. |
| Wasm actor author and deployed guest | Controls component bytes, imports, guest computation, state operations and effect requests. The guest is hostile; neither its manifest nor a request grants a host capability. |
| Foreign image publisher and running foreign process | Controls image metadata/layers and native code inside the configured sandbox, including application data and output. Digest pinning identifies bytes, not a trustworthy publisher. |
| Scoped API/MCP agent, proposer, approver and operator | Has only its token's scopes, except `admin` implies all. A human or agent can be malicious or mistaken; reviewing a proposal does not authorize unrelated changes. Tokenless Unix-socket access is deliberately full authority. |
| Local administrator and daemon/service account | Controls configuration, code cache, filesystem, runtime binaries, credentials and process memory. Trusted computing base; a hostile root user or kernel is outside the sandbox's protection. |
| KMS/secret provider, credential issuer and optional helper/module | Trusted to implement the selected key/version and access policy. Responses can be unavailable, malformed or revoked. An HSM vendor module is trusted native code, not an untrusted guest. |
| Object-store operator, audit receiver, tracing backend and backup reader | Receives sensitive or reduced data according to the channel. Storage availability, credentials and policy are external assumptions; collectors must not be treated as if they were inside the guest sandbox. |
| Maintainer, dependency/toolchain publisher and release operator | Controls source/build inputs and distribution. Release authenticity/reproducibility is a separate boundary governed by [ADR 0100](../adr/0100-signed-reproducible-releases.md); its current source policy and remaining genuine release gates are separate from this historical baseline. |

Protect these assets:

- **Execution authority:** deployment/code hashes, configuration epochs, grants,
  token scopes, policy, approvals, effect delivery/idempotency state and the
  integrity of the selected actor/branch.
- **History and derived state:** committed log records and LSN ordering,
  `branches/`, actor SQL files, code/precompiled cache, snapshots, restore
  manifests, foreign `/data` copies/checkpoints and object-storage copies.
- **Secrets and personal data:** bearer tokens, master seed and derived keys,
  subject keys, sealed values, secret versions, provider/bootstrap credentials,
  HTTP cookies/authorization headers and private reasons or error text.
- **Availability and accountability:** CPU, host memory, descriptors, disk,
  network/provider budgets, durable mutation intent/outcomes, export cursors,
  retention holds and the ability to recover and attribute operations.

## Data flows and trust boundaries

1. **Public ingress → actor execution.** `crates/kronik-gateway/src/server.rs`
   parses public HTTP and routes into the scheduler. The gateway is not the
   management API and does not authenticate application users. Request/body,
   connection and time limits protect host resources; TLS termination, proxy
   configuration and application authorization are deployment responsibilities.
2. **Guest → host imports → scheduler/effects.**
   `crates/kronik-runtime/src/allowlist.rs`, `engine.rs`, `turn.rs` and `host.rs`
   constrain imports, instantiate fresh guests and expose state, SQL, timers,
   calls, randomness, crypto and HTTP. The host must validate every operation;
   Wasm fuel does not by itself bound host-side allocation, SQLite work or I/O.
3. **WASI HTTP → recorded effect → remote target.**
   `crates/kronik-runtime/src/host/wasi_http.rs` queues WASI 0.2 HTTP, drives it
   deterministically at guest waits and calls the same `EffectGate::fetch` as
   the SDK HTTP import. `crates/kronik-sched/src/effects.rs` checks grants at
   the turn's epoch, records results and mediates delivery, timeouts and secret
   insertion. `crates/kronik-core/src/env/real.rs` performs actual network I/O.
4. **Local/TCP client or MCP tool → management authority.**
   `crates/kronik-api/src/server.rs`, `auth.rs`, `tokens.rs` and `lib.rs`
   resolve identities and scopes before routing. `crates/kronik-mcp/src/lib.rs`
   forwards the caller's identity/bearer to the same API; tool text and model
   output are not a second authorization mechanism. A socket group member can
   omit a bearer and become a fully privileged local caller.
5. **Proposal/fork → production switch.**
   `crates/kronik-fork/src/proposal.rs`, `replay.rs`, `privacy.rs` and
   `crates/kronik-policy/src/lib.rs` separate replay from live effects,
   evaluate policy, bind approvals and re-evaluate on catch-up. The scheduler
   switch gate is in `crates/kronik-sched/src/gate.rs`. Pseudonymized replay
   cannot prove behavior on real personal data.
6. **Foreign bytes/process → privileged host.**
   `crates/kronik-foreign/src/image.rs`, `blobs.rs` and `oci.rs` verify pinned
   content and unpack images. `runtime.rs`, `manager.rs` and `checkpoint.rs`
   construct/start sandboxes and fork copies. Parsing and copying occur on the
   trusted side before native code runs; the runtime's state and checkpoints
   can contain resolved secrets and are sensitive.
7. **Daemon → key source/provider/helper.**
   `crates/kronik-privacy/src/key_source.rs`, `key_source/config.rs`,
   `key_source/providers.rs` and `key_memory.rs` load/protect the master seed.
   Local secret storage is in `crates/kronik-privacy/src/lib.rs`; subject
   sealing/erasure is in `keystore.rs` and `sealer.rs`. Provider credentials are
   separate authority, not encrypted automatically by selecting a KMS.
8. **Commit → disk/snapshot/remote copy → restore.**
   `crates/kronik-log/src/lib.rs`, `crates/kronik-store/src/snapshot.rs`,
   `crates/kronik-sched/src/snapshots.rs`, `crates/kronik-ship/src/lib.rs` and
   `crates/kronik/src/restore.rs` carry data across persistence and backup
   boundaries. The bucket is not a plaintext-safe telemetry sink. Restore must
   validate data, keys, paths and compatibility before installation.
9. **Committed history → API projection/audit/telemetry sink.**
   `crates/kronik-api/src/redact.rs`, `crates/kronik-sched/src/scrub.rs` and
   `crates/kronik-otel/src/{audit,spans,follow,sink,cursor}.rs` reduce disclosure
   and track publication. [ADR 0082](../adr/0082-what-leaves-the-node.md) defines
   export policy; observed format/privacy gaps below are not erased by that
   policy. Once copied to a collector, data is outside Kronik's erasure control.

## Threat → control → evidence → residual risk

The regression paths below identify existing source to exercise on the final
integrated revision. They are not a test-run report or exhaustive coverage.

| Threat and affected boundary | Baseline control and source | Regression/evidence source | Residual risk or required validation |
| --- | --- | --- | --- |
| A hostile component escapes the guest or retains another turn's memory | Import allowlist and fresh Wasmtime instances; fuel and memory limiter in `crates/kronik-runtime/src/{allowlist,engine,host,turn}.rs` | `crates/kronik-runtime/tests/determinism.rs`; engine/allowlist unit tests | Wasmtime/compiler, host Rust and SQLite remain trusted. The local precompiled cache is trusted native-code input, not safe to replace from an untrusted upload. Limits must cover host work too; SQL per-statement memory remains a baseline gap. |
| Guest HTTP bypasses grants, smuggles secret bytes or gains unrecorded I/O | WASI hook never sends directly; same recorded effect gate, host/secret grants, bounded bodies/responses, pending-request cap and effect timeout in `host/wasi_http.rs` and `kronik-sched/src/effects.rs` | `crates/kronik-runtime/tests/wasi_http.rs`; `crates/kronik-sched/tests/effects.rs`; URL/scrub unit tests in `crates/kronik-effects/src/http.rs` | Host grants are not a private-IP/DNS/port firewall. The real client supports HTTP and HTTPS; a granted host may reach internal services or receive inserted credentials. No automatic redirect-following is implemented by `RealNet`; any guest retry/new target must pass the gate again. Do not grant destinations or plaintext transports you would not trust with those credentials. |
| Anonymous HTTP exhausts the daemon or attacks response framing/browser origin | Gateway bounds and response-header/status filtering in `crates/kronik-gateway/src/server.rs`; API body/head/time limits in `crates/kronik-api/src/server.rs`; preview handling in `crates/kronik-api/src/preview.rs` and gateway | `crates/kronik-gateway/tests/gateway.rs`; API server unit tests | Limits are not a volumetric DoS service. Proxies change the source-address accounting boundary. Use a separate registrable preview domain; same-origin previews rely on filtering/sandbox restrictions. TLS does not authenticate application users. |
| Token theft or an agent confuses read/propose with operate/approve/promote | Hashed token store, revocation and route scopes in `crates/kronik-api/src/{tokens,auth,lib}.rs`; TCP bearer before body; MCP forwards credentials for each API call | `auth.rs`/`tokens.rs` unit tests; `crates/kronik-api/tests/mutations.rs`; `crates/kronik-mcp/src/lib.rs` and tools | `admin` and tokenless socket access are full authority. Scope holders can combine powers; this is not mandatory separation of persons. MCP/prompt injection can misuse already-granted authority, so keep agent scopes narrow. |
| A stale, synthetic or PII-masked proposal becomes production without sufficient review | Policy, approval and catch-up checks in `crates/kronik-fork/src/proposal.rs`; code-level PII approval floor in `crates/kronik-policy/src/lib.rs` ([ADR 0031](../adr/0031-pii-masked-approval-floor.md)) | `crates/kronik-fork/tests/{proposals,retention,rebase,simulators}.rs`; `crates/kronik-policy/tests/policy.rs`; `crates/kronik-api/tests/privacy.rs` | Approval authorizes bounded observed evidence, not all future traffic. PII-masked/unverified counts can grow during catch-up; an approval is not proof of real-value correctness. Pending cross-node/fleet approval binding needs separate evidence. |
| A hostile OCI archive writes outside its rootfs, or a native guest escapes confinement | Digest validation, bounded image metadata, path/symlink handling and clearing setid bits in `crates/kronik-foreign/src/{image,blobs,oci}.rs`; gVisor sandbox/network and resource configuration in `runtime.rs`/`oci.rs` | OCI unit tests include hostile symlinks and setid clearing; runtime unit tests; `crates/kronik-fork/tests/foreign.rs` | `trusted` selects runc and is not the gVisor boundary. Image digest is not publisher provenance. Real Linux/runsc/cgroup/checkpoint behavior needs host-specific proof. Root-owned foreign data and process environment/checkpoints can contain secrets. |
| Secrets leak through effects, history, diffs or guest output | Host-side header/crypto handles; separate reveal capability; structured exact-value scrubbing before records in `crates/kronik-sched/src/{effects,scrub}.rs`; API projections in `crates/kronik-api/src/redact.rs` | `crates/kronik-api/tests/api.rs`; `crates/kronik-sched/tests/effects.rs`; scrub unit tests | Exact matching skips values under four bytes and JSON words `true`, `false`, `null`; it does not catch transformed/split values. Revealed data can be exfiltrated or passed to another actor's unsanitized call input. Ordinary forks may use production keys for unmatched crypto; preview crypto must not. |
| Stolen disk/bucket reveals all history, or erasure is undone by old copies | XChaCha20-Poly1305 secret/subject stores and subject-key erasure; sealing/reseal and snapshot/key checks in `kronik-privacy`, `crates/kronik-sched/src/{privacy,sealing,reseal,snapshots}.rs` and `kronik-ship` | `crates/kronik-api/tests/{privacy,reseal}.rs`; `crates/kronik-sched/tests/erasure_snapshots.rs`; `crates/kronik-ship/tests/keystore.rs` | Privacy mode seals subject-tagged values, not all fields. Actor keys, ordinary inputs, random seeds, SQL materializations/snapshots and guest/operator logs may remain sensitive. Disk encryption/access control and external backup lifecycle are still required. Losing retained subject/provider keys can make restoration impossible. |
| A KMS outage, substituted envelope or overprivileged bootstrap credential compromises custody/recovery | Shared loader, purpose-bound provider requests where supported, verification before publication, no replacement seed over existing stores, scoped TLS and locked/non-dumpable long-lived keys in `kronik-privacy/src/{key_source,key_memory}.rs` | `crates/kronik-privacy/src/key_source/tests.rs`; `crates/kronik-ship/tests/keystore.rs`; historical B1 evidence in the project status page | A running node holds the plaintext seed; KMS custody is not protection from live root. Restart/offline operations require the provider. Co-stolen credentials plus an envelope can permit unwrap. Rewrap is not seed rotation; old wrapping-key versions must remain available for retained backups. Ordinary library/HTTP buffers are not all locked or wiped. |
| Corrupt/truncated records or hostile restore data change committed history | Length/CRC/contiguous-LSN and Protobuf validation in `crates/kronik-log/src/lib.rs` and `crates/kronik-proto/src/lib.rs`; snapshot/file/key/engine checks in scheduler, shipper and restore | `crates/kronik-log/src/tests.rs`; `crates/kronik-sched/tests/snapshots.rs`; `crates/kronik-ship/tests/{ship,keystore}.rs` | CRC and public hashes detect corruption, not an authorized writer forging history. Active-tail recovery truncates from the first bad envelope. Restrict write authority, keep independent backups and test recovery; external object-store IAM/versioning is not proven by local fixtures. |
| Mutation accountability is lost or audit/telemetry becomes a disclosure channel | Nonempty reasons and source audit records; explicit intent/failure events; reduced span/audit projections, fail-closed inventory preparation and durable sink/cursor handling in API, scheduler scrub and `kronik-otel` | `crates/kronik-api/tests/{mutations,api}.rs`; `crates/kronik-otel/tests/{audit,audit_export,follow,cursor,spans}.rs` | Intent is not success. Receivers can retain reduced data indefinitely; actor-key `plain` mode is opt-in disclosure. Baseline `kronik.audit/v2` uses public BLAKE3 commitments: neither authentication nor a general guarantee against guessing private low-entropy metadata. Keyed v3 migration and complete retained secret inventory are integration gates below. |

## Assumptions and non-goals

- The operator protects the host/kernel, writable code cache, daemon binary,
  service unit, configuration, runtime/helper binaries and credential files.
  `deploy/systemd/kronik.service` is the actual installed foreign-capable
  baseline: root is implicit, with explicit hardening omissions for runsc and
  JIT/checkpoint compatibility ([ADR 0027](../adr/0027-systemd-unit-hardening.md)).
  It is not a generic least-privileged/rootless service. Wasm-only permission
  proof does not establish rootless foreign execution.
- Hostname capabilities are intentional egress authority, not tenant isolation
  or a guarantee against SSRF to a trusted destination. Provider-specific
  custom CA/client identity must not widen the guest effect client's trust.
  The operator owns DNS, endpoint selection, TLS/proxy termination, credential
  policy and object-store permissions. These cannot be inferred from source.
- Personal data must be tagged correctly; plaintext fields, reasons, identifiers
  and guest diagnostic logs are not magically sealed. `pii:read` is permission
  to inspect protected data, not a general multi-tenant partition. Copied data,
  older plaintext backups and third-party collectors need their own lifecycle.
- Sandboxing does not make guest business logic safe, prove correctness of a
  replay window, stop a malicious holder of an authorized secret destination,
  or prevent all resource exhaustion/side channels. A compromised privileged
  host can read active keys and forge local history. Physical/HSM side-channel
  resistance and real-cloud IAM correctness require evidence outside source.
- Signed release and reproducibility rules are not repeated here. Follow
  [ADR 0100](../adr/0100-signed-reproducible-releases.md), including its explicit
  remaining two-build and genuine public release evidence. Checksums, a source
  policy or an upstream verification fixture alone are not a signed Kronik
  release.

## Pending integration and architecture boundaries

These are requirements to reconcile against the **final integrated revision**,
not claims that in-progress source or newly added modules protect a deployment.
Do not infer accepted milestone behavior from a design header or file existence.

### External secret backends and helper

The B1 baseline supports file/environment master seeds and OpenBao/AWS/GCP/Azure
KMS wrapping. It does not establish accepted end-to-end B2–B6 external-secret or
PKCS#11 behavior. The work-in-progress paths
`crates/kronik-privacy/src/secret_backend.rs`,
`crates/kronik-sched/src/secrets.rs`,
`crates/kronik-core/src/env/real/exchange.rs` and `crates/kronik-keyhelper/src/`
were inspected as integration context, not baseline guarantees.

The component contracts require trusted current provider configuration and immutable
version/binding checks; durable turn admission before provider I/O; forks without
new provider I/O; complete retained-value inventories across log/state/snapshots
and paginated catalogues; fail-closed incomplete inventory; and no operational
fallback to scrub-only bytes. Synchronize the actual API/CLI, live-guest, fork,
foreign-environment, export and restart consumers before changing the baseline
claim. Local resolver/helper tests do not establish those consumers.

The optional GNU/glibc PKCS#11 helper keeps vendor module loading out of the musl
daemon. Its contract treats the configured module as trusted native code and
checks its path/digest, token manufacturer/model/serial, unique key identity and
enrolled probe before wrapping. Path/digest checks establish load integrity,
not cryptographic AAD. The PIN is passed through a private descriptor, not argv
or an environment value; bounded framing, deadline, process-group kill/reap and
private diagnostics constrain accidental leakage/resource use, not a malicious
trusted module that escapes its process group. Controlled zeroizing buffers do
not establish wiping of Cryptoki/vendor buffers or no-swap external caches.
Actual provider dispatch, SoftHSM behavior and any physical/vendor HSM claims
need their own evidence. See [the M23 design](m23-secret-backends.md) and
[ADR 0093](../adr/0093-pkcs11-through-a-helper-process.md). Neither a planned
backend nor a helper protocol fixture closes those gates.

### Cluster and fleet

No cluster/fleet security guarantee is established by this single-node baseline.
The integration work must reconcile these boundaries before they can be
advertised as protection:

Work-in-progress source paths, **not baseline interfaces**, are
`crates/kronik-cluster/src/{net,identity,admission,wal,meta,barrier,rate}.rs`
and `crates/kronik-fleet/src/{enrollment,transport,events,webhook}.rs`.
The cluster contract uses TLS 1.3 mutual authentication, committed membership
and receiver-local revocable admission; its canonical endpoint/boot proof
excludes compliant different-listener clones, not Byzantine holders of stolen
keys. It assumes exclusive canonical routing and intact original durable state.
Turn-caused provider I/O must follow the exact majority-fsynced `TurnBegin`,
not merely committed secret-version metadata. External values must not be
side-replicated as if they were built-in encrypted secrets.

The fleet contract pins an HTTPS controller and its CA identity, stages a local
leaf key and CSR before enrollment and uses an installation-originated mTLS
tunnel. Full ordinary HTTP/SSE/WebSocket parity through the existing API server
is still being integrated; the finite control RPC source is not proof of that
parity. Transport admission is not mutation admission: the original ordinary
token authority and managed enrollment epoch/request identity must reach the
final durable enqueue, including body waits, forwarding and queued work.
Durable member control/token projections and startup publication under the
same authorization fence also remain integration requirements. Loss of remote
credential custody must deny remote admission without preventing local
status/revocation. Events use typed actor/shard
or metadata positions, not a fabricated global LSN. Webhook signing must bind
the real prepared event body and immutable M23 secret identity, with durable
retry/replay cursors. Actual binary/NAT/revocation, webhook tamper/lost-ACK and
cross-node crash/restart evidence remain separate integration requirements.

- Peer/node identities, authenticated and encrypted transport, enrollment,
  membership changes and credential rotation/revocation. Network reachability
  or a self-reported node id must not become management authority.
- Ownership/placement epochs, stale-leader fencing, forwarding and retries:
  authority and durable commit must hold at the final mutation point, not only
  at an ingress scope check or cached observation.
- Fleet target/tenant selection, proposal/diff identity, policy, approvals and
  operation reasons across remote calls. A coordinator must not become a
  confused deputy that broadens the initiating token's authority.
- Event/webhook credentials, schema and replay/idempotency boundaries, plus
  scrubbed exports and durable audit attribution across nodes and restores.
- Cluster-owned audit-v3 keyed commitments and their real API/export/verifier,
  archive/restore, rewind and compatibility consumers. Baseline v2 public-hash
  behavior must not be described as keyed/private before cutover and proof.

Exact final source paths, network topology, credential custody and cross-node
failure evidence must be synchronized with the implementation; there is no
claimed three-node isolation, production deployment or external-network proof
here.

## Assurance and external review

For a security-relevant change, refresh the applicable row and its residual
risk, include a minimal regression fixture at the real boundary and record
commands/results against one integrated revision. Fuzz coverage must name the
actual log/Protobuf/HTTP/host entrypoints, bounds, corpus, duration and retained
crashes; merely compiling a target or having no local crash report is not
continuous fuzzing or all-host coverage. Run potentially hostile fixtures only
in a bounded isolated environment without production data or credentials.

The independent external review still needs an independent reviewer, agreed
revision/scope and deployment assumptions, coverage of the integrated cluster,
fleet and key boundaries, and a written findings/verification record. Confirmed
severe findings require verified fixes before the review gate closes; a
maintainer decision is not a substitute for fixing them. Maintainers must distinguish
confirmed findings from deployment facts that still need validation and from
untested source hypotheses. The implementation cannot
self-certify that external gate. Vulnerability publication, affected/fixed
version ranges and CVE coordination follow the root `SECURITY.md` process; do
not fabricate advisories or expose private findings in this document.
