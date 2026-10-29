# Status

Last updated: 2026-10-29

The history was squashed on 2026-10-28 into `Kronik v0.1` (0c3c266) and
force-pushed. Commit ids from before the squash, here and in the ADRs,
refer to the earlier history, which the owner keeps; so do the milestone
tags `v0.0.0` to `v0.0.8`.

## Current milestone

v0.1 is done; publishing it is the owner's (Open questions). M0 to M8 are
closed and tagged, `v0.0.0` to `v0.0.8`, M2 to M8 on 927c80a. On main, v0.1
ends at 4353863: `Kronik v0.1` (0c3c266), main's CI fixes and the keystore
restore fix. After the milestone tags v0.1 gained six fixes:

- Promote pins the code of changed kinds (`PROPOSAL_STALE`): 24fef29, and
  07bdeae, which pins it at the proposal's creation head instead of its
  fork point.
- Image unpacking clears setuid and setgid bits: 2858e0b.
- The systemd unit: no foreign actor started under it until 24c6dbc removed
  its `User=root` line; e3fb81a keeps `RestrictSUIDSGID`, makes the runtime
  state directories 0700 and adds a `doctor` check for `CAP_SETUID` (ADR
  0027).
- Bulk replay: a turn begun in an earlier batch is closed by its record, so
  the state rebuilt from the log equals the recovered state again (dfaedd7;
  6c04dea adds the DST `rebuild` workload). The crash test found it at
  cc2cd52.
- The master key: one loader for start, keystore shipping and restore, and
  no new key over existing stores (`MASTER_KEY_MISSING`,
  `MASTER_KEY_MISMATCH`; ffea125); a restore fails before writing when the
  bucket's keystore backup can't be installed (2ebae98).
- Restore and the keystore: restore installs the newest keystore backup and
  checks that it holds every key the restored data needs
  (`KEYSTORE_INCOMPLETE`, `--allow-missing-keys`), installs by renames only,
  and the shipper's keystore stamp includes the WAL: eb60bab and 4353863,
  verified as 329da48 before their rebase onto d80e52a. Quickstart walk 4
  found the bug: restore installed an older keystore backup, so sealed
  values were unreadable; a restore without the master key succeeded, and
  replay answered that privacy mode arrives later.

Also since the tags: test and crash-test ports below the ephemeral range
(0cf94d7, 2491abc), the quickstart walk 3 follow-ups (a7234ab, ba188e7), a
regenerated `openapi.json` (49d811a), and fixes for GitHub Actions: the ops
test's KVM check (de7b696), the TS test glob (64ae700),
`identity-examples.sh` (eb1218e), and the foreign step as root with gVisor
and the musl target (d80e52a).

v0.1's evidence, 2026-10-28:

- `scripts/ci.sh`, every step (`foreign` and `identity` included), passed at
  e3fb81a on dev.
- The testbench batch passed at e3fb81a: 56 of 56 suites in the rows M1 to
  M9 and `identity`, `M7/foreign-unit` included, 12:47 to 13:38 UTC.
- On dev at 2491abc: the crash test (1 000 cycles, 20 rebuild checks) and
  DST (30 000 runs, 10 000 webhook runs with `webhook-relay-ts`, 10 000 runs
  of the `rebuild` workload, 1 000 000 steps twice), all without a failure.
  They carry over to e3fb81a, whose changes since 2491abc touch only the
  unit, `init`, `doctor`, kronik-foreign's runtime directories and image
  packer, `openapi.json` and docs.
- At 329da48, the keystore fix: `scripts/ci.sh`, every step, passed on dev,
  and the testbench rows M6, M8, `identity` and `M7/foreign-unit` passed,
  19 of 19 suites, 18:31 to 19:01 UTC. The fix touches restore, the
  keystore, shipping, CLI messages and docs, and gives a sealed value
  without its key its own error; the crash test and DST meet none of that,
  so their results carry over.
- Quickstart walk 4, 13:47 to 14:09 UTC on travelfiesta in a fresh
  ubuntu:24.04 container with e3fb81a's release, passed steps 1 to 8 (in
  5 min 51 s) and step 10 on the source node; its step 9 found the bug
  above. The re-check of step 9, 19:05 to 19:14 UTC with 329da48's
  release: the restore with the right key installed the keystore
  (`integrity` lists no missing keys, sealed state readable), and restores
  without a key, or with a wrong one (`MASTER_KEY_MISMATCH`), were refused.
  The refused wrong-key restore still created the absent directory and an
  empty `keys/`; 247bf5a, after v0.2, fixes that. MCP on a restored node,
  2026-10-28, 23:27 to 23:34 UTC, with f957475's release: the restore with
  sealed values installed the keystore (`keys_missing` empty), and an agent
  without `pii:read` replayed 6 of 6 root inputs over stdio MCP without an
  `INTERNAL`; the PII floor (`pii-masked-needs-approval`) fired for the 2
  masked turns.
- GitHub Actions CI passed on main at eb1218e, d80e52a and 4353863.

v0.2 landed with f957475 and v0.3 with 189c8c3 (their sections), and v0.3
passed the testbench. Whether to stop or continue is the owner's (Next).
Other work is parked (Parked work).

The testbench is `travelfiesta`: Debian 13, 2 vCPU Skylake, 3.7 GiB, no
`/dev/kvm`, gVisor `release-20261019.0` with systrap. The batch
(`/var/tmp/kronik-batch/run.sh` on dev and on the testbench, not in the
repository) runs its suites one at a time under the testbench lock, with
release binaries built on dev from one commit; a row of M9 or later runs
only at a commit that has its milestone. Logs are in
`/var/tmp/kronik-batch/logs/` on the testbench. The whole batch passed at
68008f9 and at 927c80a (52 of 52 suites, 2026-10-27), at e3fb81a (56 of 56),
with v0.2's rows at c626ede (67 of 67, 2026-10-28), and with v0.3's rows at
94d20ac (88 of 88, 2026-10-29).

## M0: repository and spikes (closed, `v0.0.0` on 89a8b34)

- [x] Workspace following the repository layout, `rust-toolchain.toml`
      (Rust 1.99.1), edition 2024.
- [x] CI with fmt, clippy `-D warnings`, tests and cargo-deny. The CI of
      record is `scripts/ci.sh` (12 steps), which passed every step on dev
      at a3dce8f (537 s), adddce8 (606 s) and 0403ac2 (659 s) on 2026-10-26
      and at 927c80a (664 s) on 2026-10-27, with `foreign` and `identity`
      run (`todo-ts` included). GitHub Actions CI is green on main since
      eb1218e (2026-10-28).
- [x] `LICENSE` (ELv2), `NOTICE`, `CONTRIBUTING.md` with `CLA.md`,
      `SECURITY.md`, `STATUS.md`, `docs/adr/0000-template.md`.
- [x] `kronik --version` prints Kronik's, Wasmtime's (50.0.0) and the
      engine's versions.
- [x] Spikes A to E with ADRs 0001 to 0005. Spike C ran on the testbench's
      kind of host, without `/dev/kvm`. The spikes are archived under
      `spikes/` and not maintained.

Testbench: no batch row.

## M1: durable turns on one node (closed, `v0.0.1` on 5e51426)

- [x] WIT v0.1 (`state`, `sql`, `context`, `messaging.send`, `log`), the Rust
      SDK (`sdk/rust`), `counter-rs` and `notes-rs`.
- [x] Log with segments, CRC, group commit (2 ms) and fsync; LSNs strictly
      increasing across every record kind; `TurnRecord` in Protobuf;
      `state.db`; recovery at startup (`kronik-log`, `kronik-store`,
      `kronik-sched` tests).
- [x] Enum value 0, unknown enum values and unknown record kinds are
      `STORAGE_CORRUPT` (`kronik-log`, `kronik-proto` tests).
- [x] Gateway without TLS, with routes from `describe`.
- [x] CLI: `serve`, `deploy`, `send`, `actors inspect`, `history`,
      `dead-letters` and `explain` (`crates/kronik/tests/cli.rs`).
- [x] 10 000 increments give `n = 10000`; `kill -9` under load gives `n` =
      acknowledged; SQL rows after `kill -9` equal the acknowledged inserts,
      and the database rebuilt from the log has the same canonical hash and
      answers (`scripts/acceptance-m1.sh`, test and example guests).
- [x] SQL schema recorded as DDL; DDL outside `migrate` or after DML is
      denied. SQL determinism: `random()` and `datetime('now')` repeat;
      `ATTACH`, extensions, `VACUUM`, `ANALYZE` and storage pragmas are denied.
- [x] Ingress idempotency (one turn per key; another body is
      `IDEMPOTENCY_KEY_REUSED`), dead letters and `dead-letters resend`
      (`scripts/e2e-m1.sh`, `cli.rs`).
- [x] Logical time monotonic and causal (`kronik-sched` tests and every DST
      run; ADR 0006). The guest cannot read the execution id; `causal-id`
      is the same on a re-run.
- [x] The determinism test (`kronik-runtime/tests/determinism.rs`).
- [x] `kronik-sim` counter workload with crashes: 200 seeds, each twice,
      identical traces (`scripts/ci.sh dst`).

Testbench: row M1 (e2e-m1 and acceptance-m1 with the test and the example
guests, dst, perf-m1, determinism, node, gateway, version) passed at
68008f9 and 927c80a (2026-10-27) and at e3fb81a (2026-10-28).

## M2: effects and capabilities (closed, `v0.0.2` on 927c80a)

- [x] `http.fetch`, timers and `call` with cycle detection, timeout and
      optional compensation (`kronik-sched` effect tests).
- [x] Secret handles in headers, `crypto.hmac-sha256`,
      `crypto.sign-ed25519`, `secret.reveal` behind `secret-reveal:<name>`;
      `secret set|list|delete`, encrypted under the master key.
- [x] Grants as log records with delivery class and rate; `grant` and
      `revoke`.
- [x] Without a grant the guest gets `denied`, and the CLI shows
      `CAPABILITY_NOT_GRANTED` with the exact `kronik grant` command
      (`cli.rs`).
- [x] Rate `2/s` never exceeded at send time, across restarts (in-process
      test; DST checks every run's sends).
- [x] SIGKILL tests (`crates/kronik/tests/kill.rs`): `TurnBegin` is on disk
      before the first effect; a crash after a recorded result sends nothing
      twice and the re-run's request is byte-identical; keyed targets are
      retried with the same key; `unsafe` ones are not, and the turn ends
      `EFFECT_OUTCOME_UNKNOWN` in dead letters with the request; a crash
      around `call` gets the callee's saved response.
- [x] Compensation delivered once; without one the change is in
      `history --orphans`; a failing compensation is a dead letter and the
      orphan stays until a resend succeeds.
- [x] No secret leaks without `secret-reveal` (every data file scanned);
      with it, the value is scrubbed from the log and diffs.
- [x] `webhook-relay-rs` signs with `crypto.hmac-sha256` and is green in DST
      against a simulated service (the `webhook` scenario).

Testbench: row M2 (kill, effects, e2e-webhook-relay, its body-v2 variant)
passed at 68008f9 and 927c80a (2026-10-27) and at e3fb81a (2026-10-28).

## M3: fork, replay and behavior diff (closed, `v0.0.3` on 927c80a)

- [x] `fork create`, `replay`, `diff show`, `propose`, `promote` and
      `rollback` against a real `kronik serve` (`cli.rs`).
- [x] Identity replay of 10 000 recorded requests is empty, isolated and
      continuous (`kronik-fork`, `identity_replay_of_10k_requests`).
- [x] Counter `+2`: changed responses and state, 0 synthetic effects.
      Webhook relay with a changed body: changed effects, approximate
      grounding, confidence below 1, grounding per target.
- [x] Isolation: no follow-on divergence; byte-identical diffs with 1, 4
      and 16 workers. Causal grouping: one origin with 1 000 consequences.
      Continuous replay shows drift in `cumulative`.
- [x] Sampling: the same sample per proposal, coverage in the diff, and
      `payments-full-coverage` stops promote under a sample.
- [x] The same fork and code twice give a byte-identical diff.
- [x] Promote runs catch-up; `Deployment` carries the epoch,
      `verified_through_lsn` and the unverified gap; a catch-up that finds
      a new error stops promote; promote switches at a recorded LSN and
      rollback restores the behavior (a schema change is refused with
      `ROLLBACK_SCHEMA_CHANGED`).
- [x] `demo/verify-change.sh` on a VPS in under 10 minutes: 18 s on
      travelfiesta at 162b08d.
- Replay at 20x real time (performance target): met on travelfiesta at
  970cb81, 12 000 requests at 200 req/s, in every mode: isolated 34.8x to
  40.9x, continuous 27.1x to 28.6x, both 22.4x to 24.3x (`docs/perf.md`).

Testbench: row M3 (fork-tests with the ignored ones, api, cli,
verify-change, replay-speed) passed at 68008f9 and 927c80a (2026-10-27) and
at e3fb81a (2026-10-28).

## M4: the TypeScript SDK (closed, `v0.0.4` on 927c80a)

- [x] `@kronik/sdk` (`sdk/ts`), `kronik init --lang ts|rust` and `kronik
      build`, which checks for Node.js 22.20 or later
      (`scripts/e2e-init.sh`).
- [x] `counter-ts`, `todo-ts` and `webhook-relay-ts` pass the Rust
      versions' acceptance scripts: M1 (`M1_GUESTS=ts`, with `counter-ts`
      and `notes-ts`), M2 (`e2e-webhook-relay.sh` and webhook DST with
      `webhook-relay-ts`) and M3 (`demo/verify-change.sh` with `counter-ts`).
      `todo-ts` has no Rust twin; its tests run in `scripts/ci.sh ts`.
- [x] CI checks the TypeScript components' imports against the allowlist
      (`scripts/ci.sh ts`).
- [x] Test kits for both SDKs: `kronik_sdk::testkit` and
      `@kronik/sdk/testkit`.

Testbench: row M4 (e2e-m1-ts, acceptance-m1-ts, e2e-webhook-relay-ts,
dst-webhook-ts, verify-change-ts, e2e-init) passed at 68008f9 and 927c80a
(2026-10-27) and at e3fb81a (2026-10-28).

## M5: policy, API and MCP (closed, `v0.0.5` on 927c80a)

- [x] CEL policy with the default rules; `policy set`, `show` and `test`;
      `approve` (`kronik-policy` tests, `cli.rs`).
- [x] The JSON API with OpenAPI (the committed `openapi.json` is checked
      against the routes), tokens and scopes (`tokens.rs`), and `reason` and
      `dry_run` on every mutation (`kronik-api/tests/mutations.rs`).
- [x] MCP server, over Streamable HTTP and the stdio bridge, with the tools
      and `AGENT_GUIDE.md` (`crates/kronik/tests/mcp.rs`).
- [x] A scripted MCP client runs the golden path with only the documented
      tools, in CI (`crates/kronik/tests/agent.rs`).
- [x] The policy blocks a proposal that changes a payment effect until
      `approve`; `payments-must-be-exact` fires on one target at a total
      confidence above 0.99 (`agent.rs`, `kronik-policy/tests/policy.rs`).
- [x] Every CLI command has `--json` with a published schema
      (`cli/schemas.rs` checks `docs/reference/json.md`).

Testbench: row M5 (tokens, mcp, agent, schemas, mutations, policy, cel)
passed at 68008f9 and 927c80a (2026-10-27) and at e3fb81a (2026-10-28).

## M6: operations on a VPS (closed, `v0.0.6` on 927c80a)

- [x] TLS from files and by ACME (TLS-ALPN-01), the systemd unit,
      `serve --init` and `doctor` (`crates/kronik/tests/ops.rs`). ACME is
      tested only against Pebble (`scripts/e2e-acme-pebble.sh`): there is
      no public DNS name.
- [x] Snapshots, shipping to S3-compatible storage, `restore`, retention and
      compaction (`m6_cli.rs`, `kronik-api` and `kronik-sched` M6 tests,
      `kronik-ship` against Garage, `kronik-fork/tests/retention.rs`).
- [x] `/metrics` in Prometheus format and structured JSON logs (`ops.rs`).
- [x] `install.sh` and static musl binaries for x86_64 and aarch64, with
      `SHA256SUMS` and a CycloneDX SBOM (`scripts/release.sh`;
      `scripts/e2e-install.sh` installs in a clean Ubuntu 24.04 container,
      with and without `runsc`).
- [x] `demo/vps-restore.sh`: load, restore into a new data directory, the
      same state hash and history. It runs two data directories on one VPS
      against Garage v2.5.0, not two VPSs.
- [x] `kronik upgrade check` replays with the new binary and requires an
      empty diff; the new engine's start records `EngineUpgrade`, and a
      diverged history exits 1 with the diff (`m6_cli.rs`,
      `kronik-fork/tests/upgrade.rs`).
- Startup with 1 GiB of log after the snapshot in under 30 s (performance
  target): met on travelfiesta, 16.7 s to 20.1 s at c852dae and 7e50134
  (`docs/perf.md`), and in the batch (`M6/startup-speed`): at 68008f9,
  18.4 s to 19.0 s without `state.db` and 14.9 s to 16.7 s with it; at
  927c80a, 19.1 s to 21.4 s without and 16.7 s to 17.5 s with it; at
  e3fb81a, 19.2 s to 19.8 s without and 15.8 s to 17.2 s with it.

Testbench: row M6 (ops, m6-cli, api-m6, snapshots, vps-restore, ship-s3,
keystore, acme-pebble, install, install-runsc, startup-speed) passed at
68008f9 and 927c80a (2026-10-27) and at e3fb81a (2026-10-28).

## M7: foreign actors in gVisor (closed, `v0.0.7` on 927c80a)

- [x] `foreign add`, `list`, `logs` and `remove`, from registries, local OCI
      layouts and bundles, with `runsc` and systrap
      (`crates/kronik/tests/foreign.rs`).
- [x] `foreign-echo` runs without `/dev/kvm`, and an actor calls it via
      `foreign://echo/...` (same test).
- [x] The calls are recorded as `foreign.http`; replay matches them and
      starts no sandbox.
- [x] Outgoing network from the sandbox is blocked: TCP to public,
      link-local, Docker and host addresses, UDP DNS and name resolution
      fail, and the namespace has only `lo` (same test).
- [x] `billing-ts` with `fake-payments` runs the whole demo, approval via
      policy included (`demo/billing.sh`).

Testbench: row M7 (foreign, billing) passed at 68008f9 and 927c80a
(2026-10-27) and at e3fb81a (2026-10-28). That acceptance ran outside
systemd: the tests and the demo start the daemon by hand, which is how the
two unit findings in Known gaps went unnoticed. The batch's
`M7/foreign-unit` runs foreign actors under the unit as `serve --init`
installs it, and checks the unit's settings with systemctl. It passed at
24c6dbc (2026-10-27) and at e3fb81a (2026-10-28, with `RestrictSUIDSGID`):
an image with setid entries ran, and a call through it answered `200 ok`.

## M8: privacy mode (closed, `v0.0.8` on 927c80a)

- [x] Subject tags per value from the SDK (`set_for`, a mid-turn
      `set_subject`) and the gateway (`subject_from`), recorded in `off`.
- [x] `on`: sealed values, a keystore with the master key (or
      `KRONIK_MASTER_KEY`) and an encrypted backup that is shipped and
      restored (`privacy_mode.rs`, `kronik-ship/tests/keystore.rs`).
- [x] `erase` makes the subject's data unreadable in log, state and
      snapshots, and `history` shows `[erased]` (`privacy_mode.rs`,
      `kronik-sched/tests/erasure_snapshots.rs`).
- [x] `erase` removes the subject's SQL rows and makes their changesets
      unreadable; a rebuild equals the live databases. Rows in tables
      without `_subject` survive (Open questions).
- [x] `erase` of one subject leaves other subjects' values from the same
      turn.
- [x] `reseal` seals history written in `off` (`kronik-api/tests/reseal.rs`,
      `crates/kronik/tests/reseal_cli.rs`).
- [x] Forks with `--no-pii` replay with pseudonyms and are marked
      `pii-masked`.
- [x] `off` has no measurable overhead compared to M6:
      `scripts/bench-privacy.sh` on travelfiesta, 2026-10-26, base 28aac17
      against 37a9b9b (28aac17 with the M8 commits), 5 runs of 10 s at
      niceness -10. `off` against base: turns/s +0.0%, -1.2% and +0.2%, p99
      -1.1%, +1.1% and -0.5%, CPU per record +0.2%, +0.5% and -0.4% for
      counter, send and notes, all within the noise. `on` costs CPU per
      record +3.5%, +5.5% and +2.6%, and log bytes per record +32%, +34% and
      +57%. Not yet in `docs/perf.md`, which has the dev run. The batch at
      68008f9 measured the same two builds again: `off` no measurable
      overhead, `on` CPU per record +7.6%, +3.6% and +6.2%.

Testbench: row M8 (privacy-mode, reseal-cli, api-reseal, api-privacy,
erasure-snapshots, bench-privacy) passed at 68008f9 and 927c80a
(2026-10-27) and at e3fb81a (2026-10-28). The bench-privacy numbers above
compare fixed builds and do not change with the batch's commit.

## Definition of done for v0.1.0

- [x] M0 to M8 closed with green CI: tagged `v0.0.0` to `v0.0.8`, M2 to M8
      on 927c80a after the final batch. `scripts/ci.sh` passed every step at
      0403ac2, 68008f9, 927c80a, e3fb81a and, with the keystore fix, at
      329da48 (2026-10-28). GitHub Actions CI is green on main since eb1218e
      (2026-10-28).
- [x] A 15-minute quickstart carried out in a fresh environment by someone
      who did not write the code. A fresh agent walked
      `docs/guides/quickstart.md` on 2026-10-26 in a clean container with
      the release binary and found eleven problems, fixed in 0bf1d2d to
      162b08d. A second fresh walk, in a fresh container on travelfiesta
      with adddce8's release, found the retention problem fixed in
      7273648. The third, on 2026-10-27, 17:51 to 17:56 UTC on
      travelfiesta in a fresh ubuntu:24.04 container with the release from
      927c80a, by an agent that did not write the code, passed all 10
      steps, steps 1 to 8 in 3 min 53 s; it found the restore gap (Known
      gaps). The fourth, on 2026-10-28 with e3fb81a's release, passed steps
      1 to 8 in 5 min 51 s and step 10; its step 9 found the keystore bug
      fixed in eb60bab and 4353863, and the re-check of step 9 with
      329da48's release passed apart from one empty directory (Current
      milestone). The walks serve on a local port: there is no public
      install URL, and ACME needs a DNS name.
- [ ] GitHub release with static musl binaries for x86_64 and aarch64,
      checksums and an SBOM. `scripts/release.sh` builds all of it and the
      Release workflow runs by hand; publishing is the owner's action.
- [x] Docs in mdBook: quickstart, concepts, CLI reference, WIT reference,
      error catalog, operations guide, security model, privacy guide and
      `AGENT_GUIDE.md` (`docs/SUMMARY.md`; `scripts/ci.sh docs book` checks
      the generated pages and the links).
- [x] Identity replay empty for all eight example apps, isolated and
      continuous (`scripts/identity-examples.sh`, the `identity` CI step;
      on travelfiesta at 162b08d, 68008f9, 927c80a, e3fb81a and 329da48).
- [x] DST: 10 000 seeds plus a long run of at least 1 000 000 steps,
      without violations: on dev at 2e3740f (`docs/perf.md`); in the GitHub
      nightly at b47780d; and on dev with the nightly's commands at adddce8,
      0403ac2, 68008f9, 927c80a and 2491abc (2026-10-28): 10 000 seeds twice
      over three workloads (30 000 runs), 10 000 seeds of the webhook
      workload with `webhook-relay-ts` twice, and 1 000 000 steps twice, all
      without a failure; at 2491abc also the `rebuild` workload, 10 000
      runs.
- [x] Crash test: 1 000 `kill -9` cycles without violations
      (`scripts/chaos.sh 1000`, as the nightly runs it), on dev. It passed
      at 2491abc, 2026-10-28: 119 913 acknowledged requests, 20 rebuild
      checks from the log alone, 574 unsafe effects dead-lettered as
      outcome unknown and an empty identity replay of 125 667 root inputs;
      restarts were healthy within 11.3 s (p50 0.92 s) on a busy machine.
      It passed before at 9da9e55, adddce8 and 927c80a. At cc2cd52 (v0.2
      integration) its final rebuild check found the bulk-replay divergence
      fixed in dfaedd7. Earlier stops were the machine (out of memory at
      68008f9; a gateway port taken during a restart, fixed in 2491abc) and,
      in the GitHub nightly at b47780d, the check itself (fixed in e8866c1
      and 8b3effc).
- [x] The performance targets measured in `docs/perf.md`: 1 000 turns/s
      across actors (2 770 on travelfiesta; one actor does 180 to 210),
      gateway p99 under 25 ms at 200 req/s (22.9 ms), replay at 20x (22.4x
      and up), startup with 1 GiB under 30 s (16.7 s to 20.1 s; in the
      batch, 14.9 s to 19.0 s at 68008f9, 16.7 s to 21.4 s at 927c80a and
      15.8 s to 19.8 s at e3fb81a).
- [x] Clippy clean, no `unwrap` or `expect` in the daemon's code paths,
      `unsafe` only in the four files of `scripts/unsafe-allowlist.txt`
      (`scripts/ci.sh clippy hygiene`).
- [x] All ADRs written (0001 to 0011, 0027 and 0031 for v0.1), and
      `STATUS.md` reflects the current state.

## v0.1 security review (2026-10-26)

A review of main at 0403ac2 found these, each with a reproduction; the
report is not in the repository.

| Class | Findings | Fixed on | Merged |
| --- | --- | --- | --- |
| The node stopped for good (recovery hit the same record) | H1: privacy on, a subject's turn that called another actor and then failed; H2: secret scrubbing broke encoded call payloads | `fix-v01-secrets` | 68008f9 |
| I8: revealed secrets in effect records, fork logs and diffs, fork code, and the API's base64 | H3 to H6 | `fix-v01-secrets` | 68008f9 |
| Privacy mode: subject data for callers without `pii:read`, idempotent replays across requesters, plaintext after erasure, unkeyed hashes, repeated subject headers | H7 to H12, M3, M5 to M7 | `fix-v01-privacy` | 68008f9 |
| Gateway and API: response desync, end users' credentials in turns, denial of service before authentication, long keys, rmcp debug logs, core dumps, file modes | M1, M2, M4, L2 to L5 | `fix-v01-gateway` | 68008f9 |
| Foreign actors: disk use, cleanup, one daemon per run directory, seccomp for `trusted`, cgroups, directory modes, log scrubbing, `oci-layout` paths, pull timeout | F1 to F10 | `fix-v01-foreign` | 68008f9 |

L1 (keystore growth), L6 (a value passed in a call is the callee's input)
and L7 (copies in untagged outputs) are documented limitations. Also in
68008f9: a code switch finishes when its caller is cancelled
(`fix-switch-cancel`).

A re-review of those fixes found follow-ups, merged at 927c80a:

| Branch | Commits on main | Fixes | Merged |
| --- | --- | --- | --- |
| `fix-v01-privacy-2` | fe34d56, fd7ac24, c71322c to ff953d1 | R1 to R4: snapshots under load, the `--no-pii` request line, retry identity, summaries; a diff with `pii-masked` turns needs an approval (ADR 0031); the privacy guide and M8 design | 927c80a |
| `fix-v01-foreign-datadir` | e378107 | A foreign actor's data directory is 0755 inside its 0700 directory | 927c80a |
| `fix-v01-gateway-2` | f7a7258 to 48c80bf, 62ada9b | Credential headers redacted in diffs too, and more header names; connection caps from the open-files limit, a per-client gateway cap, an admin header timeout; whole actor names up to 235 bytes; the rmcp log cap as a layer of its own; a relative socket path keeps 0710; a 1xx answer is `TURN_FAILED`; only `trusted_proxies` set the subject, and one from another peer is refused | 927c80a |
| `fix-v01-foreign-2` | 59cb546 to 9372f4c, 66ff941, e5b3a51, 765b4a0 | `disk_reserve`: incident actions, retention and retries work below it, and health shows it; partial blobs, layout moves, image GC that never waits for a fetch, secret scrubbing in one pass, cleanup and smaller fixes (S4 re-review 1 to 5 and 7 to 16, and round 3) | 927c80a |

Checked and sound:

- AuthZ: one function decides scopes; no bypass through methods, paths or
  encodings; no GET mutates; `no_pii` is forced without `pii:read`.
- Tokens: 32 random bytes, stored as a BLAKE3 hash, shown once, revoked at
  once; only `admin` manages them.
- Transports: the socket is 0660 with no chmod race; TCP needs a token and,
  off loopback, TLS; the admin listener is loopback-only.
- Secrets at rest: XChaCha20-Poly1305 under a master-derived key, keyed
  version hashes, encrypted keystore backups, `master.key` never shipped.
- Gateway: raw-segment routing with hashed keys, header and body limits, no
  request smuggling, HTTP/1 only, idempotency scoped per actor and locked.
- Foreign actors: OCI unpacking stays inside the root filesystem, and secret
  environment values are written 0600 and deleted on stop (a partial
  code-read).

## v0.2: whole systems in CI (M9 to M11)

v0.2 landed on main with 2a2545e, one commit with v0.2's code, and
f957475, which pins the reference workflow's action to 2a2545e. M9 and M11
are closed; M10 is open on its criterion 4. ADRs 0012 and 0013 (M9), 0021
to 0023 (M10) and 0024 to 0026 (M11).

M9: system proposals (closed).

- [x] A proposal with several components gives one fork, one replay and one
      diff in which each actor kind is reported separately
      (`crates/kronik-fork/tests/system.rs`, `kronik propose <dir>` in
      `cli.rs`, a two-kind diff in `schemas.rs`).
- [x] A caller and a new route on its callee verify together and fail
      apart, and the test shows the difference (`system.rs`).
- [x] After `effective_lsn`, no turn of any kind in the set starts with old
      code (`system.rs`).
- [x] Rollback of a set restores every kind at one LSN (`system.rs`).

M10: remote control from CI (open).

- [x] The CLI against a remote API with `KRONIK_URL` and `KRONIK_TOKEN`;
      plain HTTP is refused except to this machine
      (`crates/kronik/tests/remote.rs`, unit tests in `cli/http.rs`).
- [x] A 30-minute replay survives its client disconnecting, and `proposal
      wait` shows progress (`remote.rs`; held 31 minutes with no client in
      the batch's `M10/remote-30min` at c626ede).
- [x] `diff show --summary` holds no bodies and no state values, checked
      against a diff with personal data (`privacy_mode.rs`, unit tests in
      `markdown.rs`).
- [ ] An example repository runs the whole flow in GitHub Actions. The
      action (`action/`) and the reference workflow are tested against a
      fake `kronik` and a fake GitHub API (`scripts/ci.sh action`, 48
      tests); `examples/github-flow` holds the repository's content. A run
      on GitHub needs a public repository and a daemon its runners reach
      (Open questions).
- [x] Pull requests from forks don't run propose by default (the action's
      tests).

M11: guard after promote and preview forks (closed).

- [x] `watch` rolls back when the error rate after promote breaks a guard,
      and `GuardTriggered` holds the measurements
      (`crates/kronik-fork/tests/watch.rs`).
- [x] With a schema change, `watch` alerts instead of rolling back
      (`watch.rs`).
- [x] A preview fork takes new requests on the new code without live
      effects, and they show as preview inputs in the diff
      (`crates/kronik/tests/preview.rs`, kronik-fork's `preview.rs`).
- [x] Preview forks are deleted after their TTL, 24 hours by default
      (`preview.rs`, the configuration's unit test).
- `preview_domain` gets its wildcard certificate by ACME DNS-01 through a
  hook, tested against Pebble (`scripts/e2e-acme-pebble.sh`); a public
  domain is the owner's.

Evidence, 2026-10-28:

- At c626ede (v0.2 merged with main at e3fb81a): `scripts/ci.sh`, every
  step, `action` included; the crash test (1 000 cycles, 20 rebuild checks,
  an empty identity replay of 125 540 root inputs) and DST (30 000 runs,
  10 000 webhook runs with `webhook-relay-ts`, 10 000 `rebuild` runs,
  1 000 000 steps twice), all without a failure; and the testbench batch,
  67 of 67 suites in the rows M1 to M11 and `identity`, 15:01 to 16:24 UTC,
  `M10/remote-30min` included.
- At f957475: `scripts/ci.sh`, every step, `action` included, and the
  testbench rows M3, M6, M8, M10 (without `remote-30min`), M11 and
  `identity`, 33 of 33 suites, 19:35 to 20:09 UTC. Its diff from c626ede is
  v0.1's changes since e3fb81a, unchanged in 44 of 49 files and the same in
  `ci.sh`, the CI workflow and `proposal.rs` (the keystore fix's error
  mapping next to v0.2's code), plus the action's pin. The crash test, DST
  and the other rows carry over from c626ede.

## v0.3: richer replay (M12 to M15)

v0.3 landed on main with 189c8c3, one commit with the tree of `m15-sdks`
e798b46: the branches `m12-simulators` to `m15-sdks`, rebased onto
247bf5a. reviewer-v03's verdict on them: land, no must-fixes. M12 to M15
are closed: every criterion passes in `scripts/ci.sh`, on dev and on
GitHub, and the testbench batch passed. ADRs 0014 to 0016 (M12), 0017 and
0018 (M13), 0019 and 0020 (M14) and 0030 (M15); ADRs 0023 and 0027 are
amended.

M12: effect simulators (closed).

- [x] Every synthetic answer is labeled with its simulator in the diff and
      in `trace` (`crates/kronik-fork/tests/simulators.rs`, kronik-api's
      `simulators.rs`; the neighbor in kronik-effects' unit tests).
- [x] Contract fakes give schema-valid answers, and the same request
      always gets the same answer (kronik-effects' contract tests;
      `simulators.rs` compares the bytes of two runs).
- [x] The same proposal run twice with the model simulator gives a
      byte-identical diff through the cache, also after a restart
      (`simulators.rs`, against a fake model server).
- [x] The model simulator never sees sealed values (`simulators.rs`, with
      privacy mode on).
- [x] The policy can forbid synthetic answers per target
      (`simulators.rs`).

M13: rollback via replay (closed).

- [x] A rollback via replay after a migration gives the old code's state
      and a list of irreversible effects
      (`crates/kronik-fork/tests/rebase.rs`; `kronik rollback --by-replay`
      against a daemon in `cli.rs`).
- [x] Recovery from the log after a `StateRebase` gives the same state as
      before the restart, also rebuilt from a snapshot before the switch
      (`rebase.rs`).
- [x] No root input is lost or duplicated during the switch (`rebase.rs`:
      requests with idempotency keys during promote; a switch that cannot
      pause in time writes nothing).

M14: foreign actors in forks (closed).

- [x] A fork with `fork_mode = "sandbox"` starts a copy of a Postgres actor
      from the nearest checkpoint (`crates/kronik/tests/foreign.rs`,
      `postgres_fork_answers_from_a_copy`).
- [x] A changed SQL query gets a real answer from the copy, graded
      `forked` (the same test).
- [x] The copy cannot reach the network and is deleted with the fork (the
      same test).
- For the copies' `runsc restore`, the systemd unit drops
  `RestrictSUIDSGID` (ADR 0027, Open questions). Under the installed unit
  the batch's `M14/unit` started a copy of foreign-echo from its checkpoint
  (ADR 0027's Evidence).

M15: Python and Go SDKs (closed).

- [x] The example apps pass the same acceptance scripts as Rust and
      TypeScript in M1 to M3: the testbench's `M15` row runs `e2e-m1.sh`
      and `acceptance-m1.sh` with `M1_GUESTS=py` and `go`,
      `e2e-webhook-relay.sh` and DST with each relay, and
      `verify-change.sh` with each counter and its `-step2` build. DST with
      both relays also ran 10 000 seeds twice on dev.
- [x] The imports are within the allowlist, and the determinism test passes
      for both languages (`check_imports` and `sdk_determinism` in
      `scripts/ci.sh sdks`).
- The examples are counter, notes and webhook-relay in each language;
  `kronik init --lang python|go` writes a counter project. Identity replay
  covers them (`scripts/ci.sh identity`).

Evidence, 2026-10-28 and 29:

- At e798b46, 189c8c3's tree: `scripts/ci.sh`, every step, passed on dev,
  ending 21:29 UTC: `sdks`, `foreign` (7 tests, the Postgres fork test
  included), `identity` and `action` included.
- On dev at e798b46, 21:54 to 23:01 UTC: the crash test (1 000 cycles,
  120 320 acknowledged requests, 20 rebuild checks, an empty identity
  replay of 126 235 root inputs) and DST (30 000 runs; 10 000 webhook runs
  each with `webhook-relay-ts`, `webhook-relay-py` and `webhook-relay-go`;
  10 000 `rebuild` runs; 1 000 000 steps twice), all without a failure.
- The testbench batch at 94d20ac (189c8c3 and STATUS): 88 of 88 suites in
  the rows M1 to M15 and `identity`, 2026-10-28 23:35 to 2026-10-29 01:15
  UTC, `M10/remote-30min` and 14 identity examples included. `M14/unit`
  passed when rerun at 01:20 UTC, after fixes to its own script; its
  result is in ADR 0027's Evidence.
- GitHub Actions run 40785502137 at 94d20ac passed every step: the first
  run there of `sdks`, `action` and the foreign step's Postgres fork test
  with docker.

## Next

1. Owner check-in: stop or continue.

## Parked work

Each branch's last commit message carries its handoff.

- M16 cluster: `m16-cluster` 126ee1f (from main dd2a174); the reviewed
  design is pinned at `m16-design` b6886d8. Review fixes and the resume
  plan, 5 code blockers and 10 Highs, none fixed yet:
  `docs/design/m16-review-fixes.md` on the branch. ADRs 0040 (raft-rs, with
  two cargo-deny exceptions) and 0046 (cluster security) are provisional.
- M20 microVMs: the design note `docs/design/m20-microvm.md` on
  `m21-design` 2d41fbc; it needs a KVM host. The `KVM_UNAVAILABLE` path is
  on `m21-rootless`.
- M21 non-root daemon: `m21-rootless` bbecc0c (on `m14-foreign-forks`
  3091fbc). A partial review, 5 Highs, is in
  `docs/design/m21-review-partial.md`; the testbench proof needs a rerun;
  ADR 0060 is provisional.
- M22 wasi:http: `m22-wasi-http` 297f871, on the earlier `m15-sdks` from
  before the squash; not reviewed, and not rebased onto v0.3.
- M23 secret backends: `m23-design` 30d4791, design only. ADR 0093
  (PKCS#11 through a keyhelper process) is the owner's decision.
- M24 connections: `m24-design` da0a3e5, design only.
- M28 OpenTelemetry and audit: `m28-otel` 9b65bb4, with the unmerged review
  fixes `m28-fixa` e5dcec9 and `m28-fixb` 066b604.

## Open questions

- Confirm the licensor and copyright holder in `NOTICE` and `CLA.md`
  (currently Gustaf Ekfeldt) and the public repository URL.
- `CLA.md` was written by an agent: have it reviewed before the first
  external contribution.
- **`_subject` and erasure.** As the brief is written, SQL rows of tables
  without a `_subject` column belong to the turn's default subject, but
  erasure deletes only rows with `_subject = subject`, so such rows survive
  erasure in plain text. M1 implements the brief as written (ADR 0005,
  `subjects/gap-without-column`).
- **Publishing.** The v0.1.0 GitHub release; GitHub Actions minutes for CI
  and the nightly; and a public install URL and domain, for `install.sh`
  and for ACME with a real certificate.
- **Release tags.** The milestone tags `v0.0.0` to `v0.0.8` point into the
  history from before the squash, and no later milestone is tagged.
  Proposal: release tags on the squashed commits instead, `v0.1.0` at
  4353863 and `v0.3.0` at the commit that records this question; `v0.2.0`
  waits for M10's criterion 4.
- M10's criterion 4 needs a public repository with `examples/github-flow`,
  a daemon GitHub's runners can reach, and GitHub Actions minutes.
- **Crypto in forks is a signing oracle.** As the brief's effect table
  says, a fork's `crypto.hmac-sha256` or `crypto.sign-ed25519` call that
  matches no recording is computed on the host with the production key.
  Code deployed into a fork, which needs only the `fork` scope (part of an
  agent's default), can so have arbitrary data signed with production keys;
  the key itself never leaves the host. (`secret.reveal` in a fork now
  answers a placeholder.) Proposal: a per-grant `--in-forks
  compute|recorded` (`recorded`: unmatched calls get a synthetic result),
  with a log line and a metric for every fork computation.
- **Sampling coverage.** A proposal may use `--mode isolated` with a small
  `--sample`. Only `payments-full-coverage` stops promote under a sample,
  so elsewhere coverage relies on the reviewer reading `summary.sample`.
  Should the default policy ask for more?
- **Resolved:** ADR 0027, no `RestrictSUIDSGID` from v0.3. The setting
  makes `openat2` fail, and `runsc restore` needs it for M14's sandbox
  copies, so v0.3's unit leaves it out, and copies run under it (ADR
  0027's Evidence); v0.1 kept it. The residual risk: code in an untrusted
  image, root in its sandbox, can set the setuid or setgid bit on a file
  under its actor's `/data`, and the host keeps it; so can a compromised
  daemon or runsc, anywhere it writes. Only root reaches those files,
  through 0700 parents; checkpoints and copies clear the bits, and the
  operations guide says not to copy the tree with modes kept. The owner
  accepted the ADR on 2026-10-29.
- **Resolved:** the testbench's Tailscale SSH check mode stopped the batch
  three times: on 2026-10-26, for about eight hours on 2026-10-28, and for
  about two hours from 21:34 UTC that evening, before v0.3's rows. The
  owner fixed Tailscale SSH to the testbench on 2026-10-29; BatchMode ssh
  works (three checks at 08:34 UTC, each exit 0). On dev and on the
  testbench, `tailscale status --json` says nothing about the SSH policy or
  check mode: both nodes list the SSH capabilities (`cap/ssh`,
  `ssh-behavior-v1`, `ssh-env-vars`) without values, and no login URL.
- From v0.4 the testbench is a cluster of three VPSs, as the brief says;
  there is one, `travelfiesta`.
- M20 (Firecracker) needs a test host with `/dev/kvm`: neither dev nor the
  testbench has one.
- Provisional ADRs on parked branches: 0040 and 0046 (`m16-cluster`), 0060
  (`m21-rootless`) and 0093 (`m23-design`) (Parked work).

## Known gaps

- The shipper notices a keystore change by the size and mtime of
  `keystore.db` and its WAL. A write that reuses the WAL after a
  checkpoint, at the same length and within one mtime tick, is missed until
  the next change or the daily backup (review F7 on fix-v01-keystore-restore).
  A change counter kept in the keystore itself would close it.
- The nightly has not run on the pushed history yet; its runs on the
  earlier main (b47780d) failed the crash test, which is fixed since.
  GitHub Actions CI is green on main since eb1218e (2026-10-28), after
  fixes to the ops test's KVM check, the TS test glob and
  `identity-examples.sh`. v0.3's `sdks` and `action` steps and the foreign
  step's Postgres fork test with docker passed there at 94d20ac (run
  40785502137). `scripts/ci.sh` runs on dev (Debian 13), CI on the
  workflow's Ubuntu 24.04.
- One actor commits 180 to 210 turns/s: each turn waits for the 2 ms
  group-commit window and an fsync before the actor's next turn. Across
  actors the counter commits about 7 900 turns/s on dev and 2 770 on
  travelfiesta (`docs/perf.md`). Not tuned.
- Logical time follows ADR 0006 (+1 ms only across restarts), a deviation
  from the brief's formula that the owner may overrule.
- SQLite work (`state.db`, actor databases) runs on the async worker
  threads; ADR 0004 puts it behind `Env::blocking`, which only the startup
  decode and the foreign actors' file work use.
- After a restart, a promote replays its window again: the catch-up state
  is in memory (`docs/design/m3-fork.md` §11).
- Isolated replay stopped scaling beyond 2 to 4 workers on dev at 0047670;
  not measured since (`docs/perf.md`).
- The first rate-limited call after a restart waits one full period (up to
  an hour for `N/h`): rate windows start full and are not persisted.
- `kronik upgrade check` has not seen a real engine change: there is one
  engine version, `kronik-0.1.0-dev+wasmtime-50.0.0`.
- The daemon did not set `PR_SET_DUMPABLE`. Fixed: `kronik serve` makes
  itself non-dumpable at start through rustix (6bf2f60 in the earlier
  history), besides the unit's `LimitCORE=0`; if the call fails it logs a
  warning.
- `kronik serve --test-insecure-registry <host:port>`, a hidden test hook
  for pulling foreign images over plain HTTP, is in release builds too.
- A foreign actor's `/data` has no quota. The operations guide says to put
  `<data_dir>/foreign` on its own file system; `[log] disk_reserve` refuses
  new work before the log's disk is full (`fix-v01-foreign`).
- Promote did not refuse when the code of a kind the proposal changes had
  moved on main since the proposal was made. Fixed: 24fef29 pins changed
  kinds (`PROPOSAL_STALE`). 07bdeae pins them at the proposal's creation
  head (`created_lsn`); pinning at the fork point had falsely refused
  proposals made soon after a promote.
- A proposal may use `--mode isolated` with a small `--sample`; outside
  payments, coverage then relies on the reviewer reading `summary.sample`
  (Open questions).
- A fork's `crypto.*` call without a recording is computed with the
  production key, as the brief's effect table says (Open questions).
- Forks, proposals and their diffs are not shipped, so after `kronik
  restore` the proposals behind earlier deployments are gone. Deployments
  and approvals, an approval with the approved diff's `diff_hash`, are in
  the log and survive.
- Under the unit shipped with 927c80a, `RestrictSUIDSGID=true` made the kernel
  refuse the setuid and setgid bits of image entries. So an image with such
  entries (postgres:17-alpine's `run/postgresql`, 2777) never started. Fixed
  on 2858e0b: unpacking clears those bits and keeps the sticky bit.
- Under the unit shipped with 927c80a, no foreign actor started: runsc failed
  with `cannot create gofer process: fork/exec /proc/self/exe: operation not
  permitted`. With an explicit `User=root` and a seccomp-based setting,
  systemd 257 drops `CAP_SETUID`, and `NoNewPrivileges=true` kept runsc from
  getting it back. Fixed on 24c6dbc: the unit has no `User=` line (root is
  the default) and keeps `NoNewPrivileges`; e3fb81a kept `RestrictSUIDSGID`
  for v0.1, and v0.3 drops it for M14 (ADR 0027, Open questions).
- `docs/perf.md` does not have the testbench's privacy overhead yet
  (`M8/bench-privacy` measures it).
- Previews of a rebase proposal are allowed and run the rebase's code on
  main's head. Harmless, but whether to refuse them is an open product
  decision.
- A `watch` on a rebase's epoch can fire a guard rollback, which restores
  the old code over the rebased state: the same as rolling back any
  deployment whose new code wrote state.
- CI's check that the workflow runs every `ci.sh` step counts one step per
  line: `scripts/ci.sh a b` counts only `a`.
