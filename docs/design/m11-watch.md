# M11 watch: guards after a deployment

`kronik watch <epoch> --for 10m` compares the error rate and latency of a
deployment's actor kinds after it with the equally long window before it.
The policy's guards decide: `alert`, or `rollback`. Watch is a command
over the existing concepts deployment and policy (I13); it adds no concept.
ADR 0024 records the decisions.

## 1. The log is the source

The metrics come from the log alone (I5), so a watch can be recomputed and
checked:

- **Turns.** A `TurnRecord` of one of the deployment's kinds. A turn
  fails when the code or the host failed it: any outcome but `COMMITTED`
  and `REJECTED` (failed, trap, fuel, memory, effect outcome unknown), or
  a committed HTTP response with a 5xx status. `REJECTED` is the client's
  invalid input, not a broken deployment.
- **Latency.** `TurnRecord.duration_us` (field 23, M11): the node's
  monotonic wall time from the start of the turn to its record. It is 0
  in records from before M11 and in turns a fork recomputes (a fork's wall
  time says nothing about production); such turns count as turns but are
  not latency samples. Percentiles are nearest-rank over the samples; p50
  and p99, 0 without samples.
- **The deployment's time** `t_d`: the later of its record's audit wall
  time and the logical time of the last turn at or before its LSN (when
  both are missing: the first turn after it, else the daemon's clock when
  the watch starts). It is computed once and kept in the watch.
- **After**: the turns of the deployment's kinds with LSN > the
  deployment's LSN, `config_epoch >=` its epoch (they ran the new code,
  ADR 0013), and logical time in `[t_d, t_d + for)`, up to the first later
  `Deployment` that touches one of the kinds (a promote, a deploy, a
  rollback): turns after it run other code.
- **Before**: the turns of the same kinds with LSN < the deployment's LSN
  and logical time in `[t_d - for, t_d)`.
- `error_rate = failed / turns`, 0 without turns.

The scan starts at the first segment whose highest logical time reaches
`t_d - for` (`segments.last_time_ms`) and then reads only new records on
each evaluation. The window before is final once the scan passed the
deployment: its percentiles are computed once and its samples dropped.
`for` is at most 24 hours (`watch::MAX_FOR_MS`), which bounds the samples
kept for the window after.

## 2. Guards

A rules file (`kronik policy set`) holds `[[guard]]` tables next to its
`[[rule]]` tables, with exactly `name`, `when` and `action`; names are
unique among guards and match `[a-z0-9-]+`, and every `when` compiles
under the same CEL limits as a rule (ADR 0007). `action` is `alert` or
`rollback`. A guard's `when` sees the variable `guard`:

```json
{
  "epoch": 7, "kinds": ["counter"], "schema_changed": false,
  "observed_ms": 42000,
  "before": {"turns": 40, "failed": 0, "error_rate": 0.0,
             "latency_p50_ms": 1.2, "latency_p99_ms": 9.8},
  "after":  {"turns": 20, "failed": 10, "error_rate": 0.5,
             "latency_p50_ms": 1.3, "latency_p99_ms": 10.1}
}
```

`schema_changed` is true when a rollback of the deployment would move a
schema version back (the rollback's own check, `ROLLBACK_SCHEMA_CHANGED`).
`observed_ms` is how much of the window after the deployment the log has
reached (the highest logical time read, within the window). Latencies are
doubles in milliseconds; turn counts are integers.

No guard is evaluated while no turn ran after the deployment (`after.turns`
is 0): a ratio would divide by zero, and nothing is known yet. A guard
that refers to `diff` is refused when the policy is set. A guard whose
`when` cannot be evaluated does not fire: it writes one `GuardTriggered`
with outcome `ALERTED` and a reason starting `the guard could not be
evaluated: `, so it is never silently skipped, and it is evaluated again
next time: it can still fire, and roll back, once it evaluates to true.
The CLI shows it as `could not be evaluated: <error>`, not as fired.

A policy file with a `guard` key has exactly those guards: `guard = []`
means none, and a watch then only measures. Without a `guard` key (and
while no policy is set) the default guards apply
(`kronik_policy::DEFAULT_GUARDS_TOML`):

| Guard | When | Action |
| --- | --- | --- |
| `error-rate-up` | `guard.after.turns >= 20 && guard.after.failed >= 3 && guard.after.error_rate > guard.before.error_rate + 0.05` | rollback |
| `latency-p99-up` | `guard.after.turns >= 10 && guard.before.turns >= 10 && guard.before.latency_p99_ms > 0.0 && guard.after.latency_p99_ms > 2.0 * guard.before.latency_p99_ms + 50.0` | alert |

The default rollback waits for 20 turns and 3 failures: one failure in a
quiet window is not a breach. The latency guard needs a measured p99
before the deployment (the first watch after an upgrade from before M11
has none); a guard of your own that divides by `before.latency_p99_ms`
should check it too, since a double divided by 0 is infinite in CEL.

`kronik policy show` prints the guards in force (`guards` and
`default_guards` in its JSON); `set` and `test` keep working with guards in
the file; `policy test` evaluates the rules only.

## 3. The watch job

`POST /v1/deployments/{epoch}/watch` (scope `promote`) checks the
deployment, `0 < for_ms <= 86400000` (24h), and that no later deployment
touched any of its kinds (`BAD_REQUEST` otherwise: a guard's rollback
restores the code from before the deployment, which would undo the later
one too). It then writes `<data>/watches/<id>.json` (id `w-<12 hex>`)
with status `watching` and starts a task (`Env::spawn`) that outlives the
request, like a proposal job (ADR 0022). Without `async` the request waits
until the watch is over. A dry run keeps nothing: it evaluates the guards
on the windows as they are now and returns the metrics, and in
`triggered` (with `lsn` 0) the guards that would fire and what they would
do (the rollback is planned as the real one is, so a deployment that
added a kind predicts `rollback_failed`).

Every 5 seconds (`watch::INTERVAL`, measured with `env.clock`) the task
reads the new records, evaluates the guards with the policy in force, and
saves the metrics in the watch. Each guard fires at most once per watch:

- `alert`: a `GuardTriggered` record with outcome `ALERTED`, an error in
  the daemon log and `kronik_guard_triggered_total{action,outcome}`. The
  watch goes on.
- `rollback`: the rollback runs through the normal path
  (`Proposals::rollback_watched`, audit token `kronik`, reason
  ``watch <id>: guard `<name>` fired``), then a `GuardTriggered` with
  `ROLLED_BACK` and the rollback's epoch; the watch ends `rolled_back`.
  The rollback's `CodeSwitch` pins the watched deployment's kinds at its
  code, checked under the deploy lock with the switch itself: when a later
  deployment changed them after the read, nothing is rolled back and the
  watch ends `superseded`. When the deployment changed a schema version
  the rollback refuses with `ROLLBACK_SCHEMA_CHANGED`: the record says
  `ROLLBACK_REFUSED_SCHEMA`, it alerts instead, and the watch goes on. Any
  other refusal is `ROLLBACK_FAILED`.

The watch ends `done` when the daemon's clock passes `t_d + for` (after
one last evaluation), `rolled_back`, `superseded` when a later deployment
touched one of its kinds (a promote, a deploy, a manual rollback, another
watch's rollback: the watched code no longer runs, so nothing acts on it),
`stopped` by `kronik watches stop`, or `failed` with its error.

**Stop.** `POST /v1/watches/{id}/stop {reason, dry_run}` (scope `promote`:
it gives up a rollback) ends a `watching` watch `stopped` and keeps the
caller and reason in the watch (`stopped`). It takes the same lock as an
evaluation that acts, so once it returns the watch writes no record and
rolls nothing back. A watch that is over answers `BAD_REQUEST`.

**Restart.** At startup every watch still `watching` resumes: it rescans
the log from the start. Its `GuardTriggered` records (matched by
`watch_id`) decide which guards already fired. A rollback deployment
whose audit reason starts with `watch <id>:` but has no `GuardTriggered`
yet (the daemon stopped between the two) is recorded for the guard its
reason names, whatever the guards say now, and the watch ends
`rolled_back`; it never rolls back twice.

## 4. GuardTriggered (record kind 17)

Informational, like `SnapshotMarker`: it creates no epoch and changes no
state. Like a rollback's records it is written below `[log] disk_reserve`
too, so a watch records its incident and ends on a full disk. It holds exactly what was evaluated:

| Field | Meaning |
| --- | --- |
| `deployment_epoch`, `deployment_lsn` | the watched deployment |
| `watch_id`, `guard` | the watch and the guard's name |
| `action` | `ALERT` or `ROLLBACK` (0 is invalid) |
| `outcome` | `ALERTED`, `ROLLED_BACK`, `ROLLBACK_REFUSED_SCHEMA`, `ROLLBACK_FAILED` (0 is invalid) |
| `before`, `after` | `GuardWindow`: first and last counted LSN, the window's logical time bounds, turns, failed, error rate, p50 and p99 in µs |
| `observed_lsn` | the windows count the records through this LSN |
| `rollback_epoch` | the rollback deployment's epoch, 0 without one |
| `reason` | the guard's `when`, the evaluation error, and why a rollback did not happen |
| `audit` | token `kronik`, reason `watch <id>: <the watch's reason>` |

Compatibility fixtures: `crates/kronik-proto/tests/fixtures/
guard-triggered-v1.hex` and `turn-record-v1.hex` (a `TurnRecord` without
`duration_us` decodes with 0).

## 5. API and CLI

| CLI | API |
| --- | --- |
| `kronik watch <epoch> --for 10m --reason R [--async] [--dry-run]` | `POST /v1/deployments/{epoch}/watch {for_ms, reason, dry_run, async}` |
| `kronik watches list` | `GET /v1/watches` |
| `kronik watches show <id>` | `GET /v1/watches/{id}` (`WATCH_NOT_FOUND`) |
| `kronik watches stop <id> --reason R [--dry-run]` | `POST /v1/watches/{id}/stop {reason, dry_run}` |

`kronik watch` without `--async` posts with `async` and polls the watch
every second, printing the metrics and each guard that fires to stderr; it
exits 1 when the watch rolled back or failed, or when a rollback guard
fired and the rollback was refused or failed. `kronik watches show` exits
the same way.

## 6. Limits

- Latency is the turn's time inside the node, not the gateway's response
  time (requests that never became turns, such as 404 or 504, are not in
  the log).
- The rollback's pins compare code hashes: a later deployment of the very
  same code that lands between an evaluation's read and the switch is
  rolled back with it (to the code the guard judged).
- A watch evaluates the policy in force at each evaluation; the record
  holds the guard's `when` as evaluated.
- The end of the watch uses the daemon's wall clock; the windows use
  logical time.
