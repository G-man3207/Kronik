# M2 effects design

Status: binding for M2. It extends `docs/design/m1-core.md`; the brief's
sections are "Effekter och capabilities", "Turn-semantik" and invariants
I6, I7, I8, I14 and I17.

## 1. Crates

| Crate | M2 adds |
| --- | --- |
| `kronik-privacy` | `MasterKey` (load or create `[keys] master_key_file`), `SecretStore` (`keys/secrets.db`, XChaCha20-Poly1305 under a key derived from the master key, versioned values, version hashes). |
| `kronik-effects` | Capability matching (`http:<host>`, `*.example.com`, `secret:<name>`, `secret-reveal:<name>`), `Config` (grants and limits as of an epoch), delivery classes, HTTP fingerprints, secret header rendering and response scrubbing, host-side crypto, the per grant and target rate limiter, the `EffectSimulator` trait with `RecordedMatch` and `FailClosed`. Pure code except the limiter's clock. |
| `kronik-runtime` | The `EffectGate` trait the host calls for `http-client.fetch`, `messaging.call`, `crypto.*` and `secrets.reveal`; buffered `timers.schedule/cancel`; compensations in `TurnOutput`. |
| `kronik-store` | Tables `grant_records`, `limit_records`, `open_turns`, `open_effects`, `timers`, `orphans`; saved call responses in `deliveries`. |
| `kronik-sched` | The per-turn gate (`TurnBegin`, `EffectResult`, replay of recorded results, re-execution by delivery class), `call` execution, compensations, the timer wheel, recovery re-runs, and `grant`/`revoke`/`set_limits`/secret operations. |
| `kronik-core::env::real` | The outbound `Net`: hyper client over rustls with the system roots. |
| `kronik-api` | The endpoints in §8. |

## 2. Log schema additions (additive, v1)

- `EffectRecord`: `target` (11, e.g. `http:api.example.com`,
  `actor:billing/acme`, `secret:stripe-key`), `error` (12, the guest-visible
  error text for non-OK statuses).
- `MessageInput`: `call_chain` (8, the actors waiting in `call` on this
  causal chain, for cycle detection), `compensates` (9, the call's message
  id for a compensation, kept by a resend).
- New `effects.proto`: the plaintext inside `EffectRecord.request` and
  `.response` (each a `Sealable` holding the encoded message):
  `HttpEffectRequest {method, url, headers, body}` where a header value is
  either text or a `SecretRef {name, template, version, version_hash}` (never
  the value); `HttpEffectResponse {status, headers, body}`;
  `CallEffectRequest {to, msg, compensate, message_id}`;
  `CallEffectResponse {reply}`; `CryptoEffectRequest {algorithm, secret,
  data_hash}` with the result bytes as response; `RevealEffectRequest
  {secret}` with no response payload (the value is never recorded).

## 3. The effect pipeline

Every effect-like host call gets the next operation ordinal (shared with
`send`, `call` and `timers.schedule`, see m1-core §3) and goes through the
turn's gate:

1. **Capability.** The grant is looked up in the configuration of the
   turn's epoch (`TurnBegin.config_epoch`), so re-runs and forks see the
   same answer. `http-client.fetch` needs `http:<host>` (exact, or the most
   specific `*.suffix` wildcard; a wildcard never matches the apex);
   a secret header or `crypto.*` needs `secret:<name>`; `secrets.reveal`
   needs `secret-reveal:<name>`. Without it the guest gets
   `denied("CAPABILITY_NOT_GRANTED: <capability>")` and an `EffectRecord`
   with status `DENIED` goes into the turn record (deterministic from the
   configuration, so no fsync). `foreign://` targets are denied until M7.
2. **`TurnBegin` first (I14).** Before the turn's first external effect,
   first `call`, or first secret use (crypto, reveal), the gate appends and
   fsyncs a `TurnBegin` with execution id, actor, code hash, engine version,
   causal key, logical time, seed, input and epoch. Turns without any of
   these still write no `TurnBegin`.
3. **Replay check.** If the turn is a re-run (§4) and an `EffectResult`
   exists for this ordinal, its fingerprint must equal the new request's; a
   mismatch traps with `REPLAY_DIVERGED`. The recorded result is returned
   without contacting anything.
4. **Execution.**
   - HTTP: the rate limiter waits for a slot (§6); secret header templates
     are filled from the secret store; the request carries
     `Idempotency-Key: hex(blake3(causal key + ordinal))` for every delivery
     class; the call runs under the kind's effect timeout (10 s) and response
     limit (10 MiB). Exact occurrences of the inserted secret values are
     replaced by `[secret:<name>]` in the response before anyone sees it.
     Outcomes: `ok`, `network` (connection failed or the exchange broke),
     `timeout`, `too-large`.
   - `call`: §5. Crypto: computed on the host with the secret's current
     version. Reveal: the current version's value.
5. **`EffectResult` before the guest sees it.** The `EffectRecord`
   (ordinal, kind, target, fingerprint, request, response, idempotency key,
   duration, delivery class, status, `GROUNDING_LIVE`) is appended in an
   `EffectResult` and fsynced; only then does the host return to the guest.
   For reveal the record holds the secret's name and version hash only.
6. **Turn record.** The turn record repeats every `EffectRecord` (denied
   ones included), so history and forks need only the turn record.

Effect kinds (`EffectRecord.kind`): `http.fetch`, `actor.call`,
`crypto.hmac-sha256`, `crypto.sign-ed25519`, `secret.reveal`.

**Fingerprint (HTTP).** `blake3` over: method, scheme, lowercase host, port
(when not the default), path, query parameters sorted by name then value,
`blake3(body)`, and the headers sorted by lowercase name, without
`authorization`, `cookie`, `date`, `idempotency-key`, `user-agent` and
`x-request-id`; a secret header contributes its name, secret name and
version hash. Per-kind rules come with forks (M3). Other kinds fingerprint
their encoded request.

**Delivery class** of an HTTP effect: the matching grant's `--delivery`,
else `replay-safe` for GET, HEAD and OPTIONS and `unsafe` otherwise.
Internal kinds have none.

## 4. Crash recovery: re-running open turns

`state.db` tracks `open_turns` (a `TurnBegin` without a turn record with
the same execution id; inserted when the `TurnBegin` is applied, removed by
the turn record) and `open_effects` (their `EffectResult`s). At startup,
before the mailbox is re-queued and before the gateway and API accept
requests, each open turn is re-run in `TurnBegin` LSN order on its actor:

- same execution id, input, code hash, engine version, logical time, seed,
  causal key and configuration epoch; no new `TurnBegin`;
- recorded results are returned in ordinal order (§3.3);
- an effect without a recorded result is handled by its delivery class:
  `replay-safe` and `idempotency-keyed` are performed again with the same
  `Idempotency-Key`; `unsafe` is not performed (I17): the guest gets
  `outcome-unknown`, recorded as the effect's result (`OUTCOME_UNKNOWN`);
  a `call` without a recorded result is re-issued with the same message id
  and is answered from the callee's saved response if it committed (§5);
  crypto and reveal are recomputed;
- a turn that fails after any `OUTCOME_UNKNOWN` result fails with
  `EFFECT_OUTCOME_UNKNOWN` (outcome kind `EFFECT_OUTCOME_UNKNOWN`); a message
  or timer input then goes to the dead letters with the turn record, which
  holds the unsent request.

The input of an open turn is not delivered again: its mailbox entry and
its ingress key belong to the re-run (an HTTP retry with the same
`Idempotency-Key` joins the re-run).

## 5. `call`, compensations and orphans

- **Message id** `= message_id(caller causal key, ordinal)`; the callee's
  turn has the causal key `child(caller key, caller, ordinal)` and input
  `MessageInput {source: CALL, sender, msg, message_id, call_chain}`.
- **Cycles.** `call_chain` is the caller's chain plus the caller. A call to
  an actor in the chain (or to itself) returns `reentrant` at once.
- **Timeout.** The kind's effect timeout (10 s); then `timeout`, recorded.
  (A cross-chain wait cycle ends this way.)
- **Dedup.** The callee's turn record is applied with
  `deliveries(message_id → lsn, outcome)`. A call whose message id is
  already in `deliveries` gets the saved outcome and the callee does not
  run again. The callee's reply is its `output::reply`; `rejected` and
  `failed` handler errors map to `call-error::rejected/failed`; a trap or
  fuel exhaustion to `failed`; no deployment to `not-found`. Failed call
  turns are not dead letters (the caller got the error).
- **Compensation.** When the caller's turn fails, each successful call with
  a compensation becomes an `OutboundMessage` in `TurnRecord.compensations`,
  delivered exactly once like a sent message: source `COMPENSATION`, causal
  key `child(callee turn key, callee, COMPENSATION_ORDINAL = 2^32 - 2)`,
  message id = its `causal-id`, `compensates` = the call's message id.
- **Orphans.** When the caller's turn fails, every successful call (status
  OK) adds an `orphans` row: callee, callee turn, caller turn, call message
  id, compensation message id (if any). A committed turn whose input has
  `compensates = m` resolves the orphan for `m`. A failed compensation is a
  dead letter; its resend keeps `compensates`, so a successful resend
  resolves the orphan. `history --orphans` lists unresolved rows.

## 6. Grants, limits and rates

- `Grant` records (kind, capability, op, delivery, rate, epoch, audit) and
  `Limits` records (unset fields keep the previous value) are applied into
  `grant_records`/`limit_records`; the node folds them into a `Config` per
  epoch. Grants apply per kind, not per hash.
- **Rate** `N/s`, `N/m` or `N/h` per grant and target host: a sliding
  window of the last N send times per (kind, capability, host); a call waits
  until the oldest is older than the period. **Guarantee:** no period-long
  window ever holds more than N *sends* (the moment the daemon hands the
  request to the network), across crashes and restarts: the windows are not
  persisted, but every window starts full at process start, as if N sends
  had just happened, so the first rate-limited call after a restart waits
  one period (up to an hour for `N/h`). Arrivals at the target are not
  bounded: network delay can bunch two windows' worth of sends into one
  period. Waiting uses `Env::clock`; logical time and forks are unaffected.
- **Limits** per kind: fuel, memory, message and state value size, SQL size
  per actor, effect timeout, effect response size. A turn uses the limits
  of its epoch.

## 7. Secrets and timers

- **Master key.** `[keys] master_key_file` (`kronik serve
  --master-key-file`, default `<data_dir>/keys/master.key`): 32 random
  bytes, hex, mode 0600, created at first start if missing (logged once).
- **Secret store** `keys/secrets.db`: rows `(name, version, nonce,
  ciphertext, version_hash, created, token_id, reason, deleted)`. Values
  are sealed with XChaCha20-Poly1305 under `derive_key("kronik secrets v1",
  master)`, with `name|version` as associated data. `version_hash = 16 bytes
  of blake3_keyed(derive_key("kronik secret version v1", master), name \0
  version \0 value)`, so the log reveals nothing about low-entropy values.
  `secret set` adds a version; `delete` marks every version deleted (later
  re-runs needing it fail the effect with `denied`).
- **Values never reach the log, history or API output.** Guest log events
  and the API's turn JSON have exact occurrences of revealed values
  replaced by `[secret:<name>]`.
- **Timers.** `timers.schedule(delay, msg)` buffers a `TimerOp SCHEDULE`
  with id `u64` from `blake3(causal key + ordinal)` and due time
  `now-ms + delay`; `cancel(id)` buffers `CANCEL` and returns whether the
  timer is pending (committed or scheduled earlier in the turn). Applied
  with the turn record into `timers (kind, key, id, due_ms, msg, causal
  key)`. The timer wheel fires a due timer (wall clock ≥ due) as a turn
  with `TimerInput`, logical time ≥ due, causal key `child(scheduling turn
  key, actor, ordinal)`; the row is removed when that turn's record is
  applied, and a failed timer turn is a dead letter.

## 8. API additions (`/v1`, same conventions as m1-core §4)

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/grants` | `{"kind","capability","delivery":"replay-safe"\|"idempotency-keyed"\|"unsafe"\|null,"rate":"2/s"\|null,"reason","dry_run"}` | `{"dry_run","grant":{"kind","capability","delivery","rate","epoch","lsn"}}` |
| `POST /v1/grants/revoke` | `{"kind","capability","reason","dry_run"}` | `{"dry_run","revoked":{"kind","capability","epoch","lsn"}}`; `CAPABILITY_NOT_GRANTED` if absent |
| `GET /v1/grants?kind=` | | `{"grants":[{"kind","capability","delivery","rate","epoch","lsn","reason"}]}` |
| `POST /v1/limits` | `{"kind","fuel","memory_bytes","message_bytes","state_value_bytes","sql_bytes_per_actor","effect_timeout_ms","effect_response_bytes","reason","dry_run"}` (omitted fields unchanged) | `{"dry_run","limits":{"kind", every field with its effective value,"epoch","lsn"}}` |
| `GET /v1/limits?kind=` | | `{"limits":[{"kind", every field}]}` |
| `PUT /v1/secrets/{name}` | `{"text"\|"base64","reason","dry_run"}` | `{"dry_run","secret":{"name","version","version_hash","created_wall_ms"}}` |
| `GET /v1/secrets` | | `{"secrets":[{"name","version","version_hash","created_wall_ms"}]}` (never values) |
| `DELETE /v1/secrets/{name}` | `{"reason","dry_run"}` | `{"dry_run","deleted":{"name","versions"}}`; `SECRET_NOT_FOUND` if absent |
| `GET /v1/orphans?all=false` | | `{"orphans":[{"actor","turn_id","caller","caller_turn_id","call_message_id","compensation":{"message_id","state":"pending"\|"dead_letter"\|"done"}\|null,"resolved_turn_id"}]}` |
| `GET /v1/actors/{kind}/{key}/timers` | | `{"timers":[{"id","due_ms","name"}]}`; `id` is a decimal string (a u64 does not fit a JSON number exactly) |

`GET /v1/health` gains `"http_listen"`, the gateway's bound address.
Request and response types live in `kronik_api::types`.

History entries and the turn JSON gain `"effects":[{"ordinal","kind",
"target","status","delivery","error","hint"}]`, where `hint` for a
`DENIED` effect is the exact command, e.g. `kronik grant billing
http:api.example.com --reason '...'`. Secret names must match
`[a-z0-9][a-z0-9_.-]{0,63}`.

## 9. Testing

- **Crash acceptance (SIGKILL).** `crates/kronik/tests/kill.rs` runs `kronik
  serve` as a child process. The test HTTP server signals the harness when
  the daemon's request arrives; the harness kills the daemon with SIGKILL,
  restarts it on the same data directory and checks the log, the API and
  what the server saw: `TurnBegin` durable before the request; a recorded
  result not requested again and the next request byte-identical; an
  `idempotency-keyed` target seeing the same key again; an `unsafe` target
  seeing no second request while the turn dead-letters with
  `EFFECT_OUTCOME_UNKNOWN`; and a caller killed after its callee committed
  (hidden `serve --test-hold-after-call` holds the caller at exactly that
  point) getting the saved response without the callee running again.
- **In-process (more targeted).** `crates/kronik-sched/tests/effects.rs`
  drops the daemon's tokio runtime at the same points, and covers denied
  effects, compensations and orphans, timers, rate limits and the secret
  leak scan of every file.
- **DST.** A simulated external service on the supervisor node (survives
  daemon crashes) with idempotency-key dedup and fault injection; invariants:
  no request before its durable `TurnBegin`, no duplicate processing for
  `idempotency-keyed`, never two requests for one `unsafe` effect,
  byte-identical retries, rate never exceeded, plus all M1 invariants.
