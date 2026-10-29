# Writing actors

An actor type is a WebAssembly component that exports the `kronik:actor`
world ([WIT](../reference/wit.md)). Kronik has SDKs for TypeScript, Rust,
Python and Go, with the same API in each language's spelling; all four come
with the `kronik` binary, which vendors them into new projects, builds the
projects and runs their tests.

## Start a project

```sh
kronik init --lang ts billing        # or --lang rust, python, go
cd billing
npm install                          # TypeScript: the pinned toolchain
                                     # (Python, Go: scripts/install-sdk-tools.sh from a Kronik checkout, once)
npm test                             # cargo test, python3 -m unittest discover -s tests, go test ./test
kronik build                         # dist/billing.wasm
kronik deploy dist/billing.wasm --reason 'first deploy'
```

The project has one actor type, named after the project, with one route
(`POST /billing/{key}/increment`, a counter per key) and a test. The SDK and
the WIT are copied into `vendor/kronik-sdk` from the binary (for Go into
`kronik-sdk`, since the go command reserves `vendor/`), so a project needs no
Kronik package from a registry:

| | TypeScript | Rust | Python | Go |
|---|---|---|---|---|
| Actor | `src/actor.ts` | `src/lib.rs` | `src/actor.py` | `main.go` |
| Test | `test/actor.test.ts` | `tests/actor.rs` | `tests/test_actor.py` | `test/actor_test.go` |
| SDK | `"@kronik/sdk": "file:vendor/kronik-sdk"` | `kronik-sdk = { path = "vendor/kronik-sdk" }` | `[tool.kronik] sdk = "vendor/kronik-sdk"` | `replace kronik.dev/sdk => ./kronik-sdk` |
| Toolchain | Node.js 22.20 or later with npm; jco 1.39.0, ComponentizeJS 0.23.0 and TypeScript 7.0.2, pinned in `package.json` | Rust 1.99.1 and `wasm32-wasip2`, pinned in `rust-toolchain.toml` | Python 3.11 or later for the tests; componentize-py, WASI-Virt and wasm-tools from `scripts/install-sdk-tools.sh` | TinyGo, Go, wit-bindgen-go, WASI-Virt and wasm-tools from `scripts/install-sdk-tools.sh` |

The Python and Go toolchains are pinned in
[ADR 0030](../adr/0030-python-go-components.md);
`scripts/install-sdk-tools.sh [DIR]` installs them into
`~/.cache/kronik/sdk-tools` (or `DIR`, then set `KRONIK_SDK_TOOLS`), where
`kronik build` looks for them. A missing tool, or one of another version,
fails the build with the command that installs it.

## The TypeScript SDK

The module's default export is the actor type:

```ts
import { actor } from "@kronik/sdk";

export default actor({
  kind: "counter",
  schemaVersion: 1,
  routes: [{ method: "POST", pattern: "/counter/{key}/increment" }],
  http(req, ctx) {
    const n = (ctx.state.getJson<number>("n") ?? 0) + 1;
    ctx.state.setJson("n", n);
    return ctx.json(200, { n });
  },
});
```

`actor()` takes the manifest (`kind`, `schemaVersion`, `routes`,
`capabilities`) and the handlers `http(req, ctx)`, `message(msg, ctx)`,
`timer(timer, ctx)` and `migrate(from, ctx)`. `ctx` has the same parts as the
Rust SDK's `Ctx`: `state`, `sql`, `http`, `crypto`, `secrets`, `timers`,
`random`, `log`, and `send`, `call`, `now`, `causalId`, `self`, `secret`,
`subject`, plus the outputs `json`, `text`, `status`, `reply` and `none`.

- The API is synchronous: the host does the waiting.
- Every input runs as one turn on a fresh instance; module-level variables do
  not survive it, and module scope runs once, at build time.
- A handler that throws (or an `async` handler whose promise rejects) fails
  the turn and discards its writes: `Rejected` becomes
  `handler-error::rejected`, anything else `handler-error::failed` with the
  error's name and message.
- Failed host calls throw `KronikError`, whose message names a
  `kronik explain` topic.
- `console.log` and friends write to the turn's log.
- Standard `fetch` works (M22): each request is an `http.fetch` effect, as
  `ctx.http.fetch` is, with the same grants (`http:<host>`), recording,
  replay and simulators in forks. A handler that calls it is `async`:

  ```ts
  async http(req, ctx) {
    const [a, b] = await Promise.all([
      fetch("https://api.example.com/a", { headers: { authorization: "Bearer {{secret:api-key}}" } }),
      fetch("https://api.example.com/b"),
    ]);
    return ctx.json(200, { a: a.status, b: await b.json() });
  },
  ```

  A header value with `{{secret:NAME}}` gets the secret inserted by the
  host (it needs `secret:NAME`); the actor never holds the value. Requests
  run one at a time, in the order their bodies complete, while the handler
  waits. Every failure (a missing grant, a network error, a timeout) is the
  same `TypeError` from `fetch`: use `ctx.http.fetch` when the kind of error
  matters, and for `foreign://` URLs. `examples/uptime-ts` uses `fetch`.
  Await every `fetch`: a request the handler never waits for is never
  sent, and the turn's log warns about it. A request is bounded by the
  effect timeout. Time does not move during a turn, so a `setTimeout` or
  `AbortSignal.timeout` is due at once: racing one against `fetch` does
  not bound the request, and it ends the same way in replay.
- There is no file system or process: the component imports only what the
  [allowlist](../reference/wit.md#wasi-and-the-import-allowlist) allows.

### Fuel in JavaScript

A turn may use 50 million fuel (`kronik limits`). JavaScript runs in an
interpreter inside the component, so it costs far more than Rust:

| | Fuel |
|---|---|
| An empty turn | 2.3 million |
| A host call (`ctx.now()`, `ctx.state.get(...)`) | 35 000 to 120 000 |
| Each SQL value in a query result | about 40 000 |
| A simple statement | about 1 000 |

So prefer few host calls with more in each. `todo-ts` keeps a whole list in
one state value; `notes-ts` has SQLite build a page of notes as one JSON text
(`json_group_array`), which costs 22 million fuel for 1000 notes, where 1000
rows of 5 columns would not fit in a turn.

## The Python SDK

The entry module (`[tool.kronik] entry`, default `actor`, in `src/`) binds
the actor type to `handler`:

```python
from kronik import actor


def http(req, ctx):
    n = (ctx.state.get_json("n") or 0) + 1
    ctx.state.set_json("n", n)
    return ctx.json(200, {"n": n})


handler = actor(
    kind="counter",
    schema_version=1,
    routes=[{"method": "POST", "pattern": "/counter/{key}/increment"}],
    http=http,
)
```

`actor()` takes the manifest (`kind`, `schema_version`, `routes`,
`capabilities`) and the handlers `http(req, ctx)`, `message(msg, ctx)`,
`timer(timer, ctx)` and `migrate(from_version, ctx)`. `ctx` has the parts of
the other SDKs in Python's spelling: `state` (`get`, `get_text`, `get_json`,
`set`, `set_json`, `set_for`, `delete`, `keys`), `sql`, `http.fetch`,
`crypto.hmac_sha256` and `sign_ed25519`, `secrets.reveal`, `timers`,
`random`, `log`, and `send`, `call`, `now`, `causal_id`, `self`, `secret`,
`subject`, `current_subject`, plus the outputs `json`, `text`, `status`,
`reply` and `none`.

- The API is synchronous, as in every SDK.
- Module scope runs once, when the component is built (componentize-py
  pre-initializes it); every input runs on a fresh instance, so nothing set
  at run time survives a turn.
- `raise Rejected(...)` gives `handler-error::rejected`; any other exception
  `handler-error::failed` with its message. Failed host calls raise
  `KronikError`, whose `kind` (such as `fetch.network`) says what failed and
  whose message names a `kronik explain` topic.
- `print` writes to the turn's log.
- The standard library is there, but not its file system, sockets or
  subprocesses: the component imports only what the allowlist allows.

## The Go SDK

The main package exports the actor type from `init`:

```go
package main

import "kronik.dev/sdk"

func init() {
	kronik.Export(kronik.Actor{
		Kind:          "counter",
		SchemaVersion: 1,
		Routes:        []kronik.Route{{Method: "POST", Pattern: "/counter/{key}/increment"}},
		HTTP: func(_ *kronik.Request, ctx *kronik.Ctx) (kronik.Output, error) {
			var n int64
			if _, err := ctx.State.GetJSON("n", &n); err != nil {
				return kronik.Output{}, err
			}
			n++
			if err := ctx.State.SetJSON("n", n); err != nil {
				return kronik.Output{}, err
			}
			return ctx.JSON(200, map[string]int64{"n": n})
		},
	})
}

func main() {}
```

`kronik.Actor` has the manifest (`Kind`, `SchemaVersion`, `Routes`,
`Capabilities`) and the handlers `HTTP`, `Message`, `Timer` and `Migrate`.
`*kronik.Ctx` has `State`, `SQL`, `HTTP.Fetch`, `Crypto`, `Secrets`,
`Timers`, `Random`, `Log`, and `Send`, `Call`, `Now`, `CausalID`, `Self`,
`Secret`, `Subject`, `CurrentSubject`, plus the outputs `JSON`, `Text`,
`Status`, `Reply` and `None`.

- Handlers return `(kronik.Output, error)`. `kronik.Rejected(...)` gives
  `handler-error::rejected`; any other error `handler-error::failed` with
  its message, and a panic is recovered into `failed`. Failed host calls
  return a `*kronik.Error`, whose `Kind` (such as `fetch.network`) says what
  failed and whose message names a `kronik explain` topic.
- Package initialization runs in every fresh instance; nothing survives a
  turn.
- The actor package compiles only for TinyGo's `wasip2` target, so its tests
  are a package of their own (`test/`), run by the host's `go test`.

Fuel in Python and Go is far below JavaScript's: in the SDK determinism
test, a turn that does nothing (the counter's `migrate(0)`) uses about 0.2
million fuel in `counter-py` and 0.8 million in `counter-go`, a counter
increment about 0.5 million (Python) and 1 million (Go), and a notes request
with its SQL 0.6 to 0.7 million (Python) and 0.8 to 1.3 million (Go),
against 2.3 million for an empty JavaScript turn.

## Building

`kronik build` (in the project, or `--dir`) writes `dist/<name>.wasm` and
fails, like `kronik deploy`, if the component imports an interface outside
the allowlist (`IMPORT_NOT_ALLOWED`).

- TypeScript: `tsc --noEmit`, then `jco componentize` with the fetch-event
  and stdio features disabled ([ADR 0002](../adr/0002-typescript-components.md);
  `fetch` stays on, [ADR 0070](../adr/0070-wasi-http-outgoing-handler.md))
  on an entry that exports the default export of `package.json`'s
  `kronik.entry` (default `src/actor.ts`). ComponentizeJS output differs from
  build to build, so `kronik build` keeps the previous component when no
  input changed (the project's files, the SDK, the toolchain versions and
  the flags); `--force` rebuilds. `--entry src/step2.ts` builds another
  entry of the project as the variant `dist/<name>-step2.wasm`, the way
  `counter-ts` builds the changed counter of the M3 demo.
- Rust: `cargo build --release --target wasm32-wasip2`, with the paths of
  the project and of Cargo's home remapped, so the same sources build the
  same component wherever they are.
- Python (`pyproject.toml`): `componentize-py` on the entry module with the
  SDK and `src/` on its path, then WASI-Virt, which denies the file system
  and sockets. `--entry step2` builds `src/step2.py` as
  `dist/<name>-step2.wasm`.
- Go (`go.mod`): `tinygo build -target=wasip2` with the SDK's world, then
  WASI-Virt. `--entry ./step2` builds the package `./step2` as
  `dist/<name>-step2.wasm`.
- For Python and Go, unchanged inputs (the project, the SDK, the tool
  versions and the flags) keep the previous component, as for TypeScript.

## Testing

The testkits run the project's component in a test host (`kronik
test-host`): an in-memory node with the real scheduler, runtime and effect
gate, where the clock moves only when the test advances it, and outgoing
HTTP is answered by stubs and recorded. Starting a test host builds the
project, so tests run the code they see. The `kronik` binary comes from
`KRONIK_BIN` or `PATH`; compiled components are cached in `.kronik/code`.

Every request waits until what it started has finished: messages are
delivered and timers that came due have fired. A test can check the outcome
right after it.

```ts
import assert from "node:assert/strict";
import { test } from "node:test";
import { TestHost } from "@kronik/sdk/testkit";

test("a failed delivery is retried", async (t) => {
  const host = await TestHost.start();
  t.after(() => host.close());
  await host.secret("relay-signing-key", "k");
  await host.grant("webhook-relay", "secret:relay-signing-key");
  await host.grant("webhook-relay", "http:webhooks.example.com", "idempotency-keyed");
  await host.stub({ url: "https://webhooks.example.com/", status: 200 });
  await host.stub({ url: "https://webhooks.example.com/", status: 503, times: 1 });

  const res = await host.http("POST", "/hooks/acme", { body: { event: "paid" } });
  assert.equal(res.status, 502);
  await host.advance(1000);
  assert.equal((await host.requests()).length, 2);
});
```

```rust
use kronik_sdk::testkit::TestHost;

#[test]
fn counts() {
    let mut host = TestHost::start(env!("CARGO_MANIFEST_DIR")).unwrap();
    let res = host.http("POST", "/counter/alice/increment", "").unwrap();
    assert_eq!(res.json::<serde_json::Value>().unwrap()["n"], 1);
}
```

```python
class CounterTest(unittest.TestCase):
    def test_counts(self):
        host = TestHost.start(ROOT)
        self.addCleanup(host.close)
        self.assertEqual(host.http("POST", "/counter/alice/increment").json(), {"n": 1})
```

```go
func TestCounts(t *testing.T) {
	host := testkit.Start(t, testkit.Options{Dir: ".."})
	var got struct{ N int }
	host.HTTP("POST", "/counter/alice/increment", nil).JSON(&got)
	if got.N != 1 {
		t.Fatalf("n = %d", got.N)
	}
}
```

| TypeScript (async) | Rust | Python | Go | |
|---|---|---|---|---|
| `http(method, path, { body, headers })` | `http`, `http_with_headers` | `http(method, path, body=, headers=)` | `HTTP(method, path, body, headers...)` | A request through the gateway |
| `send(actor, name, body)` | `send` | `send` | `Send`, `SendReply` | A message as the operator |
| `advance(ms)` | `advance(Duration)` | `advance(ms)` | `Advance(ms)` | Moves the clock; due timers fire |
| `stub({ url, method, status, headers, body, error, times })` | `stub(Stub::url(..))` | `stub(url, ...)` | `Stub(testkit.Stub{...})` | Answers outgoing requests whose URL starts with `url`; the newest match wins; `error` is `connect` or `io` |
| `requests({ clear })` | `requests`, `take_requests` | `requests(clear=)` | `Requests(clear)` | Outgoing requests, with the secrets the host inserted |
| `grant`, `secret` | `grant`, `secret` | `grant`, `secret` | `Grant`, `Secret` | What an operator sets up |
| `state(actor)`, `stateJson(actor, key)` | `state`, `state_json` | `state`, `state_json` | `State`, `StateJSON` | An actor's key-value state |
| `api(method, path, body)` | `api` | `api` | `API` | Any request to the daemon's API (`/v1/...`), as `kronik` sends it |

A request no stub matches fails as if the connection were refused. The seed
of ids and guest randomness is 0, or `KRONIK_TEST_SEED`. A TypeScript test
can deploy several actor types or variants of one project:
`TestHost.start({ entries: ["src/actor.ts", "src/ledger.ts"] })` builds each
entry (as `kronik build --entry` does), and `wasm` adds built components.

## Examples

`examples/`, in a checkout of the repository, has each example in several
languages where it makes sense; the TypeScript, Python and Go ones are twins
of the Rust ones, with the same routes and JSON.

| Rust | TypeScript | Python | Go | |
|---|---|---|---|---|
| `counter-rs` | `counter-ts` | `counter-py` | `counter-go` | The brief's counter |
| `notes-rs` | `notes-ts` | `notes-py` | `notes-go` | Notes in SQL state, paged, with a two-step migration |
| | `todo-ts` | | | To-do lists with a timer that removes done items a day later |
| `webhook-relay-rs` | `webhook-relay-ts` | `webhook-relay-py` | `webhook-relay-go` | Signed webhook forwarding with retries by timer |
| | `billing-ts` | | | Invoices with VAT, a `call` to a ledger with a compensation, charges through `payments.internal`; `src/eu-vat.ts` is the change to propose |

`scripts/build-examples.sh`, `build-examples-ts.sh`, `build-examples-py.sh`
and `build-examples-go.sh` build them into `examples/dist`; `npm test
--workspaces` in `examples/` runs the TypeScript ones' tests, `python3 -m
unittest discover -s tests` and `go test ./...` (in `test/`) the Python and
Go ones'.
