# Writing actors

An actor type is a WebAssembly component that exports the `kronik:actor`
world ([WIT](../reference/wit.md)). Kronik has an SDK for TypeScript and one
for Rust; both come with the `kronik` binary, which vendors them into new
projects, builds the projects and runs their tests.

## Start a project

```sh
kronik init --lang ts billing        # or --lang rust
cd billing
npm install                          # TypeScript only: the pinned toolchain
npm test                             # cargo test for Rust
kronik build                         # dist/billing.wasm
kronik deploy dist/billing.wasm --reason 'first deploy'
```

The project has one actor type, named after the project, with one route
(`POST /billing/{key}/increment`, a counter per key) and a test. The SDK and
the WIT are copied into `vendor/kronik-sdk` from the binary, so a project
needs no Kronik package from a registry:

| | TypeScript | Rust |
|---|---|---|
| Actor | `src/actor.ts` | `src/lib.rs` |
| Test | `test/actor.test.ts` | `tests/actor.rs` |
| SDK | `"@kronik/sdk": "file:vendor/kronik-sdk"` | `kronik-sdk = { path = "vendor/kronik-sdk" }` |
| Toolchain | Node.js 22.20 or later with npm; jco 1.39.0, ComponentizeJS 0.23.0 and TypeScript 7.0.2, pinned in `package.json` | Rust 1.99.1 and `wasm32-wasip2`, pinned in `rust-toolchain.toml` |

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
- A handler that throws fails the turn and discards its writes: `Rejected`
  becomes `handler-error::rejected`, anything else `handler-error::failed`
  with the error's name and message.
- Failed host calls throw `KronikError`, whose message names a
  `kronik explain` topic.
- `console.log` and friends write to the turn's log.
- There is no `fetch`, file system or process: the component imports only
  what the [allowlist](../reference/wit.md#wasi-and-the-import-allowlist) allows.

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

## Building

`kronik build` (in the project, or `--dir`) writes `dist/<name>.wasm` and
fails, like `kronik deploy`, if the component imports an interface outside
the allowlist (`IMPORT_NOT_ALLOWED`).

- TypeScript: `tsc --noEmit`, then `jco componentize` with the HTTP,
  fetch-event and stdio features disabled ([ADR 0002](../adr/0002-typescript-components.md))
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

| TypeScript (async) | Rust | |
|---|---|---|
| `http(method, path, { body, headers })` | `http`, `http_with_headers` | A request through the gateway |
| `send(actor, name, body)` | `send` | A message as the operator |
| `advance(ms)` | `advance(Duration)` | Moves the clock; due timers fire |
| `stub({ url, method, status, headers, body, error, times })` | `stub(Stub::url(..))` | Answers outgoing requests whose URL starts with `url`; the newest match wins; `error` is `connect` or `io` |
| `requests({ clear })` | `requests`, `take_requests` | Outgoing requests, with the secrets the host inserted |
| `grant`, `secret` | `grant`, `secret` | What an operator sets up |
| `state(actor)`, `stateJson(actor, key)` | `state`, `state_json` | An actor's key-value state |
| `api(method, path, body)` | `api` | Any request to the daemon's API (`/v1/...`), as `kronik` sends it |

A request no stub matches fails as if the connection were refused. The seed
of ids and guest randomness is 0, or `KRONIK_TEST_SEED`. A TypeScript test
can deploy several actor types or variants of one project:
`TestHost.start({ entries: ["src/actor.ts", "src/ledger.ts"] })` builds each
entry (as `kronik build --entry` does), and `wasm` adds built components.

## Examples

`examples/`, in a checkout of the repository, has each example in both
languages where it makes sense; the TypeScript ones are twins of the Rust
ones, with the same routes and JSON.

| Rust | TypeScript | |
|---|---|---|
| `counter-rs` | `counter-ts` | The brief's counter |
| `notes-rs` | `notes-ts` | Notes in SQL state, paged, with a two-step migration |
| | `todo-ts` | To-do lists with a timer that removes done items a day later |
| `webhook-relay-rs` | `webhook-relay-ts` | Signed webhook forwarding with retries by timer |
| | `billing-ts` | Invoices with VAT, a `call` to a ledger with a compensation, charges through `payments.internal`; `src/eu-vat.ts` is the change to propose |

`scripts/build-examples.sh` and `scripts/build-examples-ts.sh` build them
into `examples/dist`; `npm test --workspaces` in `examples/` runs the
TypeScript ones' tests.
