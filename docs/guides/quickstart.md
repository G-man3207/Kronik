# Quickstart

The finished-product journey: from an empty machine to a verified deploy,
with the release binary. A reader without a public DNS name or a bucket can
do every step; the steps that need one say what to do instead.

Releases are on [GitHub](https://github.com/G-man3207/Kronik/releases).
Current consumers require an actually signed exact tag: `v0.5.0`, `v0.4.1` and
`v0.4.0` are attested, while the historical `v0.3.0` and `v0.1.0` remain
unsigned and are refused. Follow the [installation trust contract](install.md),
or build unreleased code from a trusted checkout with `cargo build -p kronik`
and put `target/debug` on `PATH`. The rest of this journey uses that trusted
binary or an actually signed release, not an unsigned fallback.

## 1. Install

On a fresh Ubuntu 24.04 VPS, as root. The TypeScript app below needs
Node.js 22.20 or later; Ubuntu's own `nodejs` package is 18, so take
Node.js 24 from NodeSource:

```sh
apt-get update && apt-get install -y curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt-get install -y nodejs
curl -fsSL "https://github.com/G-man3207/Kronik/releases/download/v0.5.0/install.sh" | sh
kronik doctor
```

A published signed release's standalone `install.sh` knows its exact version
and base URL. A mirror changes only where the authenticated archive/bundle are
downloaded; obtain the installer itself from the trusted source:
`curl -fsSL "<trusted-url>/install.sh" | KRONIK_BASE_URL="<mirror-url>" sh`.

`install.sh` installs `kronik` and offers to install gVisor's `runsc`.
`kronik doctor` needs no daemon. It reports what this host can run. Its
warnings about `runsc`, KVM, `runc`, network namespaces and the sandbox
concern only foreign actors: the Wasm actors on this page run without them.

## 2. Start

`kronik serve --init` writes `/etc`, creates the `kronik` system group and a
systemd unit (the daemon runs as root, as in earlier versions) and, with
`--domain`, asks Let's Encrypt for a certificate on port 443. Do not run it on a
host you do not own. `kronik serve --init --rootless` installs the nonroot
service of M21 instead, with its own `kronik` user and units (opt-in; its
installed proofs passed on Ubuntu 24.04). It needs systemd 255 or newer, and on
a host without it the command stops and names `--init --root`. See the plan first, and the
[operations guide](operations.md) for the real setup:

```sh
kronik serve --init --dry-run
```

TLS with ACME needs a DNS name that points at the host, and port 443. ACME
is tested against Pebble, not a public certificate authority. Without a
name, serve on a free port instead. `kronik serve` runs in the foreground:
start it in a second terminal and leave it running. Ctrl-C stops it.

```sh
mkdir -p /var/tmp/kronik-quickstart
kronik serve \
  --data-dir /var/tmp/kronik-quickstart \
  --http-listen 127.0.0.1:8080 \
  --api-socket /var/tmp/kronik-quickstart/api.sock
```

Back in the first terminal, point the CLI at that socket once. Every
command below uses it:

```sh
export KRONIK_API_SOCKET=/var/tmp/kronik-quickstart/api.sock
```

On a host set up with `--init`, skip this: the CLI finds
`/run/kronik/api.sock`.

## 3. Create an app

```sh
kronik init --lang ts billing
cd billing
npm install
npm test
kronik build
```

That is one actor type, `billing`, with `POST /billing/{key}/increment`.
`--lang rust` is the same shape. The SDK is copied into the project from
the binary. `kronik build` checks for Node.js 22.20 or later before it runs
the toolchain. See [Writing actors](actors.md).

## 4. First deploy

```sh
kronik deploy dist/billing.wasm --reason 'first deploy'
curl -s -X POST http://127.0.0.1:8080/billing/acme/increment
```

`deploy` compiles the component first; for a TypeScript component of
about 13 MB that takes tens of seconds on 2 vCPU. When its standard error
is a terminal, the CLI says so before it waits. A kind that already has
history cannot be deployed again.
The next change goes through `propose`. With TLS, the same request is
`https://` on the gateway's name. Without a certificate, the gateway is
plain HTTP.

## 5. Traffic

```sh
for i in 1 2 3; do curl -s -X POST http://127.0.0.1:8080/billing/acme/increment; echo; done
kronik history billing/acme
```

Each row is a turn, newest first: its input (`POST
/billing/acme/increment`), its outcome, what it changed (`set n`), and in
`CODE` the hash of the code that ran it. External effects, such as an
`http.fetch` with its method, host and path, follow in a second table, with
the version of each secret they used (`secret:<name>@v<N>`); this counter
makes none.

The oldest turn is `migrate 0 -> 1`. The template declares
`schemaVersion: 1`, so before an actor's first input Kronik runs its
migration from version 0, which every new actor has. The template has no
`migrate` handler, so that turn changes nothing. `kronik actors inspect
billing/acme` shows the state.

## 6. Propose a change

Change the actor to count in steps of two, build it again, and propose the
new component. Kronik forks, replays the window's recorded traffic through
the new code, and writes a behavior diff:

```sh
sed -i 's/?? 0) + 1;/?? 0) + 2;/' src/actor.ts
kronik build
kronik propose dist/billing.wasm --window 1h --reason 'count in steps of 2'
kronik diff show <proposal> --md
```

`<proposal>` is the id `propose` printed. `--dry-run` runs the replay and
writes nothing. A component whose bytes main runs, and already ran at the
proposal's fork point, is skipped, and a proposal with nothing left is
refused; `kronik fork create` and `kronik replay` replay the running code
instead. With several actors, pass every changed component at once
(`kronik propose a.wasm b.wasm`, or a directory that holds one component
per actor kind): they are verified together in one fork, and the diff
reports each actor kind on its own. In a checkout of the
repository, `demo/verify-change.sh` runs this flow with a counter that
increments by two.

## 7. Policy, approve, promote

The policy decides what a proposal needs. `kronik policy show` prints the
brief's six default rules:

- **Denied:** a new error (`no-new-errors`), a fuel regression of more
  than 50% at p99 (`fuel-regression`), and a replay that sampled the
  inputs while payment effects are in play (`payments-full-coverage`).
- **Need an approval:** new orphaned calls (`no-new-orphans`), grounding
  confidence below 0.9 (`low-grounding-needs-approval`), and payment effects
  that replay could not match exactly, such as a changed charge
  (`payments-must-be-exact`).

Any other diff is allowed. The counter change above is allowed
(`Policy ALLOW`), and `promote` alone switches the code. To review every
change by hand, set a policy with one rule:

```sh
cat > review-every-change.toml <<'EOF'
[[rule]]
name = "any-change"
when = "diff.summary.changed"
action = "require_approval"
EOF
kronik policy set review-every-change.toml --reason 'review every change'
```

`kronik policy set` replaces all the rules, so this policy has only that
one; to keep the default rules, add them to the file. `promote` evaluates
the policy again, so the proposal above now needs an approval. Read the
diff, then:

```sh
kronik approve <proposal> --reason 'reviewed the diff'
kronik promote <proposal> --reason 'ship it'
```

`promote` first replays the traffic that arrived after the proposal.

## 8. Rollback

`kronik deployments list` shows the epochs. Epochs count every
configuration change, policy and grants included, so after `policy set`
the deployments' epochs skip a number. Rollback writes a new deployment
with the code that was in force before that epoch:

```sh
kronik deployments list
kronik rollback <epoch> --reason 'back to the previous code'
```

If the schema version changed, rollback is refused.

## 9. Restore

`kronik restore` rebuilds a data directory from a bucket the daemon has been
shipping to: an S3 bucket in production (see
[shipping](operations.md#shipping-to-object-storage)). Without one, a
directory on this machine can play the bucket, with a `file://` URL. That
shows the flow; it is not a backup, since it does not leave the machine.

Write the shipping settings, stop the daemon (Ctrl-C in its terminal) and
start it again with them:

```sh
cat > /var/tmp/kronik-quickstart/ship.toml <<'EOF'
[ship]
enabled = true
url = "file:///var/tmp/kronik-bucket"
EOF
```

```sh
kronik serve \
  --config /var/tmp/kronik-quickstart/ship.toml \
  --data-dir /var/tmp/kronik-quickstart \
  --http-listen 127.0.0.1:8080 \
  --api-socket /var/tmp/kronik-quickstart/api.sock
```

Then take a snapshot. The daemon ships every 10 seconds; `kronik snapshot
list` says `yes` under `shipped` once it is up:

```sh
kronik snapshot create --reason 'before the restore'
kronik snapshot list
```

Stop the daemon again, restore into a new directory, as on a new machine,
and serve that directory on the same address:

```sh
mkdir -p /var/tmp/kronik-restored/keys
cp /var/tmp/kronik-quickstart/keys/master.key /var/tmp/kronik-restored/keys/
kronik restore --from file:///var/tmp/kronik-bucket --data-dir /var/tmp/kronik-restored
```

```sh
kronik serve \
  --data-dir /var/tmp/kronik-restored \
  --http-listen 127.0.0.1:8080 \
  --api-socket /var/tmp/kronik-quickstart/api.sock
```

A restored daemon compiles the components before it listens, which can
take half a minute; it logs `kronik is serving` when it is ready. Then
`curl -s -X POST http://127.0.0.1:8080/billing/acme/increment` continues
from where the counter was. Forks and proposals are not shipped, so the
restored node lacks step 6's proposal and its diff; its deployment and
approval are log records and are there. Restore takes no `--reason` and
needs no running daemon. The master key is never in the bucket, so the
first two commands copy it from the old data directory before the restore
(with `KRONIK_MASTER_KEY`, set it for both commands instead). The restored
directory holds the old node's encrypted stores: without their key,
`kronik serve` stops with `MASTER_KEY_MISSING` rather than make a new key
that can't read them. In a checkout of the repository, `scripts/s3.sh
demo/vps-restore.sh` runs this flow against a local S3 server. This is one
machine and two directories, not a destroyed VPS.

## 10. An agent, via MCP

A token limits what the agent can do. Create one and give it to `kronik
mcp`, which serves MCP on stdin and stdout and forwards to the daemon:

```sh
kronik token create --name agent-1 --scopes read,fork,propose --reason 'the agent'
KRONIK_TOKEN=<the token it printed> kronik mcp
```

Give the token to `kronik mcp` only, as above: exported in your own shell,
it would make your next `kronik approve` act as the agent, which lacks the
`approve` scope (`SCOPE_MISSING`). `kronik mcp` is meant to be started by
the agent's host, as a subprocess, with `KRONIK_TOKEN` in its environment.
`--token` works too, but a flag shows in the shell history and the process
list. The agent starts from `kronik explain agent` (the same text as the
[agent guide](agent.md)) and uses only the tools that guide names: list
actors, read history, propose, read the diff, and ask for approval. A human
approves and promotes, in a shell without the agent's token.

## 11. Live updates over SSE and WebSocket

An actor can hold long-lived connections: a route with the method `SSE` or
`WEBSOCKET` names the actor that accepts them, and its turns send frames to
them. Here is a counter that streams: create a second app next to `billing`
and give it this `src/actor.ts`:

```sh
cd ..
kronik init --lang ts live
cd live
```

```ts
import { actor, Frame, type Ctx } from "@kronik/sdk";

// A counter that streams: POST /live/<key>/increment counts, and every
// client following /live/<key>/events (SSE) or /live/<key>/ws (WebSocket)
// gets {"n"} after each count.
export default actor({
  kind: "live",
  schemaVersion: 1,
  routes: [
    { method: "POST", pattern: "/live/{key}/increment" },
    { method: "SSE", pattern: "/live/{key}/events" },
    { method: "WEBSOCKET", pattern: "/live/{key}/ws" },
  ],
  http(req, ctx) {
    const n = (ctx.state.getJson<number>("n") ?? 0) + 1;
    ctx.state.setJson("n", n);
    // Sent to every follower after this turn commits.
    ctx.connections.broadcast(followers(ctx), Frame.json({ n }));
    return ctx.json(200, { n });
  },
  connections: {
    open(req, ctx) {
      ctx.state.setJson(`follower/${req.connection}`, true);
      ctx.connections.send(req.connection, Frame.json({ n: ctx.state.getJson<number>("n") ?? 0 }));
      return ctx.accept();
    },
    close(closed, ctx) {
      ctx.state.delete(`follower/${closed.connection}`);
    },
  },
});

function followers(ctx: Ctx): string[] {
  return ctx.state.keys("follower/").map((k) => k.slice("follower/".length));
}
```

```sh
npm install
npm test
kronik build
kronik deploy dist/live.wasm --reason 'a live counter'
```

`live` is a new kind, so it deploys directly. Follow the counter from two
more terminals, one command in each: `curl -N` prints each SSE event as it
arrives, and Node.js's built-in client does the same over a WebSocket:

```sh
curl -N http://127.0.0.1:8080/live/demo/events
node -e 'const ws = new WebSocket("ws://127.0.0.1:8080/live/demo/ws"); ws.onmessage = (e) => console.log(e.data)'
```

Each prints `{"n":0}` when it connects (`data: {"n":0}` on the SSE stream,
which also gets a `: keep-alive` comment every 15 seconds). Count in the
first terminal, and both print the new value:

```sh
curl -s -X POST http://127.0.0.1:8080/live/demo/increment
kronik connections list
kronik history live/demo --connection <id>
```

`kronik connections list` shows each open connection with its actor,
protocol and route, and how many frames went in and out. Opening a
connection, each frame a client sends and its close are turns of the actor,
recorded like any other input, and the frames a turn sends are recorded with
it and go out only after it commits: `kronik history --connection` shows a
connection's turns and what became of each frame (`written`, `queued`,
`dropped` or `unknown`). A frame to a connection that has closed is
dropped, not an error. Stop the clients with Ctrl-C: each connection gets
its `close` turn. A restart of the daemon closes every connection
(WebSocket code 1012), and clients reconnect: a browser's `EventSource`
does so by itself. `examples/chat-ts` in the repository is a chat room
built the same way, and [Connections](connections.md) has the rest.

## 12. Large files as blobs

A request body above its kind's blob threshold, 1 MiB by default, does not
go into the log. For code that reads blobs, as code built with the
TypeScript SDK does, the gateway streams it into the blob store as it
arrives, and the turn gets a blob: a reference made of the bytes' hash and
size. A blob is the turn's only until it ends; to keep it, the actor holds
it. Here is a store with one file per key: create a third app and give it
this `src/actor.ts`:

```sh
cd ..
kronik init --lang ts files
cd files
rm test/actor.test.ts
```

```ts
import { actor, BlobRef } from "@kronik/sdk";

// One file per key: PUT /files/<key> keeps the body, GET /files/<key>
// gives it back. The actor holds the file's blob; its state keeps only
// the reference, which keeps nothing alive by itself.
export default actor({
  kind: "files",
  schemaVersion: 1,
  routes: [
    { method: "PUT", pattern: "/files/{key}" },
    { method: "GET", pattern: "/files/{key}" },
  ],
  http(req, ctx) {
    const kept = ctx.state.getJson<{ hash: string; size: number }>("file");
    const old = kept && new BlobRef(kept.hash, BigInt(kept.size));
    if (req.method === "GET") return old ? ctx.blob(200, old) : ctx.status(404);
    // Hold the upload: a blob as it came, a small inline body through put.
    const file = req.blob ?? ctx.blobs.put(req.body);
    if (req.blob) ctx.blobs.retain(file);
    // Let the previous file go.
    if (old && old.hash !== file.hash) ctx.blobs.release(old);
    ctx.state.setJson("file", { hash: file.hash, size: Number(file.size) });
    return ctx.json(201, { hash: file.hash, size: Number(file.size) });
  },
});
```

The template's test counts requests, which this actor does not do, so the
commands above remove it; `examples/media-ts/test` in the repository tests
large uploads with the test host. Build and deploy:

```sh
npm install
kronik build
kronik deploy dist/files.wasm --reason 'a file store'
```

Make a file of 5 MiB, upload it (`curl -T` sends it with `PUT`, streamed
from the disk), read it back and compare:

```sh
head -c 5M /dev/urandom > report.bin
curl -s -T report.bin http://127.0.0.1:8080/files/report; echo
curl -s -o copy.bin http://127.0.0.1:8080/files/report
cmp report.bin copy.bin && echo same
```

The upload answers with the blob's reference,
`{"hash":"b3:…","size":5242880}`: `b3:` and the BLAKE3 hash of the bytes.
The turn's record holds only that reference; the bytes are in the blob
store, under the data directory's `blobs`, and the daemon's memory stays
flat whatever their size. Now ask the daemon about its blobs, with the hash
the upload printed:

```sh
kronik blobs status
kronik blobs inspect <hash>
```

`kronik blobs status` counts the blobs the store keeps and their bytes, and
shows the free disk and the collector's last pass. `kronik blobs inspect`
shows what keeps one blob: a hold (`held by files/report`) and the records
that name it (`log`), while they are within retention.

A reference is not a permission. A turn may use only the blobs its actor
holds, the ones that reached it (an upload, a message's `blobs`, a `fetch`
response) and the ones it wrote. The hash in this actor's state is data: if
the actor did not hold the file, the `GET`'s turn would fail with
`BLOB_NOT_HELD`, and the client would get `500 TURN_FAILED`. Holds change
when the turn commits, as state does. Upload another file to the same key,
and the actor releases the old blob; once retention passes the records that
name it, nothing keeps it, and the collector deletes it
(`kronik blobs gc --dry-run` lists what nothing keeps, and why). A body
below the threshold arrives inline, and `put` stores it as a blob the actor
holds. A request above the kind's upload size, 64 MiB by default, gets
`413 PAYLOAD_TOO_LARGE`, and an actor keeps at most 1 GiB of blobs
(`BLOB_QUOTA_EXCEEDED`);
`kronik limits set files --upload-size 1Gi --reason '...'` raises the
first. `examples/media-ts` in the repository is an image album built the
same way, which also shares images by message and lets them expire by
timer, and [Blobs](operations.md#blobs) in the operations guide has the
rest.
