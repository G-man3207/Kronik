# Quickstart

The finished-product journey: from an empty machine to a verified deploy,
with the release binary. A reader without a public DNS name or a bucket can
do every step; the steps that need one say what to do instead.

Releases are on [GitHub](https://github.com/G-man3207/Kronik/releases);
the install line below takes the latest. In a checkout of the repository,
`cargo build -p kronik` builds the binary as `target/debug/kronik`.

## 1. Install

On a fresh Ubuntu 24.04 VPS, as root. The TypeScript app below needs
Node.js 22.20 or later; Ubuntu's own `nodejs` package is 18, so take
Node.js 24 from NodeSource:

```sh
apt-get update && apt-get install -y curl
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt-get install -y nodejs
curl -fsSL https://github.com/G-man3207/Kronik/releases/latest/download/install.sh | sh
kronik doctor
```

A published release's `install.sh` knows where its files are. If you serve
a release's files yourself, give their URL to `sh`:
`curl -fsSL <url>/install.sh | KRONIK_BASE_URL=<url> sh`.

`install.sh` installs `kronik` and offers to install gVisor's `runsc`.
`kronik doctor` needs no daemon. It reports what this host can run. Its
warnings about `runsc`, KVM, `runc`, network namespaces and the sandbox
concern only foreign actors: the Wasm actors on this page run without them.

## 2. Start

`kronik serve --init` writes `/etc`, a systemd unit, and, with `--domain`,
asks Let's Encrypt for a certificate on port 443. Do not run it on a host
you do not own. See the plan first, and the
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
`http.fetch` with its method, host and path, follow in a second table; this
counter makes none.

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
that can't read them. In a checkout of the repository, `scripts/minio.sh
demo/vps-restore.sh` runs this flow against a local MinIO.

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
There is no `--token` flag. The agent starts from `kronik explain agent`
(the same text as the [agent guide](agent.md)) and uses only the tools that
guide names: list actors, read history, propose, read the diff, and ask for
approval. A human approves and promotes, in a shell without the agent's
token.
