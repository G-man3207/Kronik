# 0021. The CLI against a remote API

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M10: "The CLI reads `KRONIK_URL` and `KRONIK_TOKEN`, or `--url` and
`--token`, and talks to the API over TLS", and "unencrypted HTTP is refused
except against localhost". Since M5 the daemon can serve the JSON API on
TCP (`server.api_listen`), where every request needs a bearer token: with
`[tls]` on it serves HTTPS with the gateway's certificate (from files or
ACME, ADR 0009), and without TLS it accepts only a loopback address. The
CLI only spoke HTTP/1.1 over the Unix socket. M5 left `--token` out on
purpose: a token on a command line shows in shell history and in the
process list (`/proc/<pid>/cmdline`) of every user on the host.

## Decision

- **Where the CLI goes.** `--url`, else `--socket`, else `$KRONIK_URL`,
  else the socket from `$KRONIK_API_SOCKET` or the configuration file, as
  before. `--url` and `--socket` exclude each other. A URL is
  `https://host:port[/]`; the port is required, since 443 (or 80) is
  usually the gateway, whose request log would record the token. `http://`
  is accepted only to `localhost` or a loopback IP address, so a token
  never crosses a network in the clear. Anything else (a path, a query,
  user info, another scheme, an upper-case scheme, anything after `[ip]`
  but `:port`) is `BAD_REQUEST` before a connection is made, and the
  message names only the URL's scheme, host and port.
- **`localhost` is not looked up.** It dials `[::1]`, then `127.0.0.1`
  (RFC 6761), so neither `/etc/hosts` nor DNS can send a token in the clear
  to another machine; plain HTTP dials only loopback addresses.
- **Timeouts.** Connecting takes at most 30 s, and a request fails with
  `UNAVAILABLE` when the daemon stays silent for an hour (a sync replay or
  a promote's catch-up may be that long). `kronik proposal wait` bounds
  each poll by its `--timeout` and retries transport errors (a response cut
  short included) and a proxy's 502, 503 or 504 with backoff, so one reset
  does not end a CI job's wait; a certificate error is not retried.
  `kronik propose` starts a job and follows it without retrying (it has no
  `--timeout` to bound retries): when following fails, the error names the
  proposal and `kronik proposal wait <id>`, which retries (ADR 0022).
- **TLS.** The CLI's client is rustls with ring, as the gateway, with the
  system's root certificates from `rustls-native-certs` (already in the
  tree), which honours `SSL_CERT_FILE` and `SSL_CERT_DIR`: a private CA is
  trusted by pointing `SSL_CERT_FILE` at it, with no Kronik-specific flag.
  The handshake completes before the request is sent, so an untrusted or
  mismatched certificate is reported as `UNAVAILABLE` "TLS to … failed" with
  a hint, never as a broken connection.
- **The server side stays as M5 built it.** The TCP API uses the gateway's
  certificate configuration; M10 adds no second certificate or ACME order.
  One name serves both, and a deployment that wants the API on another name
  puts it in `tls.domains` too.
- **`--token`.** Added as the brief asks, next to `$KRONIK_TOKEN` (the flag
  wins). The CLI help, `cli.md` and the GitHub Action guide say that the
  environment variable is preferred, and the action never puts the token on
  a command line. The token is checked as before (printable ASCII) and only
  ever sent as `Authorization: Bearer`. Commands that do not talk to the
  API (`serve`, `init`, `build`, `doctor`, `restore`, `upgrade`) refuse
  `--url` and `--token` instead of ignoring them.

## Alternatives

- **`--ca-file` / `$KRONIK_CA_FILE`.** Kronik's own knob for what every TLS
  client already reads; it would not help tools such as `curl` next to it.
- **webpki-roots (a compiled-in Mozilla list).** A CLI on a host with a
  corporate CA could not trust it without a rebuild.
- **A separate certificate for the API listener.** More configuration and
  a second ACME challenge for no gain while the gateway's certificate can
  carry the API's name.
- **No `--token` flag.** Contradicts the brief. Its risk is documented and
  avoided in everything Kronik ships (the action, the reference workflow).

## Consequences

- `kronik` adds `rustls` and `rustls-native-certs` as direct dependencies
  (both already compiled into the daemon).
- Remote use needs a token with the command's scopes (M5); every mutation
  over TCP records `token:<name>`.
- `kronik mcp` still bridges only the local socket, with `--token` (or
  `$KRONIK_TOKEN`); it refuses `--url`, since an agent off the host uses
  the TCP API's `/mcp` endpoint directly with a bearer token.
- Human output names next commands without `--url`; after a command given
  `--url`, one reminder line says to add it or to export `KRONIK_URL`.
- Tested by `crates/kronik/tests/remote.rs`: HTTPS with `$KRONIK_URL` and
  `$KRONIK_TOKEN` and with the flags, an untrusted certificate, no token,
  plain HTTP to another host refused, plain HTTP to 127.0.0.1 accepted.
