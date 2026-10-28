# 0026. DNS-01 for the preview wildcard: an exec hook

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M11's preview forks answer at `<id>.<preview_domain>`. A name per preview
fork means a certificate per fork, unless one wildcard certificate,
`*.<preview_domain>`, covers them all. ACME issues wildcards only by DNS-01
(RFC 8555 §7.1.3): the CA looks up a TXT record at
`_acme-challenge.<preview_domain>`, so whoever gets the certificate must be
able to write to the domain's DNS zone. TLS-ALPN-01 on the gateway's port
(ADR 0009) can't do that.

Every DNS host has its own API (Cloudflare, Route 53, Gandi, deSEC, a
BIND server with RFC 2136 updates, and hundreds more). Kronik has none of
these APIs built in and no way to test against them in CI.

## Decision

- **A `Dns01` trait** in `kronik-gateway::tls` (`present` and `cleanup` of a
  TXT record) is the seam, and **one provider: an exec hook**.
  `[tls] dns01_hook = "/usr/local/bin/kronik-dns01"` is run as
  `<hook> present <fqdn> <value>` and `<hook> cleanup <fqdn> <value>`, with
  `fqdn` = `_acme-challenge.<preview_domain>.` (with the final dot). Exit 0
  is success; anything else, or no exit within two minutes, is a failure: a
  failed `present` fails the order, which is retried with the usual ACME
  backoff (a minute, doubling to an hour), and a failed `cleanup` is logged
  as a warning. The hook's stdout and stderr go to the daemon log. It runs
  in its own process group, killed as a whole on timeout, with the
  daemon's environment minus `KRONIK_MASTER_KEY` and `KRONIK_TOKEN`. This
  is the contract of lego's `exec` provider, so existing scripts carry over
  with little change.
- **`[tls] dns01_propagation`** (default `"60s"`) is the wait between a
  successful `present` and telling the CA to look. A hook that waits for its
  own propagation sets it to `"0s"`.
- The wildcard is a second ACME certificate from the same CA and account,
  with its own task, cache file (`wildcard.<domain>.pem`) and renewal. The
  certificate resolver serves it for SNI names exactly one label below
  `preview_domain`, and the main certificate otherwise.
- `dns01_hook` needs `mode = "acme"` and `[gateway] preview_domain`; either
  missing is a config error at start. `kronik doctor` checks that the hook is
  an executable file.

## Alternatives

- **Built-in providers** (Cloudflare, Route 53, ...): convenient for the
  covered few, but each is an API client with credentials to store, to keep
  current and to test, and the long tail stays uncovered. A provider can
  still be added later behind the same trait.
- **RFC 2136 dynamic updates with TSIG**: one standard protocol, but most
  hosted DNS doesn't speak it, and it would add a DNS client dependency. A
  hook can call `nsupdate` for the zones that do.
- **acme-dns** (a CNAME from `_acme-challenge` to a small dedicated DNS
  server): limits what a leaked credential can do, but needs a separate
  server. A hook can call acme-dns's HTTP API, so the owner can still choose
  it.
- **No wildcard; a certificate per preview fork**: one order per preview,
  slow and against Let's Encrypt's rate limits. The path prefix
  `/__preview/<id>` on the main name, without `preview_domain`, is the
  fallback without DNS-01.

## Consequences

- The owner writes or picks the hook, and keeps the DNS API credentials
  where the hook reads them, not in `kronik.toml`. Kronik never sees them.
- There is no built-in DNS provider: without a hook there is no wildcard
  certificate, so `mode = "acme"` with `preview_domain` and no hook is
  refused at start, and preview forks use the path prefix only when
  `preview_domain` is unset (ADR 0025).
- `scripts/e2e-acme-pebble.sh` covers the flow against Pebble, with a hook
  that sets the TXT records through pebble-challtestsrv's management API.
