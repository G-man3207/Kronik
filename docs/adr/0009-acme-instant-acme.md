# 0009. Gateway TLS: rustls, and ACME with instant-acme

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

M6 asks for TLS on the gateway with ACME (`[tls] mode = "acme" | "files" |
"off"`), and `kronik serve --init --domain d --acme-email e` should leave a
server that answers HTTPS for `d`. The brief leaves an open question: is the
ACME library `rustls-acme` or `instant-acme`? Constraints: no C dependencies
beyond SQLite (so `ring`, not `aws-lc-rs`); every dependency passes `cargo
deny` with the current license allowlist; the gateway is shell code on tokio
(ADR 0004 §3), and the effects client already uses hyper-rustls with ring and
the system's roots.

Both crates were built with `ring` and checked with `cargo deny`:

- **rustls-acme 0.15.4** wraps everything: a rustls resolver that answers
  TLS-ALPN-01, a cache, and renewal. But its HTTP client
  (`async-web-client`) brings an async-io stack (`async-io`, `async-net`,
  `blocking`, `polling`), a second runtime with its own thread pool inside
  the daemon. With its `webpki-roots` feature it fails `cargo deny`:
  `webpki-roots` is `CDLA-Permissive-2.0`, which is not on the allowlist.
- **instant-acme 0.8.5** is an ACME client only: account, order,
  challenges, finalize, certificate. With `ring` and `hyper-rustls` it runs
  on the hyper-rustls and tokio already in the graph, with the system's
  roots. `cargo deny` passes. `Account::builder_with_root` trusts an extra
  CA, which is how a private ACME CA (and Pebble) works.

## Decision

- **instant-acme 0.8.5 (pinned)**, plus `rcgen` for the TLS-ALPN-01
  challenge certificate, `x509-parser` for expiry, and `rustls` and
  `tokio-rustls` with ring for the server. `kronik-gateway::tls` (about 300
  lines) implements the rest:
  - a rustls certificate resolver that presents the current certificate, or
    the challenge certificate (with the `acmeIdentifier` extension) when the
    client offers ALPN `acme-tls/1`;
  - TLS-ALPN-01 on the gateway's own port, so no port 80 listener is needed;
  - the account credentials and the certificate (chain and key, mode 0600)
    cached under `<data_dir>/tls/acme/<hash of the directory URL>/`, so
    staging and production never mix;
  - renewal 30 days before expiry, checked at least every 12 hours, and a
    backoff from a minute to an hour after a failure, while the old
    certificate keeps being served.
- **`mode = "files"`** loads `cert_file` and `key_file` at start (a bad file
  stops the start) and reloads them every 12 hours, so a certificate renewed
  by another tool is picked up.
- **`[tls]` gains `acme_directory`** (Let's Encrypt production by default)
  and `acme_ca_file`, a CA to trust for a private ACME server. Pebble needs
  both.

## Alternatives

- **rustls-acme**: less code here, but a second async runtime and a license
  outside the allowlist (or no default roots without `webpki-roots`).
- **HTTP-01 instead of TLS-ALPN-01**: needs a listener on port 80 next to
  `http_listen`, which the brief's configuration does not have. TLS-ALPN-01
  works on the HTTPS port alone. Wildcards need DNS-01, which comes with
  preview domains (M11).

## Consequences

- `scripts/e2e-acme-pebble.sh` runs the whole flow against Pebble, Let's
  Encrypt's test CA, with pinned and checked binaries: the gateway gets a
  certificate by TLS-ALPN-01, serves HTTPS that verifies against Pebble's
  root, and after a restart serves the cached certificate without a new
  order.
- A real certificate needs a DNS name with an A record pointing at the host,
  and port 443 reachable from the internet. The CA connects to the gateway
  itself. Let's Encrypt rate-limits failed validations, so a first test uses
  `acme_directory =
  "https://acme-staging-v02.api.letsencrypt.org/directory"`.
- Renewal, the account and the cache are code to maintain. Whether ACME
  Renewal Information is worth adopting (instant-acme supports it) can be
  decided later without changing the cache.
