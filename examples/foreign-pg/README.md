# foreign-pg

Postgres behind a small HTTP/1.1 shim: the foreign actor of Kronik's M14
fork tests (`fork_mode = "sandbox"`, docs/design/m14-foreign-forks.md). The
shim is a standalone Cargo project (std only, no dependencies), not part of
the `examples/` workspace.

```text
foreign-pg [--listen ADDR]     default: 0.0.0.0:8080
```

At start it runs the image's `docker-entrypoint.sh postgres` (data in
`$PGDATA`, `/data/pg`, so on the actor's persistent `/data`; trust
authentication on 127.0.0.1) and listens once `psql -h 127.0.0.1` answers.
If Postgres exits, so does the shim.

| Endpoint | Answer |
|---|---|
| `GET /healthz` | `200 ok` |
| `POST /sql` | runs the body with `psql -X -q -At -F '\|' -v ON_ERROR_STOP=1`: `200` with its output, `400` with its error |
| `GET /egress` | `200 reachable` or `200 unreachable: <error>`: a TCP connect to 1.1.1.1:443 within 2 s |

Anything else is a `404`. Connections are kept alive (`Content-Length`
bodies only); each request is logged as one line on stdout.

Build the image with `scripts/build-foreign-examples.sh --only foreign-pg`.
It needs docker: the base is `postgres:16.4-alpine3.20`, pinned by digest,
exported with `docker export` and flattened into one layer with the shim at
`/usr/local/bin/foreign-pg`. The image (`examples/dist/foreign-pg.oci`,
`foreign-pg:dev`) runs as root on port 8080; Postgres's entrypoint drops to
the `postgres` user. `--check` rebuilds it from scratch and compares
digests: it is reproducible, because the base is pinned and the packer
writes owners, times and order of its own.
