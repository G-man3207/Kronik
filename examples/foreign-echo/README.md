# foreign-echo

A small HTTP/1.1 server that plays a foreign actor in Kronik's tests. It
reports what the gVisor sandbox looks like from the inside. It is a
standalone Cargo project (std only, no dependencies), not part of the
`examples/` workspace.

```text
foreign-echo [--listen ADDR] [--data-dir DIR]     defaults: 0.0.0.0:8080, /data
```

| Endpoint | Answer |
|---|---|
| `GET /healthz` | `200 ok` |
| `* /echo` | `{"method","path","query","headers":{name: value},"body"}` (names lowercased, repeated headers joined with `, `, body as lossy UTF-8) |
| `GET /info` | `{"pid","uid","gid","hostname","cwd","cpus","mem_total_kb","interfaces":[...]}` |
| `POST /exit?code=N` | `200 {"exit":N}`, then the process exits with status N (0 to 255) |
| `GET /egress[?target=host:port...]` | `{"attempts":[{"target","proto","ok","error"}],"succeeded":N}`: TCP connects to public, IPv6, metadata and Docker bridge addresses and every `target`, UDP DNS queries to 8.8.8.8 and 1.1.1.1, a resolver lookup of example.com. Each attempt times out after 1 s; they run in parallel. Inside a sandbox `succeeded` should be 0. |
| `GET /env?name=X` | `{"name","set","len","sha256"}`: the length and SHA-256 of the value, never the value |
| `GET /data` | increments `DIR/count` and answers `{"count":N}`; `500` if the directory is not writable |

Anything else is a `404` (or `405` for a known path with another method) with
a JSON body. Connections are kept alive (`Content-Length` bodies only); a
malformed request gets `400` and the connection is closed. Each request is
logged as one line on stdout.

Build the image with `scripts/build-foreign-examples.sh` (it writes
`examples/dist/foreign-echo.oci`, `foreign-echo:dev`, running as `nobody`
on port 8080). For local development: `cargo test` and
`cargo run -- --listen 127.0.0.1:18080 --data-dir /var/tmp/echo-data`.
