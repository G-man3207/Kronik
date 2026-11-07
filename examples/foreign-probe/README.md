# foreign-probe

A deliberately hostile foreign actor, for the isolation conformance run
(ADR 0064, `scripts/isolation-conformance.py`). It is packed with OCI user 0
(`scripts/build-foreign-examples.sh --only foreign-probe`), so that it is the
strongest confined actor: root inside the sandbox. It serves the checks below
over HTTP; the harness asks it to try, and compares what it reports with what
the host observes (listeners that saw no connection, canary files that must
not appear outside the sandbox).

It is a standalone Cargo project (one dependency, `libc`), not part of the
`examples/` workspace, and a static musl binary. It must never run on a host
outside a sandbox: it needs `KRONIK_PROBE_TOKEN` (32 hex digits) and refuses to
start without it, and it only ever creates its own exclusive canaries and
objects.

| Endpoint | What it tries |
|---|---|
| `GET /healthz` | `200 ok` |
| `GET /check/control` | Positive controls: its own files, sockets and child process work |
| `GET /check/paths?path=...`, `/check/marker?path=...&token=...` | Reading host paths, and a host marker file that must be absent |
| `GET /check/write?dir=...&token=...` | Writing an exclusive canary outside its sandbox |
| `GET /check/network?tcp=...&udp=...&unix=...&abstract=...` | TCP, UDP (DNS included), Unix and abstract sockets to host listeners |
| `GET /check/processes?token=...` | Seeing or signalling processes outside the sandbox |
| `GET /check/sysv?key=...` | Attaching to host SysV shared memory |
| `GET /check/devices`, `/check/guest-disks`, `/check/identity` | Devices, the microVM's own disks and namespace identity |
| `GET /check/fill-data?token=...` | Fills its data drive until `ENOSPC` |

An unexpected error number is reported as an error, never as "absent".
