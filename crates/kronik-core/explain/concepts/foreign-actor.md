A foreign actor is an ordinary Linux binary from an OCI image, always pinned by digest, that runs in gVisor: `runsc` with the `systrap` platform by default, which works without KVM. Only the boundary to it is recorded. Actors call it with `http.fetch` on `foreign://<name>/...`, which requires the capability `foreign:<name>` and is recorded as `foreign.http`. In a fork, the calls are matched against recordings and the foreign actor is not started. The sandbox has no outgoing network in v0.1, and its persistent directory cannot be replayed.

    kronik foreign add payments --image ghcr.io/org/fake-payments@sha256:... --port 8080 --cpu 1 --memory 512Mi --reason "..."
    kronik foreign list

See also: `isolation-level`, `RUNSC_MISSING`, `FOREIGN_UNAVAILABLE`.
