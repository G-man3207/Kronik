A fork is a branch of the system's history from an LSN, with its own state and its own log from there on. Its state is built from the nearest snapshot plus the log up to the fork point, and its configuration (deployments, grants, limits and policy) is the one at the fork point plus what changes in the fork. A fork makes no live effects (I7) but one: a fetch without a stub is denied, except a GET without secret headers to a host in `[fork] live_allowlist` whose grant's effective delivery class is `replay-safe`, which goes out live. With `--no-pii` (M8), a fork has no access to the keys of sealed values. Fork is one of Kronik's five concepts.

    kronik fork create --at now --name try-1 --reason "try a fix"
    kronik fork list

See also: `branch`, `proposal`, `isolated-replay`, `continuous-replay`.
