The engine is the identity of the runtime that executes turns: `kronik-<version>+wasmtime-<version>`, which `kronik --version` prints and every turn record carries. Wasmtime and Kronik changes are not assumed to replay identically, so each release has its own engine, and a data directory written by another engine starts only after `kronik upgrade check` with the new binary passed on it: the check replays the last window of logical time with the new engine and compares the result. Without a passing check, `kronik serve` stops with `ENGINE_VERSION_MISMATCH` before it serves anything; a start after one records an `engine upgrade` in the log. Going back to an older binary needs that binary's own check, and works only while the log holds no record the older binary does not know.

    kronik upgrade check --window 6h --config /etc/kronik/kronik.toml

See also: `snapshot`, `ENGINE_VERSION_MISMATCH`, `ENGINE_UPGRADE_DIVERGED`.
