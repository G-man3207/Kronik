The engine version, Kronik plus Wasmtime, is part of replay identity and is written in every `TurnBegin` and turn record. This binary's engine version does not match the one that the work at hand was recorded or verified with.

Typical causes:

- Re-executing or replaying turns that were recorded with another engine version.
- Running a new binary against a data directory before `kronik upgrade check` has verified the switch and recorded it as an `EngineUpgrade` record.

To fix it, run a binary with the recorded engine version (`kronik --version` prints a binary's Kronik and Wasmtime versions), or verify the new binary first:

    kronik upgrade check --window 6h

See also: `ENGINE_UPGRADE_DIVERGED`.
