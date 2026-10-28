# Spikes (M0, archived)

The spikes answered the open questions of milestone M0. Their decisions and
numbers are in the ADRs; the code here is evidence, not a pattern for
production code. Since M0 closed (tag `v0.0.0`) the spikes are archived: they
are not maintained, not built by CI, and not part of the Cargo workspace.
Each spike is a standalone project with its own lockfile.

| Spike | Question | ADR | WIT | Reproduce |
| --- | --- | --- | --- | --- |
| `spike-a-wasmtime` | A Rust component in Wasmtime with a deterministic clock and randomness, fuel, and a fresh instance per call | [0001](../docs/adr/0001-wasmtime-determinism.md) | `5a8d400` | `run.sh`, from `ca784bf` |
| `spike-b-componentize-js` | A TypeScript component via ComponentizeJS in the same world, its imports, determinism and the cost of a fresh instance | [0002](../docs/adr/0002-typescript-components.md) | `5a8d400` | `README.md`, from `v0.0.0` |
| `spike-c-gvisor` | `runsc` without KVM and a bridge into the sandbox | [0003](../docs/adr/0003-gvisor-bridge.md) | none | `README.md`, from `v0.0.0` |
| `spike-d-dst` | Deterministic simulation: madsim or our own executor | [0004](../docs/adr/0004-deterministic-simulation.md) | `5a8d400` | `run.sh`, from `ca784bf` |
| `spike-e-sql` | Per-actor SQL state with sessions and changesets | [0005](../docs/adr/0005-sql-state.md) | none | `run.sh`, from `v0.0.0` |

## Pinned to the WIT they were built against

Spikes A, B and D generate bindings from `wit/kronik-actor.wit` as it was in
`5a8d400`, the draft from the brief. `b8a3b39` amended the WIT for v0.1
(`state.set-for`, `privacy.current-subject`), so spikes A and D no longer
compile in later checkouts. Run them from `ca784bf`, the last commit with the
draft WIT, in a separate worktree:

```sh
git worktree add /tmp/kronik-ca784bf ca784bf
/tmp/kronik-ca784bf/spikes/spike-a-wasmtime/run.sh
/tmp/kronik-ca784bf/spikes/spike-d-dst/run.sh
```

Spike B takes the draft WIT from git itself (`WIT_REV` in its
`scripts/lib.sh`) and runs its components in spike A's harness, so build that
harness from the same `ca784bf` worktree and point `HARNESS` at it, as its
README describes. Spikes C and E do not use the WIT.

The worktree also brings the Rust toolchain that was pinned at the time
(`rust-toolchain.toml`; spike C pins its own). Spikes B and C use the
testbench VPS as well; their results are committed in their `results/`
directories, and the other spikes' numbers are in their ADRs.
