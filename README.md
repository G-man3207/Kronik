# Kronik

Don't deploy code you hope works. See what it would have done with
yesterday's traffic.

Kronik is a source-available runtime where a system is a deterministic
function of its history, so every change can be verified against real
production traffic before it goes live. It is a single binary that runs
actors: Wasm components with built-in state. All contact with the outside
world is recorded in a log. You can fork the whole system, run real inputs
through new code and review a behavior diff before anything goes live.

## Status

Pre-alpha. Kronik is being built toward v0.1 and is not usable yet. See
[`STATUS.md`](STATUS.md) for progress.

## Development

Run the same checks as CI with `scripts/ci.sh`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for requirements and conventions, and
[`AGENTS.md`](AGENTS.md) if you are a coding agent.

## License

Kronik is licensed under the [Elastic License 2.0](LICENSE) (ELv2).
Contributions require a signed [CLA](CLA.md).
