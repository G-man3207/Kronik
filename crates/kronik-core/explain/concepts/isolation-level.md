The isolation level says how code is sandboxed: `wasm` for actors (the default), `gvisor` for foreign actors (their default, `runsc` with the systrap platform), `trusted` for what the operator chooses to trust (plain runc, with a warning), and `microvm` for Firecracker where KVM is available. `microvm` is reserved and gives `NOT_IMPLEMENTED` in v0.1.

See also: `foreign-actor`, `KVM_UNAVAILABLE`.
