The isolation level says how code is sandboxed: `wasm` for actors (the default), `gvisor` for foreign actors (their default, `runsc` with the systrap platform), `trusted` for what the operator chooses to trust (plain runc, with a warning), and `microvm` for Firecracker where KVM is available. `microvm` needs a usable `/dev/kvm` and the pinned tool bundle in `[foreign] microvm_dir`; without KVM the add gives `KVM_UNAVAILABLE`, which suggests `gvisor`.

See also: `foreign-actor`, `KVM_UNAVAILABLE`.
