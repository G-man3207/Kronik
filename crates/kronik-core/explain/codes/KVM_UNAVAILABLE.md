The configuration or the operation needs KVM, but `/dev/kvm` is missing or not usable. Everything in v0.1 works without KVM (I11): foreign actors run in gVisor with the `systrap` platform by default.

This applies either to gVisor's explicit `platform = "kvm"` or to an actor declared with `isolation = "microvm"`, the Firecracker level (M20).

MicroVM admission checks the real KVM API and VM-creation operation; an existing pathname alone is not proof. Missing hardware is an error, not a successful boot test. Never reinterpret a microVM snapshot as a gVisor checkpoint.

For gVisor, select `platform = "auto"` or `"systrap"`. For a microVM, use a host with a usable existing `/dev/kvm`, or explicitly choose `isolation = "gvisor"` instead; changing the gVisor platform does not change a microVM declaration. Kronik does not create a device, load a module or silently weaken isolation. Check the selected service identity and its device access:

    kronik doctor --rootless

See also: `isolation-level`.
