The configuration or the operation needs KVM, but `/dev/kvm` is missing or not usable. Everything in v0.1 works without KVM (I11): foreign actors run in gVisor with the `systrap` platform by default.

Typical cause: `platform = "kvm"` under `[foreign]` in `/etc/kronik/kronik.toml` on a VPS without KVM.

To fix it, set `platform = "auto"` or `platform = "systrap"` under `[foreign]`, or run on a host with `/dev/kvm`. `kronik doctor` shows whether the host has KVM:

    kronik doctor

See also: `isolation-level`.
