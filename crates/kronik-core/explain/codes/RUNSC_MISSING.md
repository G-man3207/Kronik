Foreign actors run in gVisor, and Kronik could not find its `runsc` binary (`runsc_path` under `[foreign]`, `/usr/local/bin/runsc` by default). `runsc` is optional: Kronik itself needs no external services (I10), but foreign actors need it.

To fix it, install gVisor's `runsc` (the install script offers to), or point `runsc_path` to it, then check the host:

    kronik doctor

See also: `foreign-actor`, `isolation-level`.
