The foreign actor asks for `--isolation trusted`, which runs the image with plain `runc` and the host kernel, and Kronik found no `runc` in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin` or `/usr/bin`. Nothing was written.

To fix it, install `runc` (on Debian and Ubuntu, `apt install runc`), or use the default isolation, gVisor, which only needs `runsc`:

    kronik doctor
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..."

See also: `isolation-level`, `RUNSC_MISSING`.
