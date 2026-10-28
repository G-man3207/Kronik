# Installing Kronik

Kronik is one static binary for Linux on x86_64 or aarch64. On the brief's
target, a fresh Ubuntu 24.04 VPS:

```sh
curl -fsSL https://<project>/install.sh | sh
kronik doctor
```

A published release's `install.sh` names its release: its base URL is
written into it when the release is built. For a release's files served
from somewhere else, such as a mirror or a local HTTP server, give their
URL to `sh`, not to `curl`:

```sh
curl -fsSL <url>/install.sh | KRONIK_BASE_URL=<url> sh
```

## Prerequisites

- `curl`, for the installer. A minimal image needs
  `apt-get update && apt-get install -y curl`.
- Node.js 22.20 or later, with npm, only to build TypeScript actors;
  `kronik build` checks it. Ubuntu 24.04's own `nodejs` package is 18, too
  old. NodeSource has Node.js 24 for it (as root):

  ```sh
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y nodejs
  ```

- rustup, only to build Rust actors; it installs the toolchain that the
  project pins.
- For Python and Go actors (M15), the pinned toolchains of
  [ADR 0030](../adr/0030-python-go-components.md): componentize-py, Go,
  TinyGo, wasm-tools and WASI-Virt. `scripts/install-sdk-tools.sh` from a
  Kronik checkout installs them into `~/.cache/kronik/sdk-tools` (or
  `$KRONIK_SDK_TOOLS`), where `kronik build` looks; it needs Linux x86_64,
  python3 with pip, and rustup for the two Rust tools.
- gVisor's `runsc`, only for foreign actors; `install.sh` offers it.

## What install.sh does

`install.sh`:

1. picks the binary for the machine (`kronik-x86_64-unknown-linux-musl` or
   `kronik-aarch64-unknown-linux-musl`) and downloads it and the release's
   `SHA256SUMS`;
2. refuses a binary whose SHA-256 is not the one in `SHA256SUMS`;
3. installs `kronik` into `/usr/local/bin` as root, else into
   `~/.local/bin`;
4. offers to install gVisor's `runsc`, which only foreign actors need
   ([ADR 0003](../adr/0003-gvisor-bridge.md)): the pinned release
   `release-20261019.0`, checked against a SHA-512 written into the script,
   into `/usr/local/bin`. It asks on the terminal; piped into `sh` without a
   terminal (in a container, say) it installs nothing;
5. suggests `kronik doctor`, which shows what the host can run.

The environment changes what it does:

| Variable | |
| --- | --- |
| `KRONIK_BASE_URL` | Where the release's files are (`https://`, `http://` or `file://`); a release's `install.sh` has its own |
| `KRONIK_INSTALL_DIR` | Where `kronik` goes |
| `KRONIK_INSTALL_RUNSC` | `yes`, `no`, or `ask` (the default) |

Without the script: download the binary and `SHA256SUMS`, then

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -m 755 kronik-x86_64-unknown-linux-musl /usr/local/bin/kronik
```

## What a release contains

| File | |
| --- | --- |
| `kronik-x86_64-unknown-linux-musl`, `kronik-aarch64-unknown-linux-musl` | Static binaries: musl, with SQLite compiled in, stripped |
| `kronik.cdx.json` | A CycloneDX 1.5 SBOM of the crates in the binary |
| `install.sh` | The installer, with the release's version and base URL |
| `SHA256SUMS` | The SHA-256 of each of the above |

## Building a release

In a checkout of the repository, `scripts/release.sh` builds a release into
`dist/release/`. It cross-compiles both binaries with cargo-zigbuild, which
links with zig and compiles the C code (SQLite, ring) for musl, and remaps
the paths of the checkout and of Cargo's home so they do not end up in the
binaries. Its tools are pinned and installed on first use: zig 0.17.0 (its
SHA-256 is checked), cargo-zigbuild 0.24.0 and cargo-cyclonedx 0.5.9.
Without `KRONIK_BASE_URL`, the release's `install.sh` names no release and
needs the variable when it runs.

```sh
KRONIK_BASE_URL=https://<where the files will be> scripts/release.sh
scripts/e2e-install.sh dist/release        # install.sh in a clean Ubuntu 24.04 container
KRONIK_BIN=$PWD/dist/release/kronik-x86_64-unknown-linux-musl scripts/e2e-m1.sh
```

`scripts/e2e-install.sh` installs as root from `file://`, as a user with
`curl | sh` over HTTP, refuses a corrupted binary, and with `RUNSC=1` also
installs `runsc` and checks that `kronik doctor` finds it.

On GitHub, the Release workflow runs the same script, but only when started
by hand; its files are kept as the run's artifact and, if asked, become a
draft release for the owner to publish.
