# Installing Kronik

Kronik is one static binary for Linux on x86_64 or aarch64. On the brief's
target, a fresh Ubuntu 24.04 VPS, the latest
[release](https://github.com/G-man3207/Kronik/releases):

```sh
curl -fsSL https://github.com/G-man3207/Kronik/releases/latest/download/install.sh | sh
kronik doctor
```

A published release's `install.sh` names its release: its base URL is
written into it when the release is built, e.g.
`https://github.com/G-man3207/Kronik/releases/download/v0.3.0`. For a
release's files served from somewhere else, such as a mirror or a local
HTTP server, give their URL to `sh`, not to `curl`:

```sh
curl -fsSL <url>/install.sh | KRONIK_BASE_URL=<url> sh
```
The published `v0.3.0` installer and all five original assets are unchanged.
The release now also provides licensed `.tar.gz` archives and their checksum
sidecars for both targets, usable by this checkout's installer and Action at
`https://github.com/G-man3207/Kronik/releases/download/v0.3.0`. Their binaries
are the exact historical Wasmtime **50.0.0** bytes: this is a licensing
supplement, **not** the Wasmtime 50.0.1 security/engine patch in current source.
The published installation command above still uses the original installer.


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

1. picks `kronik-<arch>-unknown-linux-musl.tar.gz` for the machine and
   downloads it and its `.tar.gz.sha256` sidecar;
2. checks the archive's SHA-256 **before** reading any member;
3. streams the named `kronik`, `LICENSE`, `NOTICE` and
   `THIRD_PARTY_LICENSES.txt` members into private temporary regular files,
   refusing a missing or empty notice, then installs `kronik` into
   `/usr/local/bin` as root, else `~/.local/bin`, with the three notice files
   in that directory's `kronik-licenses/` subdirectory. It stages the verified
   executable in a private temporary file inside the install directory, then
   renames it on the same filesystem. A notice, copy or sync failure leaves
   the existing executable unchanged; no parent-directory write or
   archive-path extraction is needed;
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
| `TMPDIR` | Parent for private `mktemp` directories; must be writable and executable because the verified candidate runs before installation. With a `noexec` `/tmp`, use an already owned executable directory such as the install directory |

For a new installation without the script (use the installer for replacement):

```sh
sha256sum --check kronik-x86_64-unknown-linux-musl.tar.gz.sha256
mkdir kronik-release
tar -xzf kronik-x86_64-unknown-linux-musl.tar.gz -C kronik-release
mkdir -p "$HOME/.local/bin/kronik-licenses"
install -m 755 kronik-release/kronik "$HOME/.local/bin/kronik"
cp kronik-release/LICENSE kronik-release/NOTICE \
  kronik-release/THIRD_PARTY_LICENSES.txt "$HOME/.local/bin/kronik-licenses/"
```

Retain the notices when redistributing the binary. Checksums detect
corruption; a checksum from the same server is not an independent signature.

## What a release contains

| File | |
| --- | --- |
| `kronik-<target>.tar.gz` | Static, stripped musl `kronik`, `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.txt` and a target-specific `kronik.cdx.json` |
| `kronik-<target>.tar.gz.sha256` | The archive's SHA-256, usable without replacing a historical release's checksum manifest |
| `install.sh` | The archive installer, with the release's version and base URL |
| `SHA256SUMS` | SHA-256 of the new archives, their sidecars and installer |

The additive `v0.3.0` archives retain its original published `kronik.cdx.json`
verbatim, not a newly generated per-target SBOM. Its original installer and
`SHA256SUMS` continue to describe the original raw binaries; the new sidecars
describe only the supplementary archives.

The Cargo SBOM supplies dependency identities/license expressions, not a
substitute for license texts. `scripts/package-release.py` uses locked,
target-filtered Cargo metadata for the binary's normal dependency closure,
retains packaged license/notice files and source-specific copyright comments,
and fails rather than inventing a missing license or copyright holder.
Wasmtime's shared root text is reused only at the same upstream revision and
declared license; other absent packaged texts have checked-in, hash-checked
upstream provenance in `scripts/licenses/sources.json`. `crc32c 0.6.8` has no
upstream license file: its declared Apache-2.0 alternative is supplied without
inventing a MIT copyright.

The notices also cover Rust's supplied standard-library dependencies,
musl/Zig native runtime sources, bundled SQLite/ring/BLAKE3 and the embedded
OpenTelemetry definitions and Go SDK/WASI interface sources. The WIT
specifications retain their actual WASI 0.2.0/W3C attribution and terms.
ComponentizeJS/StarlingMonkey, CPython, TinyGo and WASI-Virt runtimes are
external actor-build tools/outputs, not embedded host runtimes. Source notice
collection is conservative and does not claim every listed portion is linked.
This distribution work does not settle contributor provenance or the
licensor/CLA ownership review.

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
release_tmp="$(mktemp -d)"
tar -xzf dist/release/kronik-x86_64-unknown-linux-musl.tar.gz -C "$release_tmp" kronik
KRONIK_BIN="$release_tmp/kronik" scripts/e2e-m1.sh
rm -rf "$release_tmp"
```

`scripts/e2e-install.sh` installs as root from `file://`, as a user with
`curl | sh` over HTTP, keeps the license/notice files, refuses a corrupted
archive, and with `RUNSC=1` also installs `runsc` and checks that `doctor`
finds it. Packaging requires Python 3.11 or later; it fixes archive ordering,
ownership, modes and timestamps, and checks the ELF target/static boundary.

On GitHub, the Release workflow runs the same script, but only when started
by hand; its files are kept as the run's artifact and, if asked, become a
draft release for the maintainers to publish.
