# Installing Kronik

Kronik is one static binary for Linux on x86_64 or aarch64. The target is a
fresh Ubuntu 24.04 VPS. **This checkout's installer requires a signed release.**
No public Kronik signing event has been performed for this cutover: the latest
published `v0.3.0` is still historical and unsigned, with Wasmtime **50.0.0**,
not the current source's 50.0.1 security/engine patch.

For an actually published signed version, obtain its standalone `install.sh`
from the authenticated exact release tag, then use that release's curl-pipe
entry point. It needs neither a checkout nor a runtime helper. It contains its
version and base URL. A mirror changes only the download location:

```sh
curl -fsSL "<trusted-installer-url>/install.sh" | KRONIK_BASE_URL="<mirror-url>" sh
```

Do not bootstrap the script or its trust policy from an untrusted mirror:
executing a script cannot retroactively authenticate that script. Version is
explicit when running the source checkout's installer:

```sh
KRONIK_BASE_URL="<signed-release-url>" KRONIK_VERSION="<exact-version>" sh scripts/install.sh
```

The unchanged historical `v0.3.0` installer still lives at its release URL.
Its five original assets and four supplementary licensed archive/checksum
assets are unchanged. Current consumers refuse those unsigned archives; the
supplement was licensing work, not a new version, signature or security patch.


## Prerequisites

- `curl` and CA certificates, for the installer. A minimal image needs
  `apt-get update && apt-get install -y curl ca-certificates`.
  The installer bootstraps a source-hash-pinned official static GitHub CLI,
  **not** Ubuntu 24.04's old system `gh`; no GitHub account/token is required.
  Fresh verification needs HTTPS access to the official verifier and maintained
  Sigstore TUF endpoints, even when release artifacts use a local mirror.
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

1. selects `kronik-<arch>-unknown-linux-musl.tar.gz` and its standard
   `.tar.gz.sigstore.json` attestation bundle;
2. downloads official GitHub CLI 2.103.3 for the architecture and checks its
   SHA-256 against a value in the trusted source **before** reading or executing
   it. Its original license stays beside it in private temporary storage;
3. verifies the archive's actual digest, exact release workflow/tag and source
   ref, GitHub Actions issuer, hosted runner, and numeric repository **1432583300**
   from the **verified certificate**. The verifier gets private HOME/config/cache,
   no operator credentials and no runtime trust-policy overrides. Missing,
   tampered, unsigned or wrong-identity artifacts fail before installation;
4. streams only the named binary/license/notice members, checks ELF architecture,
   then runs the authenticated candidate. It retains notices in
   `<install-directory>/kronik-licenses/` and stages the executable privately on
   the destination filesystem before renaming it. A notice, copy or sync failure
   leaves the existing executable unchanged;
   When the GNU helper is explicitly selected, it authenticates and stages that
   separate archive too before replacing either executable. Copy/notice/sync
   failures keep both existing executables; each replacement uses same-filesystem
   rename. This is not a multi-file power-loss transaction.
5. offers to install gVisor's `runsc`, which only foreign actors need
   ([ADR 0003](../adr/0003-gvisor-bridge.md)): the pinned release
   `release-20261019.0`, checked against a SHA-512 written into the script,
   into `/usr/local/bin`. It asks on the terminal; piped into `sh` without a
   terminal (in a container, say) it installs nothing;
6. suggests `kronik doctor`, which shows what the host can run.

The environment changes what it does:

| Variable | |
| --- | --- |
| `KRONIK_BASE_URL` | Where the release's files are (`https://`, `http://` or `file://`); a release's `install.sh` has its own |
| `KRONIK_VERSION` | Exact signed version; defaults to the published installer's own version |
| `KRONIK_INSTALL_DIR` | Where `kronik` goes |
| `KRONIK_INSTALL_RUNSC` | `yes`, `no`, or `ask` (the default) |
| `KRONIK_INSTALL_KEYHELPER` | `yes` to select the separate signed x86_64 GNU PKCS#11 helper; `no` by default |
| `TMPDIR` | Parent for private `mktemp` directories; must be writable and executable because the verified candidate runs before installation. With a `noexec` `/tmp`, use an already owned executable directory such as the install directory |

For manual installation, first establish a trusted modern GitHub verifier and
apply the exact policy in [ADR 0100](../adr/0100-signed-reproducible-releases.md).
An adjacent checksum is not signature verification. For example, with `version`
set to an actually signed release and `archive` to the correct architecture:

```sh
gh attestation verify "$archive" --bundle "$archive.sigstore.json" \
  --repo G-man3207/Kronik \
  --cert-identity "https://github.com/G-man3207/Kronik/.github/workflows/release.yml@refs/tags/v$version" \
  --source-ref "refs/tags/v$version" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners --format json \
  --jq 'if length > 0 and all(.[].verificationResult.signature.certificate; .sourceRepositoryIdentifier == "1432583300") then true else error("wrong repository") end'
```

Only after that succeeds may a new installation read the archive's flat members.
Use the installer for atomic replacement. Retain the original notices whenever
redistributing the binary. The trusted verifier checks signatures; the downloaded
product is never executed to verify itself.

### Optional GNU PKCS#11 helper

The musl daemon does not link cryptoki or load a vendor module. A release may
also contain `kronik-keyhelper-x86_64-unknown-linux-gnu.tar.gz`, built separately
with the explicit `pkcs11` feature. It is never selected by default. For a
release that actually carries its standard signature bundle:

```sh
curl -fsSL https://<project>/install.sh | KRONIK_INSTALL_KEYHELPER=yes sh
```

The same pinned verifier, repository **1432583300**, workflow, exact tag/source
ref and issuer authenticate both archives. Missing or unsigned helper assets
fail closed; there is no raw-binary, checksum-only or unsigned fallback. The
installer retains its original notices in `kronik-keyhelper-licenses/` beside
`kronik-keyhelper`, on the same destination filesystem as the daemon.

The helper requires the system x86_64 GNU loader, libc and libgcc_s. The selected
vendor PKCS#11 module, its own dependencies, token/key and access configuration
are **not bundled**. ELF symbol versions are observations, not a supported
glibc floor or proof on Ubuntu, ARM or physical HSMs. Configure the actual
`helper_path`, hash-validated `module`, token manufacturer/model/serial,
enrolled `key_id`/`key_version` and private `pin_file` under `[keys.pkcs11]`;
obtain its non-secret possession probe through the real operator command:

```sh
kronik --json keys enroll --config /owned/hsm/kronik.toml
```

Save that returned probe in `[keys.pkcs11.probe]`; labels and slot numbers
are not key identities. See [ADR 0093](../adr/0093-pkcs11-through-a-helper-process.md).
Local unsigned candidates are exercised only as owned build artifacts, not by
weakening this production installer. A public signed helper/tag and complete
B6 lifecycle require their own actual release evidence.

## What a release contains

| File | |
| --- | --- |
| `kronik-<target>.tar.gz` | Static, stripped musl `kronik`, `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.txt` and a target-specific `kronik.cdx.json` |
| `kronik-keyhelper-x86_64-unknown-linux-gnu.tar.gz` | Optional GNU helper, its own `kronik-keyhelper.cdx.json` and original `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES.txt`; same checksum/signature sidecars |
| `kronik-<target>.tar.gz.sha256` | Human/archive checksum, not authentication |
| `kronik-<target>.tar.gz.sigstore.json` | Standard keyless bundle authenticated against exact source policy |
| `install.sh` | Standalone archive installer, exact version/base URL and embedded shared gVisor setup |
| `SHA256SUMS` | Human checksums of unsigned build outputs and reproducibility evidence, not a signature |
| `reproducibility.json` | Actual two-build ELF/member/distribution comparison and source/input identities |

The additive `v0.3.0` archives retain its original published `kronik.cdx.json`
verbatim, not a newly generated per-target SBOM. Its original installer and
`SHA256SUMS` continue to describe the original raw binaries; the new sidecars
describe only the supplementary archives.

The Cargo SBOM supplies dependency identities/license expressions, not a
substitute for license texts. `scripts/package-release.py` uses locked,
target-filtered Cargo metadata for the binary's normal dependency closure,
retains packaged license/notice files and source-specific copyright comments,
and fails rather than inventing a missing license or copyright holder.
Local third-party path dependencies are not project code merely because Cargo's
`source` is null. They need an explicit `ORIGIN.json` with the actual upstream
revision/archive, ordered hash-checked patches, license/attribution paths and a
hash-checked maintained-file inventory; notices retain that provenance and the
verified original texts. Unclassified local dependencies and changed inputs fail.
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

Separate tool recipes reuse this collector rather than assuming the daemon's
dependency or native-runtime closure. `packages` and `dependency_notices` accept
the explicit `root_name="kronik-guest-init"` input; the default remains `kronik`.
`rust_notices` retains the actual supplied Rust documentation/license inputs,
with `copyright_files=("COPYRIGHT-library.html", "COPYRIGHT.html")` for the tool
recipe's full compiler/runtime records. These records do not by themselves prove
every native object's source attribution. A plain-Cargo musl build must establish
its actual Rust/native source provenance, not borrow the Zig inputs or infer a
version from its target name. No optional helper ABI or tool bundle is claimed
accepted without its actual build, graph, original notices and runtime evidence.

## Building a release

`scripts/release.sh` builds **unsigned candidates** into `dist/release/`. It
cross-compiles both architectures with pinned Rust, Zig 0.17.0,
cargo-zigbuild 0.24.0 and cargo-cyclonedx 0.5.9, retaining original notices and
per-target SBOMs. `SOURCE_DATE_EPOCH` controls the existing SBOM generator;
archive metadata is deterministic. This alone is not reproduction or signing.
Set `KRONIK_RELEASE_KEYHELPER=yes` to add the separate x86_64 GNU helper;
the default daemon targets and normal dependency closures stay unchanged.
Its normal-root/Rust notices do not borrow the daemon's Zig, musl or embedded
SDK inputs. GNU packaging verifies the ELF architecture, dynamic loader and
system-library dependency set without executing it; binutils `readelf` is needed.

For a committed source snapshot, `scripts/reproduce-release.py` builds twice
in independent source/target directories without reusing compiled Kronik output.
It requires equal ELF bytes, each archive payload and the final unsigned
distribution. Only pinned tools/source inputs are shared. Actual results are
recorded in `reproducibility.json`; differences fail the release.
The same `KRONIK_RELEASE_KEYHELPER=yes` selection reaches both independent
builds. The report retains their actual Cargo logs, hashes and compiled paths,
not just a source archive or re-packed cached debug binary.

```sh
KRONIK_BASE_URL="https://<public-exact-release-url>" python3 scripts/reproduce-release.py
```

The existing manual Release workflow must run from the exact package-version
tag in the real repository. It reproduces before scoped GitHub OIDC attestation,
retains the standard bundles beside the archives, and only creates a draft when
explicitly requested. No push/tag trigger was added. A local unsigned candidate
cannot be installed through the production installer; do not add a bypass.

`scripts/e2e-install.sh` requires an actually attested release. It exercises root
and ordinary-user installation, tamper/unsigned refusal preserving a real
executable, and with `RUNSC=1` the existing pinned gVisor yes/install behavior.
The Action CI step also runs a finite genuine-public-bundle consumer/fault drill;
that fixture is not a claim of a public signed Kronik release or an external
security audit.
