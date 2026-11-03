# 0093. PKCS#11 through an optional helper process

- **Status:** Accepted narrow exception for M23 B6; integrated helper/release acceptance is not yet claimed.
- **Supersedes:** the parked approval gate, label/slot identity assumptions and unpatched cryptoki 0.10 recommendation.

## Context

The authoritative M23 requirement includes an HSM through PKCS#11. Vendor modules are C shared libraries with platform-specific dependencies. Loading them into the daemon would violate the static-musl core boundary and expose its address space to vendor code. A non-exportable AES key also cannot replace the master seed's six local derivations.

The reviewed exception is one optional glibc helper outside the daemon. The core remains one static-musl binary with unchanged file/env defaults and no vendor C/dlopen. This is not approval of any particular vendor module, a physical-HSM assurance or a general subprocess framework.

## Decision

### One bounded exchange

Extend the existing `ProcessRunner` with one managed, one-shot sensitive exchange. Reuse its program/cwd/explicit-environment conventions; leave ordinary foreign spawning intact. The exchange owns zeroizing request/response buffers, private stdin/stdout pipes and one trusted PIN-file descriptor mapped only to fd3. Request and response are bounded to 4 KiB. Send one request and EOF; discard helper stderr. No PIN/seed in argv, environment, protocol files, diagnostics or inherited daemon log streams, and no arbitrary global inherited-FD API.

Open the PIN with the existing trusted credential ownership/no-follow checks. Keep the child owned by a supervisor until it is reaped. Deadline, output overflow, malformed response, crash, caller cancellation and errors converge on kill **and** wait; kill-on-drop alone is insufficient. A wait future holding the existing Child mutex must be dropped before kill. Deterministic simulation uses Env time and sticky lifecycle state, not a lossy notification as reap evidence.

Make unrelated descriptors close-on-exec rather than blindly closing an unknown range in pre-exec: the standard process exec-error pipe must survive failed exec. Handle an already-fd3 PIN without invalid duplication, preserve standard-I/O/error reporting, and exercise nonexistent/bad executable behavior. Privilege transitions must reapply the required process protections. No helper launch changes host services, namespaces or device policy globally.

### Trusted module and key identity

The helper reads one request, disables dumps before reading sensitive input, loads only the administrator-configured validated module, opens the selected session, performs one operation, finalizes and exits. Bound its memory, output and runtime. The daemon never loads the module.

Select exactly one token by trusted manufacturer, model and serial, not a slot index or display label. Select exactly one `CKO_SECRET_KEY`/`CKK_AES` object by an enrolled ID and version. Check AES256 size, sensitive/nonextractable/nonmodifiable attributes and the required mechanism permissions. Reject duplicate matches, wrong identity/attributes and automatic same-label replacement.

Serials and `CKA_ID` are identifiers, **not** cryptographic fingerprints: an administrator or compromised module can recreate them. Trusted enrollment therefore retains a nonsecret key-possession probe, bound to canonical purpose AAD and the enrolled identity. Before authorizing a new wrap, decrypt and verify that probe. Envelopes cannot choose another module, token, key or untrusted historical version. Retained wrapping versions require trusted enrollment/binding, not arbitrary IDs supplied by stored metadata.

Use AES-GCM byte `C_Encrypt`/`C_Decrypt` for the seed envelope, with a fresh 12-byte IV, authenticated canonical purpose/binding and a 128-bit tag. Do not require `C_WrapKey`/`C_UnwrapKey`: the actual SoftHSM AES-GCM mechanism exposes encrypt/decrypt flags, not key-object wrap flags. The nonextractable object is the KEK; the plaintext being encrypted is Kronik's 32-byte seed.

Reuse ADR 0092's verified fresh-wrap, offline ownership, rewrap, shipping and staged-restore lifecycle. Wrong key/probe/AAD/tag, disabled versions or provider failure never create a fresh seed, replace a valid target envelope or fall back to file/env. Preserve the old raw file unless removal is explicit. No master-seed rotation is introduced.

### Dependency and memory scope

The optional helper uses exact `cryptoki = 0.12.1` with default features disabled. Its reviewed normal path uses pregenerated bindings and no bindgen/clang/vendor link in the daemon. The parked 0.10.0 line has RUSTSEC-2026-0286; patched 0.10.1 still introduces unmaintained paste, contrary to existing deny policy. Add no advisory exception. The final locked helper graph, features, licenses and target builds must still pass the normal checks.

Immediately zeroize successful returned buffers and controlled request/response/PIN material. Do not claim every failed cryptoki/vendor internal allocation is zeroized: the reviewed decrypt wrapper allocates an ordinary Vec and can return on module error before the caller receives it. Non-dumpability, bounded one-shot lifetime and process isolation reduce that exposure but are not a physical-memory or swap-exclusion guarantee for all transient buffers. Preserve the daemon's separately documented long-lived protected-key mappings.

### Separate release artifact

The existing release producer adds the optional
`kronik-keyhelper-x86_64-unknown-linux-gnu.tar.gz` only when
`KRONIK_RELEASE_KEYHELPER=yes`. Its root is `kronik-keyhelper`, with its own
target-specific CycloneDX SBOM, actual normal-dependency and Rust notices,
project LICENSE/NOTICE, checksum and standard Sigstore sidecar. The default
musl daemon artifacts and their cryptoki-free normal closure remain unchanged.
No vendor module or GNU system shared library is bundled.

The same exact repository/workflow/tag/issuer/numeric-ID verification applies
when the standalone installer explicitly selects it with
`KRONIK_INSTALL_KEYHELPER=yes`; no unsigned helper fallback is permitted.
GNU ELF metadata and owned SoftHSM tests do not establish a supported glibc
floor, ARM/Ubuntu execution, a physical HSM or a public signed release.

## Observed capability evidence, not product acceptance

An owned, network-disabled, read-only-container spike exercised authenticated Debian SoftHSM2 2.6.1-3: AES256 sensitive/nonextractable/nonmodifiable keys, real AES-GCM encrypt/decrypt, wrong-key/AAD/tag rejection, finalize/reinitialize and exact serial/ID recovery. Duplicate labels returned two objects; slots changed; `CKA_UNIQUE_ID` was unsupported. The mechanism reported ENCRYPT/DECRYPT only. No host module/package/service installation or physical HSM was used.

This proves the exercised software module capability, not an integrated helper, release ABI floor, daemon lifecycle, IAM, vendor hardware or complete no-plaintext/no-orphan claim. Exact command/package/module digests and source-review caveats are retained on [the project status page](https://github.com/G-man3207/Kronik/wiki/Project-status); only actually exercised integrated checks may be claimed.

## Acceptance evidence required

Build the unchanged musl daemon and optional glibc helper from the final locked graph. Exercise real helper enrollment/probe, fresh wrap, restart, rewrap, shipping, staged restore and migration against owned SoftHSM fixtures; duplicate/replaced token/key/module and wrong version/AAD/tag must fail closed. Exercise private stdin EOF/fd3, same-fd3, bad exec, timeout/overflow/malformed output/crash/cancellation with kill-and-reap/no orphan, resource bounds and scoped secret/PIN needle checks. Verify the actual release ABI/license bundle and root/helper deny paths. Do not substitute mock echo crypto or a module-only spike for product acceptance.
