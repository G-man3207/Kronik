#!/usr/bin/env bash
# Explicit native build, single-job unless --kernel-jobs says otherwise; never called by the daemon or ordinary Cargo builds.
# Prerequisites are caller-installed C/kernel tools and the Rust musl target/runtime.
# No package installation, privilege, devtool container, or prebuilt S3 kernel is used.
# Usage: bash scripts/build-microvm-tools.sh --execute --output /owned/new-tools [--kernel-from /owned/completed-build]
#        [--command-timeout SECONDS] [--kernel-jobs N]
# Every build command is limited to --command-timeout seconds (default 3600) and the kernel compile
# runs --kernel-jobs jobs (default 1, the recorded recipe); a slow machine may need more of either.
# Both installed-tools and full-manifest two-location ext4 proofs are mandatory.
set -euo pipefail
exec python3 - "$@" <<'PY'
import argparse, contextlib, ctypes, hashlib, json, os, pathlib, platform
import re, runpy, shutil, signal, subprocess, sys, tarfile, tempfile, time, tomllib, urllib.error, urllib.request

_spawning = False
_cancel_signal = None
def interrupt(signum, _frame):
    global _cancel_signal
    if _cancel_signal is not None:
        return
    _cancel_signal = signum
    if not _spawning:
        raise SystemExit(128 + signum)
for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, interrupt)

p = argparse.ArgumentParser(description='Build pinned offline microVM tools in a new owned directory')
p.add_argument('--execute', action='store_true', required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
p.add_argument('--kernel-from', type=pathlib.Path,
    help='reuse a protected completed kernel with identical recorded inputs and verified hashes')
p.add_argument('--command-timeout', type=int, default=3600, metavar='SECONDS',
    help='limit for each build command, recorded with it in the provenance (default 3600)')
p.add_argument('--kernel-jobs', type=int, default=1, metavar='N',
    help='parallel jobs of the kernel compile (default 1, the recorded recipe)')
a = p.parse_args()
if not 60 <= a.command_timeout <= 7 * 86400:
    raise SystemExit('--command-timeout must be between 60 seconds and 7 days')
if not 1 <= a.kernel_jobs <= 256:
    raise SystemExit('--kernel-jobs must be between 1 and 256')
repo = pathlib.Path.cwd()
if not (repo / 'crates/kronik-guest-init/Cargo.toml').is_file():
    raise SystemExit('invoke from repository root')
destination = a.output.absolute()
parent = destination.parent
md = parent.lstat()
if not parent.is_dir() or parent.is_symlink() or md.st_uid != os.getuid() or md.st_mode & 0o022:
    raise SystemExit('output parent must be an owned, non-symlink directory, not writable by others')
os.umask(0o077)
if os.path.lexists(destination): raise SystemExit('output installation already exists')
output = pathlib.Path(tempfile.mkdtemp(prefix='.' + destination.name + '.candidate-', dir=parent))
print('Private build candidate and failure evidence: ' + str(output), file=sys.stderr)
work = output / '.build'
work.mkdir()
sources = output / 'sources'
sources.mkdir()
logs = output / 'logs'
logs.mkdir()
arch = platform.machine()
if arch == 'x86_64':
    fc_sha = '06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558'
    config_blob = '8022e6aa517513b8c399fe14d6beca0d6d71661d'
    kernel_arch = 'x86'
elif arch == 'aarch64':
    fc_sha = 'e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256'
    config_blob = '8dac0ead7e3a880db013e81684a88fbef481652d'
    kernel_arch = 'arm64'
else:
    raise SystemExit('only native x86_64 and aarch64 builds are supported')
commit = '003a7905ac5f07e7f0e213951258d5bb80ea31e5'
fc_commit = '95f868c8e345b1cc8faccd1a3c910b4989dc3f58'
epoch = '1772323200'
env = dict(os.environ, SOURCE_DATE_EPOCH=epoch, TZ='UTC', LC_ALL='C',
           KBUILD_BUILD_TIMESTAMP='Sun Mar  1 00:00:00 UTC 2026',
           KBUILD_BUILD_USER='kronik', KBUILD_BUILD_HOST='microvm', KBUILD_BUILD_VERSION='1')
# One compiler job, including Rust; no automatic daemon/download/build integration.
env.update(CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0')
records = {}
commands = []
def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while b := f.read(1024 * 1024): h.update(b)
    return h.hexdigest()
def run(name, args, cwd=work, timeout=None, extra=None, capture=None):
    global _spawning
    if timeout is None:
        timeout = a.command_timeout
    commands.append({'name':name,'argv':[str(x) for x in args],'cwd':str(cwd),'env':extra or {},'timeout_seconds':timeout})
    with open(logs / (name + '.log'), 'xb') as log, (
        open(capture, 'xb') if capture is not None else contextlib.nullcontext(log)
    ) as stdout:
        child = None
        _spawning = True
        try:
            child = subprocess.Popen([str(x) for x in args], cwd=cwd, env=dict(env, **(extra or {})),
                           stdin=subprocess.DEVNULL, stdout=stdout, stderr=log, start_new_session=True)
            _spawning = False
            if _cancel_signal is not None:
                raise SystemExit(128 + _cancel_signal)
            status = child.wait(timeout=timeout)
            if status:
                raise subprocess.CalledProcessError(status, args)
        except BaseException:
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                finally:
                    child.wait()
            raise
        finally:
            _spawning = False
    return (logs / (name + '.log')).read_text(errors='replace')
def fetch(name, url, limit, expected=None):
    # Hosted runners share their addresses, and GitHub's archive host answers
    # 429 to too many downloads from one: such an answer, a server error or a
    # dropped connection is retried, after Retry-After (at most five minutes)
    # or a doubling wait, five times. The partial file goes first; the digest
    # check below stays the same.
    for attempt in range(6):
        try:
            return fetch_once(name, url, limit, expected)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 5: raise
            after = (e.headers.get('Retry-After') or '').strip()
            wait = min(int(after), 300) if after.isdigit() else 15 * 2 ** attempt
            why = 'HTTP ' + str(e.code)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == 5: raise
            wait, why = 15 * 2 ** attempt, str(e)
        (sources / name).unlink(missing_ok=True)
        print(name + ': ' + why + ', retrying in ' + str(wait) + ' s', file=sys.stderr, flush=True)
        time.sleep(wait)
def fetch_once(name, url, limit, expected=None):
    path = sources / name
    start = time.monotonic()
    h = hashlib.sha256()
    n = 0
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'kronik-microvm-builder/1'}), timeout=30) as r, open(path, 'xb') as f:
        if not r.url.startswith('https://'): raise RuntimeError('non-HTTPS redirect')
        while b := r.read(1024 * 1024):
            n += len(b)
            if n > limit or time.monotonic() - start > 600: raise RuntimeError('fetch bound exceeded')
            h.update(b); f.write(b)
        f.flush(); os.fsync(f.fileno())
    actual = h.hexdigest()
    if expected and actual != expected: raise RuntimeError(name + ': digest mismatch')
    records[name] = {'url':url, 'sha256':actual, 'bytes':n}
    return path
def unpack(archive, destination, limit):
    destination.mkdir()
    with tarfile.open(archive) as t:
        total = 0
        members = t.getmembers()
        if len(members) > 200000: raise RuntimeError('source archive entry bound exceeded')
        for m in members:
            total += m.size
            if total > limit: raise RuntimeError('source archive expanded bound exceeded')
        t.extractall(destination, filter='data')
    entries = list(destination.iterdir())
    if len(entries) != 1 or not entries[0].is_dir(): raise RuntimeError('unexpected source archive root')
    return entries[0]
def image_proof(name, selector, extra):
    report = run(name, ['cargo','test','--locked','-p','kronik-foreign','--lib',
        selector,'--','--exact','--ignored','--nocapture'], cwd=repo, extra=extra)
    if not re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', report, re.M):
        raise RuntimeError(name + ': expected exactly one passed test, no failed or ignored tests')

cc = os.environ.get('CC', 'cc')
remap = '-ffile-prefix-map=' + str(work) + '=/kronik-build -fdebug-prefix-map=' + str(work) + '=/kronik-build'
target = arch + '-unknown-linux-musl'
rustc = env.get('RUSTC', 'rustc')
for tool in [cc, rustc, 'cargo', 'make', 'patch', 'ld', 'as', 'readelf', 'ldd', 'dpkg-query', 'flex', 'bison', 'bc', 'perl', 'pkg-config', 'openssl']:
    if not shutil.which(tool):
        raise RuntimeError('required installed build tool is missing: ' + tool)
run('prerequisite-cc', [cc, '--version'], cwd=repo)
run('prerequisite-cc-compile', [cc, '-x', 'c', '-c', '/dev/null', '-o', work / 'compiler-prerequisite.o'], cwd=repo)
runtime_path = sources / 'prerequisite-rust-target-libdir.txt'
run('prerequisite-musl-runtime', [rustc, '--target', target, '--print', 'target-libdir'],
    cwd=repo, capture=runtime_path)
installed_runtime = pathlib.Path(runtime_path.read_text().strip())
if not (installed_runtime / 'self-contained/libc.a').is_file():
    raise RuntimeError('installed Rust musl target self-contained libc.a is required')
e2 = fetch('e2fsprogs-1.47.2.tar.gz',
    'https://cdn.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.2/e2fsprogs-1.47.2.tar.gz',
    16 << 20, '7a959221c1b1cc6e28b7d7a4e204a2ffd8ec6d8a2de4461c482b64c5f4463cca')
e2source = unpack(e2, work / 'e2fsprogs-source', 128 << 20)
patch_path = sources / 'e2fsprogs-1.47.2-directory-times.patch'
shutil.copyfile(repo / 'scripts' / patch_path.name, patch_path)
original_inode = sources / 'e2fsprogs-create_inode.c.original'
patched_inode = sources / 'e2fsprogs-create_inode.c.patched'
shutil.copyfile(e2source / 'misc/create_inode.c', original_inode)
if sha(original_inode) != '695914ed1b9072b21a7d056ccd15d5764cf67b7f637633ed1cab32f417ac1d4f':
    raise RuntimeError('pinned original create_inode.c identity mismatch')
if sha(patch_path) != '019c64a02a9703a7db7f21582b2ae4bd1faa610df4944ec6db8ce43c7c362c45':
    raise RuntimeError('recorded e2fsprogs timestamp patch identity mismatch')
run('e2fsprogs-directory-times-patch',
    ['patch','--batch','--fuzz=0','-p1','-i',patch_path], cwd=e2source)
shutil.copyfile(e2source / 'misc/create_inode.c', patched_inode)
if sha(patched_inode) != 'e213099f707afdceed5adf3b2b4b04b06db05cc914d984d0dd37ad7325e82d39':
    raise RuntimeError('pinned patched create_inode.c identity mismatch')
e2_patch = {'original_sha256':sha(original_inode), 'patched_sha256':sha(patched_inode),
    'patch_sha256':sha(patch_path), 'archive_sha256':sha(e2),
    'archive_checksum_source':'https://cdn.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v1.47.2/sha256sums.asc',
    'authentication':'official HTTPS archive/checksum record and measured SHA256; no PGP verification claim',
    'regenerate_command':'diff -u --label a/misc/create_inode.c --label b/misc/create_inode.c e2fsprogs-create_inode.c.original e2fsprogs-create_inode.c.patched',
    'apply_command':'patch --batch --fuzz=0 -p1 -i ' + patch_path.name,
    'license':'misc/create_inode.c: GNU Library General Public License version 2; original archive and NOTICE retained'}
e2build = work / 'e2fsprogs-build'; e2build.mkdir()
run('e2fsprogs-configure', [e2source / 'configure', '--disable-nls', '--disable-elf-shlibs', '--disable-fuse2fs', '--without-libarchive'],
    cwd=e2build, extra={'CFLAGS':'-O2 ' + remap, 'CC':cc})
run('e2fsprogs-libs', ['make', '-j1', 'libs'], cwd=e2build)
for directory, binary in [('misc','mke2fs'),('debugfs','debugfs'),('e2fsck','e2fsck')]:
    run('e2fsprogs-' + binary, ['make','-j1','-C',directory,binary], cwd=e2build)
    shutil.copyfile(e2build / directory / binary, output / binary)
    os.chmod(output / binary, 0o500)
shutil.copyfile(e2source / 'NOTICE', sources / 'e2fsprogs-NOTICE')
image_proof('installed-tools-two-location', 'microvm_assets::tests::real_ext4_with_installed_tools',
    {'KRONIK_MICROVM_EXT4_TOOLS':str(output)})
collector_path = repo / 'scripts/package-release.py'
collector = runpy.run_path(str(collector_path))
# These host tools use replaceable installed libraries, not bundled host runtime objects.
host_legal = sources / 'host-licenses'; host_legal.mkdir()
host_libraries = {}
ldd = {}
for binary in ['mke2fs','debugfs','e2fsck']:
    ldd[binary] = run('linkage-' + binary, ['ldd',output / binary])
    for line in ldd[binary].splitlines():
        if not line.strip() or line.lstrip().startswith('linux-vdso.'): continue
        match = re.fullmatch(r'\s*(?:(\S+)\s+=>\s+)?(/\S+)\s+\(0x[0-9a-f]+\)\s*',line)
        if not match: raise RuntimeError('unresolved host shared-library dependency: ' + line)
        library = pathlib.Path(match[2]).resolve(strict=True)
        if str(library) in host_libraries: continue
        if not library.is_file(): raise RuntimeError('host dependency is not a regular file')
        ownership = run('library-owner-' + library.name,
            ['dpkg-query','--search','*/' + library.name],cwd=repo)
        providers = set()
        for row in ownership.splitlines():
            provider, separator, owned = row.partition(': ')
            if separator and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?',provider) and pathlib.Path(owned).resolve() == library:
                providers.add(provider)
        if len(providers) != 1: raise RuntimeError('host dependency has no unique installed package provider')
        host_libraries[str(library)] = {'needed_name':match[1] or pathlib.Path(match[2]).name,
            'resolved_path':str(library),'sha256':sha(library),'provider':providers.pop()}
if not host_libraries: raise RuntimeError('host shared-library attribution is empty')
host_packages = {}
host_notices = (
    'Kronik microVM filesystem tools: external host shared libraries\n'
    'mke2fs, debugfs and e2fsck use the user-installed, replaceable, interface-compatible shared libraries recorded in provenance.json.\n'
    'Those host library binaries, static objects and runtime packages are not redistributed in this tool bundle.\n'
    'Only the recorded build/proof host ABI is tested; no universal glibc baseline or self-contained host-tool claim is made.\n'
    'Original package notices are retained conservatively; not every supplied package component is linked.\n')
common_licenses = {'LGPL-2.1'}
for provider in sorted({entry['provider'] for entry in host_libraries.values()}):
    package = run('library-package-' + provider,
        ['dpkg-query','--show','--showformat=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n',provider],cwd=repo)
    original = pathlib.Path('/usr/share/doc') / provider.split(':',1)[0] / 'copyright'
    text = original.read_text()
    if not text.strip(): raise RuntimeError('original host library package notices are empty')
    copied = host_legal / (provider.replace(':','-') + '-copyright')
    shutil.copyfile(original,copied)
    host_packages[provider] = {'installed_record':package,'copyright_input':str(copied.relative_to(sources)),
        'copyright_sha256':sha(copied)}
    host_notices += collector['section'](provider + ': original package copyright',text)
    common_licenses.update(re.findall(r'/usr/share/common-licenses/([A-Za-z0-9.+-]+)',text))
for license_name in sorted(common_licenses):
    original = pathlib.Path('/usr/share/common-licenses') / license_name
    copied = host_legal / license_name
    shutil.copyfile(original,copied)
    host_notices += collector['section']('host libraries: ' + license_name,copied.read_text())
host_notice_path = output / 'HOST_TOOLS_THIRD_PARTY_LICENSES.txt'
host_notice_path.write_text(host_notices)
shutil.copyfile('/etc/os-release',sources / 'host-os-release')
# Reuse Cargo's current locked musl guest-init artifact; this explicit build only updates it if needed.
cargo_target = pathlib.Path(env.get('CARGO_TARGET_DIR', str(repo / 'target')))
if not cargo_target.is_absolute(): cargo_target = repo / cargo_target
rustflags = env.get('RUSTFLAGS','') + ' --remap-path-prefix=' + str(repo) + '=/kronik-source'
run('guest-init', ['cargo','build','--locked','--release','-p','kronik-guest-init','--target',target,'--target-dir',cargo_target],
    cwd=repo, extra={'RUSTFLAGS':rustflags})
guest = cargo_target / target / 'release' / 'kronik-guest-init'
elf = run('guest-init-elf', ['readelf','-l',guest])
if 'INTERP' in elf: raise RuntimeError('guest-init must be a static musl executable')
shutil.copyfile(guest, output / 'guest-init'); os.chmod(output / 'guest-init', 0o500)
fc = fetch('firecracker-v1.17.0-' + arch + '.tgz',
    'https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-' + arch + '.tgz', 64 << 20, fc_sha)
fc_tree = unpack(fc, work / 'firecracker-release', 256 << 20)
fc_name = 'firecracker-v1.17.0-' + arch
fc_binary = fc_tree / fc_name
if not fc_binary.is_file() or fc_binary.is_symlink(): raise RuntimeError('missing fixed Firecracker executable')
shutil.copyfile(fc_binary, output / 'firecracker')
os.chmod(output / 'firecracker', 0o500)
fetch('firecracker-v1.17.0-source.tar.gz',
      'https://github.com/firecracker-microvm/firecracker/archive/' + fc_commit + '.tar.gz', 64 << 20)
config = fetch('firecracker-guest.config',
    'https://raw.githubusercontent.com/firecracker-microvm/firecracker/' + fc_commit + '/resources/guest_configs/microvm-kernel-ci-' + arch + '-6.18.config', 256 << 10)
content = config.read_bytes()
blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
if blob != config_blob: raise RuntimeError('Firecracker kernel config Git blob identity mismatch')
kernel_tools = {}
for name, executable in [('cc',cc),('ld','ld'),('as','as'),('make','make'),('flex','flex'),
        ('bison','bison'),('bc','bc'),('perl','perl'),
        ('pkg-config',env.get('PKG_CONFIG','pkg-config')),('openssl','openssl'),('m4',env.get('M4','m4'))]:
    path = pathlib.Path(shutil.which(executable,path=env['PATH'])).resolve(strict=True)
    kernel_tools[name] = {'resolved_path':str(path),'sha256':sha(path)}
header_libraries = run('kernel-header-libraries',
    [env.get('PKG_CONFIG','pkg-config'),'--modversion','uuid','blkid','libelf','openssl','zlib'],cwd=repo)
# The one change to Firecracker's guest configuration. Its 6.18 configuration turns on
# Amazon Linux's loader of an external FIPS 140 crypto module, which this recipe does not
# build (it builds the kernel image alone, and no modules): at boot the loader cannot link
# the module and panics ("FIPS140 loader: module loading error"), as the first boot on KVM
# showed. The guest has no use for FIPS 140 mode; CRYPTO_FIPS, which the loader selects,
# goes too (its own dependencies are not met without it).
config_overrides = {'CRYPTO_FIPS140_EXTMOD': 'n', 'CRYPTO_FIPS': 'n'}
kernel_inputs = {'recipe':'kronik.microvm-kernel/v2','architecture':arch,
    'config_overrides':config_overrides,
    'kernel_commit':commit,'kernel_version':'6.18.25','firecracker_commit':fc_commit,
    'guest_config_git_blob':config_blob,'source_date_epoch':epoch,'tools':kernel_tools,
    'header_libraries':header_libraries,
    'environment':{key:env[key] for key in ['PATH','CC','CFLAGS','CPPFLAGS','CPATH','LDFLAGS','LIBRARY_PATH','LD_LIBRARY_PATH','PKG_CONFIG','PKG_CONFIG_LIBDIR','PKG_CONFIG_SYSROOT_DIR','BISON_PKGDATADIR','M4'] if key in env}}
archive_name = 'amazon-linux-' + commit + '.tar.gz'
source_url = 'https://github.com/amazonlinux/linux/archive/' + commit + '.tar.gz'
kernel_target = 'vmlinux' if arch == 'x86_64' else 'Image'
kernel_files = ['vmlinux','sources/' + archive_name,'sources/firecracker-guest.config',
    'sources/kernel-resolved.config','sources/kernel-COPYING','sources/kernel-producer.sh',
    'logs/kernel-' + kernel_target + '.log','logs/kernel-olddefconfig.log']
kernel_receipt_path = sources / 'kernel-provenance.json'
kernel_reused_from = None
if a.kernel_from is not None:
    previous = a.kernel_from.absolute()
    md = previous.lstat()
    if not previous.is_dir() or previous.is_symlink() or md.st_uid != os.getuid() or md.st_mode & 0o022:
        raise RuntimeError('kernel input must be a protected owned completed build directory')
    receipt_path = previous / 'sources/kernel-provenance.json'
    md = receipt_path.lstat()
    if not receipt_path.is_file() or receipt_path.is_symlink() or md.st_uid != os.getuid() or md.st_mode & 0o022 or md.st_size > 65536:
        raise RuntimeError('kernel provenance must be a bounded protected owned regular file')
    receipt = json.loads(receipt_path.read_text())
    if receipt.get('schema') != 'kronik.microvm-kernel-provenance/v1' or receipt.get('inputs') != kernel_inputs or set(receipt.get('files',{})) != set(kernel_files):
        raise RuntimeError('reused kernel inputs, toolchain or artifact inventory differ')
    for relative in kernel_files:
        original = previous / relative
        md = original.lstat()
        if not original.is_file() or original.is_symlink() or md.st_uid != os.getuid() or md.st_mode & 0o022 or md.st_size > 512 << 20 or sha(original) != receipt['files'][relative]:
            raise RuntimeError('reused kernel artifact identity/protection mismatch: ' + relative)
        copied = output / relative
        if not copied.exists():
            shutil.copyfile(original,copied)
        if sha(copied) != receipt['files'][relative]:
            raise RuntimeError('reused kernel artifact changed during transfer: ' + relative)
    source_record = receipt['source']
    if source_record['url'] != source_url or source_record['sha256'] != receipt['files']['sources/' + archive_name] or source_record['bytes'] != (sources / archive_name).stat().st_size:
        raise RuntimeError('reused immutable kernel source archive identity differs')
    records[archive_name] = source_record
    shutil.copyfile(receipt_path,kernel_receipt_path)
    kernel_reused_from = {'directory':str(previous),'receipt_sha256':sha(receipt_path)}
    version = kernel_inputs['kernel_version']
else:
    source = fetch(archive_name,source_url,512 << 20)
    kernel = unpack(source, work / 'kernel-source', 3 << 30)
    makefile = (kernel / 'Makefile').read_text()
    version = '.'.join(re.search(r'^' + key + r'\s*=\s*(\d+)\s*$', makefile, re.M)[1]
                       for key in ['VERSION','PATCHLEVEL','SUBLEVEL'])
    if version != '6.18.25': raise RuntimeError('pinned Amazon source does not have kernel version 6.18.25')
    kbuild = work / 'kernel-build'; kbuild.mkdir()
    text = config.read_text()
    for option, value in config_overrides.items():
        line = 'CONFIG_' + option + '=y\n'
        if value != 'n' or text.count(line) != 1:
            raise RuntimeError('the guest configuration does not have CONFIG_' + option + '=y to turn off')
        text = text.replace(line, '# CONFIG_' + option + ' is not set\n')
    (kbuild / '.config').write_text(text)
    kargs = ['make', '-j' + str(a.kernel_jobs), '-C', kernel, 'O=' + str(kbuild), 'ARCH=' + kernel_arch,
             'CC=' + cc, 'KCFLAGS=' + remap, 'HOSTCFLAGS=' + remap]
    run('kernel-olddefconfig', kargs + ['olddefconfig'])
    shutil.copyfile(kbuild / '.config', sources / 'kernel-resolved.config')
    shutil.copyfile(kernel / 'COPYING', sources / 'kernel-COPYING')
# Required guest facilities are built in; no modules, guest NIC, or host mount is needed.
required = ['BLK_DEV_INITRD','DEVTMPFS','EXT4_FS','OVERLAY_FS','TMPFS','VSOCKETS',
            'VIRTIO_VSOCKETS','VIRTIO_BLK','VIRTIO_MMIO','BLOCK','SECCOMP','VMGENID',
            # What guest-init and the workloads need besides: all =y in both pinned guest
            # configurations. DEVPTS_FS and LIBCRC32C are not options of 6.18 and are not listed.
            # CRC32 is =y as well, but it has no prompt: CRYPTO_CRC32C selects it, so it follows
            # from the option that is listed and is left out.
            'PROC_FS','SYSFS','UNIX98_PTYS','NET','INET','UNIX','BINFMT_ELF',
            'CRYPTO_CRC32C','TMPFS_XATTR','EXT4_FS_POSIX_ACL','SERIAL_8250_CONSOLE']
if arch == 'x86_64':
    required.append('ACPI')
resolved_config = (sources / 'kernel-resolved.config').read_text()
for feature in required:
    if '\nCONFIG_' + feature + '=y\n' not in '\n' + resolved_config:
        raise RuntimeError('upstream resolved config lacks built-in CONFIG_' + feature)
# Off is `# CONFIG_X is not set`, or no line at all for an option whose dependencies are
# not met (CRYPTO_FIPS without the loader): Kconfig writes such an option nowhere.
for option in config_overrides:
    if '\nCONFIG_' + option + '=' in '\n' + resolved_config:
        raise RuntimeError('the resolved config did not keep CONFIG_' + option + ' off')
if a.kernel_from is None:
    run('kernel-' + kernel_target, kargs + [kernel_target])
    kernel_binary = kbuild / ('vmlinux' if arch == 'x86_64' else 'arch/arm64/boot/Image')
    shutil.copyfile(kernel_binary, output / 'vmlinux')
    shutil.copyfile(repo / 'scripts/build-microvm-tools.sh', sources / 'kernel-producer.sh')
    receipt = {'schema':'kronik.microvm-kernel-provenance/v1','inputs':kernel_inputs,
        'files':{relative:sha(output / relative) for relative in kernel_files},
        'source':records[archive_name]}
    kernel_receipt_path.write_text(json.dumps(receipt,sort_keys=True,indent=2) + '\n')
# The exact completed kernel, original recipe/logs and immutable source archive remain hash-bound.
metadata_path = sources / 'guest-cargo-metadata.json'
run('guest-cargo-metadata', ['cargo','metadata','--locked','--filter-platform',target,'--format-version','1'],
    cwd=repo, capture=metadata_path)
target_metadata = json.loads(metadata_path.read_text())
# Preserve the exact Rust/build inputs, not a mutable checkout reference.
with tarfile.open(sources / 'kronik-guest-init-source.tar.gz', 'w:gz') as t:
    for name in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','.cargo/config.toml','LICENSE','NOTICE','crates/kronik-guest-init']:
        path = repo / name
        if path.exists(): t.add(path, arcname=name)
shutil.copyfile(pathlib.Path('scripts/build-microvm-tools.sh'), sources / 'build-microvm-tools.sh')
identities = {}
for name,args in [('cc',[cc,'--version']),('ld',['ld','--version']),('as',['as','--version']),
                  ('rustc',[rustc,'-Vv']),('cargo',['cargo','-V']),
                  ('flex',['flex','--version']),('bison',['bison','--version']),
                  ('bc',['bc','--version']),('patch',['patch','--version']),
                  ('pkg-config',['pkg-config','--version']),
                  ('mke2fs',[output / 'mke2fs','-V'])]:
    identities[name] = run('identity-' + name, args, cwd=repo)
    exe = shutil.which(str(args[0]))
    if exe: identities[name + '_sha256'] = sha(exe)
identities['header_libraries'] = header_libraries
# Use the existing release collector with the actual guest root, never a daemon/Zig notice donor.
sysroot_path = sources / 'guest-rust-sysroot.txt'
effective_flags = env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f') if 'CARGO_ENCODED_RUSTFLAGS' in env else rustflags.split()
run('guest-rust-sysroot', [rustc,'--target',target,*effective_flags,'--print','sysroot'],cwd=repo,capture=sysroot_path)
sysroot = pathlib.Path(sysroot_path.read_text().strip())
rust_doc = sysroot / 'share/doc/rust'
runtime_root = sysroot / 'lib/rustlib' / target / 'lib'
runtime_files = sorted(path for path in runtime_root.rglob('*') if path.is_file())
if not runtime_files or not (runtime_root / 'self-contained/libc.a').is_file():
    raise RuntimeError('actual Rust target self-contained musl runtime inputs are required')
channel_path = sysroot / 'lib/rustlib/multirust-channel-manifest.toml'
channel = tomllib.loads(channel_path.read_text())
rust_fields = dict(line.split(': ',1) for line in identities['rustc'].splitlines() if ': ' in line)
rust_commit = rust_fields['commit-hash']
if not re.fullmatch('[0-9a-f]{40}',rust_commit):
    raise RuntimeError('the actual Rust compiler must have a concrete source commit')
for package in ['rustc','rust-src','rust-std']:
    if not channel['pkg'][package]['version'].startswith(rust_fields['release'] + ' (' + rust_commit[:9]):
        raise RuntimeError('Rust compiler/source/target distribution identities disagree')
rust_source = channel['pkg']['rust-src']['target']['*']
rust_target = channel['pkg']['rust-std']['target'][target]
if not rust_source['available'] or not rust_target['available']:
    raise RuntimeError('matching Rust source and musl target distribution records are required')
rust_source_archive = fetch('rust-src-' + rust_fields['release'] + '.tar.xz',
    rust_source['xz_url'],128 << 20,rust_source['xz_hash'])
rust_target_archive = fetch('rust-std-' + rust_fields['release'] + '-' + target + '.tar.xz',
    rust_target['xz_url'],256 << 20,rust_target['xz_hash'])
runtime_hashes = {str(path.relative_to(sysroot)):sha(path) for path in runtime_files}
matched_runtime = set()
with tarfile.open(rust_target_archive) as distribution:
    marker = 'lib/rustlib/' + target + '/lib/'
    for member in distribution:
        _, separator, relative = member.name.partition(marker)
        if not separator or not member.isfile(): continue
        key = marker + relative
        if key not in runtime_hashes:
            raise RuntimeError('installed Rust target is missing a supplied runtime input: ' + key)
        with distribution.extractfile(member) as original:
            if hashlib.file_digest(original,'sha256').hexdigest() != runtime_hashes[key]:
                raise RuntimeError('installed Rust runtime differs from its pinned distribution: ' + key)
        matched_runtime.add(key)
if matched_runtime != set(runtime_hashes):
    raise RuntimeError('installed Rust runtime has inputs outside its pinned target distribution')
# These native records follow the repository's actual pinned compiler recipes, not a Zig donor.
if rust_commit != '58cf8f9c35b355199727627d07ae34a4e2846d67':
    raise RuntimeError('native runtime source attribution must be reviewed for this Rust commit')
native_objects = {
    'musl-1.2.5':['Scrt1.o','crt1.o','crti.o','crtn.o','rcrt1.o','libc.a'],
    'llvm-libunwind':['libunwind.a'],
    'llvm-compiler-rt':['crtbegin.o','crtbeginS.o','crtend.o','crtendS.o'],
}
if {path.name for path in (runtime_root / 'self-contained').iterdir()} != {
        name for names in native_objects.values() for name in names}:
    raise RuntimeError('unresolved native runtime object attribution')
recipe_blobs = {
    '.gitmodules':'9d04fae2375057b34c905bdb022347353fe90766',
    'src/ci/docker/scripts/musl.sh':'370b243dd455104bde0c7acd0aeb3ee14475acce',
    'src/ci/docker/scripts/musl-toolchain.sh':'9e527e269360b0a708191c88de8fa48c913bf705',
    'src/ci/docker/scripts/musl-cve-2026-6042.diff':'9b39420ea3c5103e1bdc43f18438f3b35366e8ce',
    'src/ci/docker/scripts/musl-cve-2026-40200.diff':'88298ca471d38b2c8861f817caf394a591fcdc26',
    'src/bootstrap/src/core/build_steps/llvm.rs':'6b9a6f8530d262f16beee30d0729f4d41c70f9ae',
}
native_recipes = []
for relative, expected_blob in recipe_blobs.items():
    path = fetch('rust-native-' + relative.replace('/','_'),
        'https://raw.githubusercontent.com/rust-lang/rust/' + rust_commit + '/' + relative, 512 << 10)
    data = path.read_bytes()
    if hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != expected_blob:
        raise RuntimeError('Rust native recipe Git blob mismatch: ' + relative)
    native_recipes.append(path)
cross_commit = '3635262e4524c991552789af6f36211a335a77b3'
cross_archive = fetch('rust-musl-cross-make-' + cross_commit + '.tar.gz',
    'https://github.com/richfelker/musl-cross-make/archive/' + cross_commit + '.tar.gz', 16 << 20)
cross_root = unpack(cross_archive, work / 'musl-cross-source', 64 << 20)
musl_archive = fetch('rust-native-musl-1.2.5.tar.gz',
    'https://www.musl-libc.org/releases/musl-1.2.5.tar.gz', 16 << 20)
musl_expected_sha1 = '36210d3423172a40ddcf83c762207c5f760b60a6'
if (cross_root / 'hashes/musl-1.2.5.tar.gz.sha1').read_text().split() != [
        musl_expected_sha1,'musl-1.2.5.tar.gz']:
    raise RuntimeError('pinned cross-toolchain musl source identity differs')
with musl_archive.open('rb') as stream:
    if hashlib.file_digest(stream,'sha1').hexdigest() != musl_expected_sha1:
        raise RuntimeError('native musl source differs from the pinned compiler recipe')
musl_root = unpack(musl_archive, work / 'musl-native-source', 128 << 20)
if not (musl_root / 'COPYRIGHT').is_file() or not (musl_root / 'COPYRIGHT').stat().st_size:
    raise RuntimeError('complete original musl COPYRIGHT is required')
llvm_commit = '1b9c0d5ff9bbe7634aead059efe6b11a7eeba145'
llvm_archive = fetch('rust-native-llvm-' + llvm_commit + '.tar.gz',
    'https://github.com/rust-lang/llvm-project/archive/' + llvm_commit + '.tar.gz', 1 << 30)
llvm_destination = work / 'llvm-native-source'
llvm_destination.mkdir()
llvm_root = llvm_destination / ('llvm-project-' + llvm_commit)
started = time.monotonic()
expanded = selected = 0
with tarfile.open(llvm_archive) as archive:
    for count, member in enumerate(archive,1):
        expanded += member.size
        if count > 500000 or expanded > 16 << 30 or time.monotonic() - started > 600:
            raise RuntimeError('LLVM native source archive bound exceeded')
        parts = pathlib.PurePosixPath(member.name).parts
        if not parts or parts[0] != llvm_root.name or '..' in parts:
            raise RuntimeError('unexpected LLVM archive path')
        # Retain the full archive, but do not unpack unrelated compiler/tests into the build tree.
        if len(parts) > 1 and parts[1] in {'LICENSE.TXT','libunwind','compiler-rt'}:
            selected += member.size
            if selected > 1 << 30:
                raise RuntimeError('LLVM runtime source bound exceeded')
            archive.extract(member,llvm_destination,filter='data')
for relative, expected_blob in [('LICENSE.TXT','fa6ac540007032cbd0ec772a1c72e6cb5527a4fe'),
                                ('libunwind/LICENSE.TXT','1e3120621caeb62648745a42f7a9a25d1e2731ab')]:
    data = (llvm_root / relative).read_bytes()
    if hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != expected_blob:
        raise RuntimeError('original LLVM runtime license Git blob mismatch: ' + relative)
native_sources = {'rust_commit':rust_commit, 'objects':native_objects,
    'musl_version':'1.2.5','musl_sha256':sha(musl_archive),'musl_recipe_sha1':musl_expected_sha1,
    'musl_cross_make_commit':cross_commit,'musl_cross_make_sha256':sha(cross_archive),
    'llvm_commit':llvm_commit,'llvm_archive_sha256':sha(llvm_archive),
    'recipe_git_blobs':recipe_blobs,
    'authentication':'pinned compiler recipe/Git blobs and original source archives; measured SHA256, no signature claim'}
guest_package, guest_dependencies = collector['packages'](target_metadata, root_name='kronik-guest-init')
apache = (rust_doc / 'licenses/Apache-2.0.txt').read_text()
guest_notices = (f"Kronik guest-init third-party notices ({target})\n"
    "Actual target-filtered normal Cargo dependency closure; build/dev edges are excluded.\n"
    "Original Rust distribution notices are retained conservatively; not every supplied component is linked.\n")
guest_notices += collector['dependency_notices'](target_metadata, apache, root_name='kronik-guest-init')
guest_notices += collector['rust_notices'](rust_doc, identities['rustc'],
    copyright_files=('COPYRIGHT-library.html','COPYRIGHT.html'))
native_legal_files = []
for label, source_root in [('musl-1.2.5',musl_root),('llvm-native',llvm_root),('musl-cross-make',cross_root)]:
    legal_files = collector['legal_files'](source_root)
    if not legal_files:
        raise RuntimeError('native source attribution is absent: ' + label)
    for path in legal_files:
        relative = str(path.relative_to(source_root))
        guest_notices += collector['section'](label + ': ' + relative,path.read_text())
        native_legal_files.append((path,'native/' + label + '/' + relative))
    guest_notices += collector['source_notices'](source_root)
notice_path = output / 'GUEST_INIT_THIRD_PARTY_LICENSES.txt'
notice_path.write_text(guest_notices)
guest_legal = {
    'schema':'kronik.guest-init-provenance/v1', 'target':target, 'root_package_id':guest_package['id'],
    'guest_init_sha256':sha(output / 'guest-init'), 'cargo_lock_sha256':sha(repo / 'Cargo.lock'),
    'target_metadata_sha256':sha(metadata_path), 'collector_sha256':sha(collector_path),
    'rustc_version':identities['rustc'], 'rustc_sha256':sha(sysroot / 'bin/rustc'),
    'rust_source_commit':rust_commit, 'distribution_manifest_sha256':sha(channel_path),
    'source_distribution':rust_source, 'target_distribution':rust_target,
    'verified_source_archive':rust_source_archive.name, 'verified_target_archive':rust_target_archive.name,
    'runtime_inputs':runtime_hashes,
    'native_runtime_sources':native_sources,
    'notices_sha256':sha(notice_path),
    'normal_dependencies':[{'id':package['id'],'name':package['name'],'version':package['version'],
        'source':package['source'],'manifest_sha256':sha(pathlib.Path(package['manifest_path']))}
        for package in guest_dependencies],
}
legal_provenance = sources / 'guest-init-legal-provenance.json'
legal_provenance.write_text(json.dumps(guest_legal,sort_keys=True,indent=2) + '\n')
legal_archive = sources / 'guest-init-notices-and-provenance.tar.gz'
with tarfile.open(legal_archive,'w:gz') as archive:
    for path in [metadata_path,legal_provenance,repo / 'Cargo.lock',notice_path]:
        archive.add(path,arcname='provenance/' + path.name)
    archive.add(collector_path,arcname='collector/package-release.py')
    archive.add(repo / 'scripts/licenses',arcname='collector/licenses')
    for name in ['COPYRIGHT-library.html','COPYRIGHT.html','licenses']:
        archive.add(rust_doc / name,arcname='rust/' + name)
    archive.add(channel_path,arcname='rust/multirust-channel-manifest.toml')
    for path in sorted((sysroot / 'lib/rustlib').glob('manifest-*')):
        if path.is_file() and (path.name == 'manifest-rust-std-' + target or path.name.startswith('manifest-rustc')):
            archive.add(path,arcname='rust/component-manifests/' + path.name)
    for path, name in native_legal_files:
        archive.add(path,arcname=name)
    for path in native_recipes:
        archive.add(path,arcname='native/recipes/' + path.name)
    for package in guest_dependencies:
        source_root = pathlib.Path(package['manifest_path']).parent
        identity = hashlib.sha256(package['id'].encode()).hexdigest()
        archive.add(source_root,arcname='dependencies/' + package['name'] + '-' + package['version'] + '-' + identity)
if not guest_legal['normal_dependencies'] or not notice_path.stat().st_size or not legal_archive.stat().st_size:
    raise RuntimeError('guest dependency/runtime attribution closure is empty')
provenance = {'schema':'kronik.microvm-tools-provenance/v1', 'architecture':arch,
    'kernel_commit':commit, 'kernel_version':version, 'firecracker_version':'1.17.0',
    'firecracker_commit':fc_commit,
    'guest_config_git_blob':config_blob, 'source_date_epoch':epoch,
    'sources':records, 'compilers_and_binutils':identities, 'dynamic_linkage':ldd,
    'e2fsprogs_directory_patch':e2_patch,
    'host_runtime':{'libraries':host_libraries,'providers':host_packages,
        'notices_sha256':sha(host_notice_path),'os_release_sha256':sha(sources / 'host-os-release'),
        'contract':'unbundled replaceable shared libraries; only the recorded host ABI is tested'},
    'guest_init_legal':{'notices_sha256':sha(notice_path),'provenance_sha256':sha(legal_provenance),'archive_sha256':sha(legal_archive)},
    'kernel_build':{'receipt_sha256':sha(kernel_receipt_path),'reused_from':kernel_reused_from},
    'build_commands':commands,
    'build_environment':{key:env[key] for key in ['PATH','CC','CFLAGS','CPPFLAGS','CPATH','LDFLAGS','LIBRARY_PATH','LD_LIBRARY_PATH','PKG_CONFIG','PKG_CONFIG_LIBDIR','PKG_CONFIG_SYSROOT_DIR','BISON_PKGDATADIR','M4'] if key in env},
    'inputs':{str(path.relative_to(sources)):sha(path) for path in sorted(sources.rglob('*')) if path.is_file()},
    'offline_tools':{name:sha(output / name) for name in ['mke2fs','debugfs','e2fsck']},
    'reproducibility':'required installed-tools and full-manifest two-location image proofs',
    'kernel_source_authentication':'immutable GitHub commit URL, measured archive SHA256; no signature claim'}
(output / 'provenance.json').write_text(json.dumps(provenance,sort_keys=True,indent=2) + '\n')
manifest = {'schema':'kronik.microvm-tools/v1','firecracker_version':'1.17.0','kernel_version':'6.18.25',
    'firecracker_sha256':sha(output / 'firecracker'),'kernel_sha256':sha(output / 'vmlinux'),
    'guest_init_sha256':sha(output / 'guest-init'),'mke2fs_version':'1.47.2',
    'mke2fs_sha256':sha(output / 'mke2fs'),'provenance_sha256':sha(output / 'provenance.json')}
for path in list(output.iterdir()) + list(sources.rglob('*')) + list(logs.iterdir()):
    if path.is_file():
        with open(path,'rb') as f: os.fsync(f.fileno())
# The loader needs a manifest inside the private candidate; the installation path is still absent.
with open(output / 'manifest.json.new','x') as f:
    json.dump(manifest,f,sort_keys=True,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.rename(output / 'manifest.json.new', output / 'manifest.json')
for directory in [host_legal, sources, logs, output]:
    fd = os.open(directory, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
assert not a.output.absolute().exists(), 'usable installation appeared before the required image proof'
try:
    image_proof('rootfs-two-location',
        'microvm_assets::tests::real_ext4_metadata_and_two_location_reproducibility',
        {'KRONIK_MICROVM_ASSETS':str(output)})
except BaseException:
    assert not a.output.absolute().exists(), 'failed image proof published an installation'
    raise
# Retain build logs and exact sources; only disposable compiler output is removed after success.
shutil.rmtree(work)
for path in logs.iterdir():
    if path.is_file():
        with open(path,'rb') as f: os.fsync(f.fileno())
for directory in [logs, output]:
    fd = os.open(directory, os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
# Publish the complete proved candidate atomically; never replace an existing installation.
libc = ctypes.CDLL(None, use_errno=True)
libc.renameat2.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
libc.renameat2.restype = ctypes.c_int
if libc.renameat2(-100,os.fsencode(output),-100,os.fsencode(destination),1) != 0:
    error = ctypes.get_errno()
    raise OSError(error,os.strerror(error),str(destination))
fd = os.open(parent, os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
print(destination)
PY
