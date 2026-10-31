#!/usr/bin/env python3
"""Package one built musl binary with its locked sources' real license notices.

Usage: package-release.py TARGET BINARY SBOM METADATA ZIG_DIR OUT_DIR
METADATA is `cargo metadata --locked --filter-platform TARGET --format-version 1`.
The metadata's workspace_root supplies the version's own LICENSE/NOTICE/lockfile.
No build, download, license-text template or copyright guess occurs here.
"""

import argparse
import gzip
import hashlib
import io
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tarfile
import tempfile


LEGAL_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)", re.I)
COMMENTS = re.compile(r"/\*.*?\*/|^(?:[ \t]*(?://|#|;|@)[^\n]*(?:\n|$))+", re.S | re.M)
LEGAL_COMMENT = re.compile(r"copyright|permission.{0,40}granted|redistribution and use|SPDX-License-Identifier", re.I)
SOURCE_SUFFIXES = {".rs", ".proto", ".c", ".h", ".hh", ".hpp", ".cc", ".cpp", ".inc", ".inl", ".S", ".s", ".asm", ".zig"}
SUPPLEMENTS = Path(__file__).resolve().parent / "licenses"


def section(label, text):
    return f"\n{'=' * 78}\n{label}\n{'=' * 78}\n{text.rstrip()}\n"


def legal_files(root, paths=None):
    paths = sorted(p for p in (root.rglob("*") if paths is None else paths) if p.is_file() and
                   any(LEGAL_NAME.match(part) for part in p.relative_to(root).parts))
    for path in paths:
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"license path escapes package: {path}")
    return paths


def source_notices(root, paths=None):
    if not root.is_dir():
        raise ValueError(f"missing runtime source directory: {root}")
    result = []
    for path in sorted(root.rglob("*") if paths is None else paths):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"source path escapes package: {path}")
        text = path.read_text(encoding="utf-8")
        notices = [m.group() for m in COMMENTS.finditer(text) if LEGAL_COMMENT.search(m.group())]
        if notices:
            result.append(section(str(path.relative_to(root)), "\n\n".join(notices)))
    return "".join(result)


def revision(root):
    path = root / ".cargo_vcs_info.json"
    if path.is_file() and not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"revision path escapes package: {path}")
    return json.loads(path.read_text())["git"]["sha1"] if path.is_file() else None


def local_origin(package, workspace):
    root = Path(package["manifest_path"]).parent.resolve()
    path = root / "ORIGIN.json"
    if not root.is_relative_to(workspace) or not path.resolve().is_relative_to(root):
        raise ValueError(f"third-party origin escapes workspace/package: {package['name']}")
    origin = json.loads(path.read_text())
    if (origin["schema_version"] != 1 or origin["name"] != package["name"] or
            origin["repository"] != package["repository"] or
            not origin["repository"].startswith("https://") or
            not re.fullmatch(r"[0-9a-f]{40}", origin["revision"]) or
            not origin["archive"]["url"].startswith("https://") or
            not re.fullmatch(r"[0-9a-f]{64}", origin["archive"]["sha256"]) or
            origin["license"]["spdx"] != package["license"] or not origin["patches"]):
        raise ValueError(f"invalid third-party origin: {package['name']}")
    full_path = (root / origin.get("full_import_manifest", "ORIGIN.json")).resolve()
    if not full_path.is_relative_to(workspace):
        raise ValueError(f"full import manifest escapes workspace: {package['name']}")
    full = json.loads(full_path.read_text())
    if (any(full[key] != origin[key] for key in ("schema_version", "repository", "revision", "archive")) or
            [(p["repository_path"], p["sha256"]) for p in full["patches"]] !=
            [(p["repository_path"], p["sha256"]) for p in origin["patches"]]):
        raise ValueError(f"inconsistent third-party import manifest: {package['name']}")
    for patch in origin["patches"]:
        relative = Path(patch["repository_path"])
        actual = (root / patch["path"]).resolve()
        if (relative.is_absolute() or ".." in relative.parts or
                not actual.is_relative_to(workspace) or actual != (workspace / relative).resolve() or
                hashlib.sha256(actual.read_bytes()).hexdigest() != patch["sha256"]):
            raise ValueError(f"changed/escaping third-party patch: {package['name']}")
    paths = []
    for item in full["maintained_files"]:
        relative = Path(item["path"])
        actual = (workspace / relative).resolve()
        if (relative.is_absolute() or ".." in relative.parts or not actual.is_relative_to(workspace) or
                hashlib.sha256(actual.read_bytes()).hexdigest() != item["sha256"]):
            raise ValueError(f"changed/escaping maintained source: {item['path']}")
        if actual.is_relative_to(root):
            paths.append(actual)
    for name in (origin["license"]["text"], origin["license"]["downstream_attribution_index"], "Cargo.toml"):
        actual = (root / name).resolve()
        if actual not in paths or not actual.is_relative_to(root) or not actual.stat().st_size:
            raise ValueError(f"missing verified third-party license/source: {package['name']}: {name}")
    return origin, paths


def packages(metadata, root_name: str = "kronik"):
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(p for p in metadata["packages"] if p["name"] == root_name)
    seen, todo = set(), [root["id"]]
    while todo:
        ident = todo.pop()
        if ident in seen:
            continue
        seen.add(ident)
        todo.extend(d["pkg"] for d in nodes[ident]["deps"]
                    if any(k["kind"] is None for k in d["dep_kinds"]))
    workspace = Path(metadata["workspace_root"]).resolve()
    members = set(metadata["workspace_members"])
    dependencies = []
    for package in metadata["packages"]:
        if package["id"] not in seen or package["id"] == root["id"]:
            continue
        if package["source"] is None:
            source = Path(package["manifest_path"]).parent.resolve()
            origin = source / "ORIGIN.json"
            if (package["id"] in members and source.is_relative_to(workspace) and
                    not source.is_relative_to(workspace / "vendor") and not origin.exists()):
                continue
            if not source.is_relative_to(workspace) or not origin.is_file():
                raise ValueError(f"unclassified local dependency needs ORIGIN.json: {package['name']}")
        dependencies.append(package)
    return root, sorted(dependencies, key=lambda p: (p["name"], p["version"]))


def dependency_notices(metadata, apache, root_name: str = "kronik"):
    _, dependencies = packages(metadata, root_name)
    workspace = Path(metadata["workspace_root"]).resolve()
    origins = {p["id"]: local_origin(p, workspace) for p in dependencies if p["source"] is None}
    files = {p["id"]: legal_files(Path(p["manifest_path"]).parent,
                                origins[p["id"]][1] if p["id"] in origins else None) for p in dependencies}
    revisions = {p["id"]: revision(Path(p["manifest_path"]).parent) for p in dependencies}
    supplements = json.loads((SUPPLEMENTS / "sources.json").read_text())
    result = []
    for package in dependencies:
        root = Path(package["manifest_path"]).parent
        texts = []
        paths = files[package["id"]]
        explicit = package["license_file"]
        if explicit:
            explicit = root / explicit
            if not explicit.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"license_file escapes package: {package['name']}")
            if package["id"] in origins and explicit.resolve() not in origins[package["id"]][1]:
                raise ValueError(f"unverified third-party license_file: {package['name']}")
            paths = sorted(set(paths) | {explicit})
        origin = "packaged source"
        if not paths:
            # Published Wasmtime workspace crates omit their shared root text.
            # Reuse Wasmtime's actual LICENSE only at the same VCS revision and
            # declared license. Other projects need their own real text.
            donor = next((p for p in dependencies if p["name"] == "wasmtime" and files[p["id"]] and
                          revisions[p["id"]] and revisions[p["id"]] == revisions[package["id"]] and
                          p["license"] == package["license"]), None)
            if donor:
                donor_root = Path(donor["manifest_path"]).parent
                paths = [p for p in files[donor["id"]] if p.parent == donor_root]
                origin = f"same upstream revision via {donor['name']} {donor['version']}"
        for path in paths:
            texts.append(section(f"{origin}: {path.relative_to(root) if path.is_relative_to(root) else path.name}",
                                 path.read_text(encoding="utf-8")))
        if not texts:
            name = f"{package['name']}-{package['version']}-MIT.txt"
            if name in supplements:
                data = (SUPPLEMENTS / name).read_bytes()
                source = supplements[name]
                if hashlib.sha256(data).hexdigest() != source["sha256"]:
                    raise ValueError(f"changed upstream license supplement: {name}")
                texts.append(section(source["url"], data.decode("utf-8")))
            elif package["name"] == "crc32c" and package["version"] == "0.6.8" and package["license"] == "Apache-2.0/MIT":
                # This exact published source has no LICENSE or NOTICE. Elect its
                # declared Apache-2.0 alternative; do not synthesize a MIT holder.
                texts.append(section("Apache-2.0 alternative declared in Cargo.toml", apache))
            else:
                raise ValueError(f"missing actual license text: {package['name']} {package['version']}")
        heading = (f"{package['name']} {package['version']}\n"
                   f"Source: {package['source']}\nRepository: {package['repository']}\n"
                   f"VCS revision: {revisions[package['id']]}\n"
                   f"Declared license: {package['license']}\nAuthors (package metadata): {', '.join(package['authors'])}")
        origin, retained = origins.get(package["id"], (None, None))
        if origin is not None:
            texts.append(section("Verified third-party ORIGIN.json (patch order retained)",
                                 json.dumps(origin, indent=2, sort_keys=True)))
        result.append(section(heading, "".join(texts) + source_notices(root, retained)))
    return "".join(result)


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def rust_notices(rust: Path, rustc_version: str,
                 copyright_files: tuple[str, ...] = ("COPYRIGHT-library.html",)):
    text = ""
    for name in copyright_files:
        library = PlainText()
        library.feed((rust / name).read_text())
        label = rustc_version if name == "COPYRIGHT-library.html" else f"{rustc_version}: {name}"
        text += section(label, "".join(library.parts))
    for path in sorted((rust / "licenses").iterdir()):
        if path.is_file():
            text += section(f"Rust supplied license text: {path.name}", path.read_text())
    return text


def notices(metadata, zig, target):
    root = Path(metadata["workspace_root"])
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    rust = sysroot / "share/doc/rust"
    apache = (rust / "licenses/Apache-2.0.txt").read_text()
    text = (f"Kronik third-party licenses and source attributions ({target})\n"
            f"Cargo.lock SHA-256: {hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest()}\n"
            "The normal dependency closure includes macro-generated code and may include unused portions.\n"
            "Upstream notices are retained conservatively, not a claim every listed source is linked.\n"
            "Rust standard-library notices include its own bundled dependencies.\n"
            "Node/ComponentizeJS/StarlingMonkey, CPython, TinyGo and WASI-Virt runtimes are\n"
            "external actor-build tools/outputs, not runtimes embedded in this host binary.\n")
    text += dependency_notices(metadata, apache)
    text += rust_notices(rust, subprocess.check_output(["rustc", "--version"], text=True).strip())
    for relative in ("LICENSE", "lib/libc/musl/COPYRIGHT", "lib/libunwind/LICENSE.TXT"):
        text += section(f"Zig supplied runtime: {relative}", (zig / relative).read_text())
    for relative in ("lib/libc/musl", "lib/libunwind", "lib/compiler_rt", "lib/include"):
        text += section(f"Zig bundled source notices: {relative}", source_notices(zig / relative))
    sources = json.loads((SUPPLEMENTS / "sources.json").read_text())
    for name, source in sorted(sources.items()):
        if name.endswith("-MIT.txt"):
            continue
        data = (SUPPLEMENTS / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError(f"changed embedded-source license: {name}")
        text += section(f"Embedded Go SDK/WASI interface source: {source['url']}", data.decode("utf-8"))
    text += section("Embedded WASI interface attribution", "WASI 0.2.0: cli, clocks, filesystem, io, random and sockets.\n"
                    "WIT copied from TinyGo 0.43.0 lib/wasi-cli/wit; generated Go bindings use wit-bindgen-go v0.7.0.\n"
                    "These interface specifications are distinct from the external TinyGo runtime.\n")
    otel = root / "proto/opentelemetry/LICENSE"
    if any(p["name"] == "kronik-otel" for p in metadata["packages"]):
        text += section("OpenTelemetry protocol definitions (see NOTICE)", otel.read_text())
    return text.encode("utf-8")


def check_binary(path, target):
    with path.open("rb") as binary:
        header = binary.read(64)
        machine = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}[target]
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != machine:
            raise ValueError(f"not a 64-bit little-endian {target} ELF binary")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size < 4:
            raise ValueError("invalid ELF program header size")
        for index in range(count):
            binary.seek(offset + index * size)
            if struct.unpack("<I", binary.read(4))[0] == 3:
                raise ValueError("release binary has a dynamic ELF interpreter")


def reproducible_sbom(sbom, source):
    # cargo-cyclonedx's opaque graph IDs retain absolute source paths despite SOURCE_DATE_EPOCH.
    prefix = "path+" + source.resolve().as_uri()

    bom = json.loads(sbom.read_text())
    components = list(bom.get("components", []))
    if bom.get("metadata", {}).get("component") is not None:
        components.append(bom["metadata"]["component"])
    references = {}
    for component in components:
        components.extend(component.get("components", []))
        if "bom-ref" not in component:
            continue
        original = component["bom-ref"]
        if not isinstance(original, str) or not original or original in references:
            raise ValueError("invalid or duplicate SBOM component reference")
        replacement = original
        if original == prefix or original.startswith((prefix + "/", prefix + "#")):
            replacement = "path+file:///kronik" + original[len(prefix):]
        references[original] = replacement
    if len(set(references.values())) != len(references):
        raise ValueError("workspace SBOM reference normalization collides with another component")
    for dependency in bom.get("dependencies", []):
        for reference in (dependency["ref"], *dependency.get("dependsOn", [])):
            if reference not in references:
                raise ValueError(f"dangling SBOM dependency reference: {reference}")
        dependency["ref"] = references[dependency["ref"]]
        if "dependsOn" in dependency:
            dependency["dependsOn"] = [references[reference] for reference in dependency["dependsOn"]]
    for component in components:
        if "bom-ref" in component:
            component["bom-ref"] = references[component["bom-ref"]]
    return (json.dumps(bom, sort_keys=True, indent=2) + "\n").encode()

def render_installer(source, version, base_url):
    text = (source / "scripts/install.sh").read_text()
    replacements = {
        "'@VERSION@'": shlex.quote(version),
        "'@BASE_URL@'": shlex.quote(base_url),
        'sh "$(dirname "$0")/install-runsc.sh" # @RUNSC_SETUP@':
            (source / "scripts/install-runsc.sh").read_text().rstrip(),
    }
    for token, value in replacements.items():
        if text.count(token) != 1:
            raise ValueError(f"installer template must contain exactly one {token}")
        text = text.replace(token, value)
    return text



def package(target, binary, sbom, metadata, zig, out):
    check_binary(binary, target)
    root, _ = packages(metadata)
    bom = json.loads(sbom.read_text())
    if bom["bomFormat"] != "CycloneDX" or bom["metadata"]["component"]["name"] != "kronik" or bom["metadata"]["component"]["version"] != root["version"]:
        raise ValueError("SBOM does not describe this Kronik version")
    source = Path(metadata["workspace_root"])
    members = {"kronik": binary, "kronik.cdx.json": sbom,
               "LICENSE": source / "LICENSE", "NOTICE": source / "NOTICE",
               "THIRD_PARTY_LICENSES.txt": notices(metadata, zig, target)}
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"kronik-{target}.tar.gz"
    with tempfile.NamedTemporaryFile(dir=out, delete=False) as temporary:
        tmp = Path(temporary.name)
    try:
        with tmp.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name, value in sorted(members.items()):
                    stream = io.BytesIO(value) if isinstance(value, bytes) else value.open("rb")
                    with stream:
                        info = tarfile.TarInfo(name)
                        info.size = len(value) if isinstance(value, bytes) else value.stat().st_size
                        if not info.size:
                            raise ValueError(f"empty required release member: {name}")
                        info.mode = 0o755 if name == "kronik" else 0o644
                        tar.addfile(info, stream)
        tmp.replace(archive)
    finally:
        tmp.unlink(missing_ok=True)
    archive.chmod(0o644)
    with archive.open("rb") as data:
        digest = hashlib.file_digest(data, "sha256").hexdigest()
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n")
    checksum.chmod(0o644)
    print(f"{digest}  {archive}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"])
    for name in ("binary", "sbom", "metadata", "zig", "out"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    package(args.target, args.binary, args.sbom, json.loads(args.metadata.read_text()), args.zig, args.out)
