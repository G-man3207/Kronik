"""Release packager boundary checks; full packaging/consumer proof uses real binaries."""

import hashlib
import json
from pathlib import Path
import runpy
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = runpy.run_path(str(ROOT / "scripts/package-release.py"))


class PackagingTest(unittest.TestCase):
    def test_elf_architecture_and_dynamic_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "kronik"
            for target, machine in (("x86_64-unknown-linux-musl", 62),
                                    ("aarch64-unknown-linux-musl", 183)):
                with self.subTest(target=target):
                    header = bytearray(64)
                    header[:6] = b"\x7fELF\x02\x01"
                    struct.pack_into("<H", header, 18, machine)
                    struct.pack_into("<Q", header, 32, 64)
                    struct.pack_into("<HH", header, 54, 56, 1)
                    binary.write_bytes(header + struct.pack("<I", 1) + bytes(52))
                    PACKAGER["check_binary"](binary, target)
                    other = "aarch64-unknown-linux-musl" if machine == 62 else "x86_64-unknown-linux-musl"
                    with self.assertRaises(ValueError):
                        PACKAGER["check_binary"](binary, other)
                    binary.write_bytes(header + struct.pack("<I", 3) + bytes(52))
                    with self.assertRaisesRegex(ValueError, "dynamic"):
                        PACKAGER["check_binary"](binary, target)

    def test_only_normal_dependency_closure_is_distributed(self):
        def node(name, dependencies=()):
            return {"id": name, "deps": [{"pkg": child, "dep_kinds": [{"kind": kind}]}
                                         for child, kind in dependencies]}

        metadata = {
            "workspace_root": str(ROOT),
            "workspace_members": ["kronik"],
            "packages": [{"id": name, "name": name, "version": "1", "source": "registry" if name != "kronik" else None}
                         for name in ("kronik", "normal", "transitive", "dev", "build")],
            "resolve": {"nodes": [node("kronik", [("normal", None), ("dev", "dev"), ("build", "build")]),
                                  node("normal", [("transitive", None)]), node("transitive"),
                                  node("dev"), node("build")]},
        }
        _, dependencies = PACKAGER["packages"](metadata)
        self.assertEqual([p["name"] for p in dependencies], ["normal", "transitive"])

    def test_missing_license_is_not_fabricated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            manifest.write_text("")
            dependency = {"id": "unlicensed", "name": "unlicensed", "version": "1",
                          "source": "registry", "manifest_path": str(manifest),
                          "license_file": None, "license": "MIT", "repository": None, "authors": []}
            metadata = {"packages": [{"id": "kronik", "name": "kronik", "source": None}, dependency],
                        "workspace_root": str(ROOT), "workspace_members": ["kronik"],
                        "resolve": {"nodes": [{"id": "kronik", "deps": [
                            {"pkg": "unlicensed", "dep_kinds": [{"kind": None}]}]},
                            {"id": "unlicensed", "deps": []}]}}
            with self.assertRaisesRegex(ValueError, "missing actual license"):
                PACKAGER["dependency_notices"](metadata, "not a copyright fallback")
            self.assertEqual(list(root.iterdir()), [manifest])
            # Another crate at the same revision/license is not authority to
            # donate its copyright notice to a package missing its own text.
            with tempfile.TemporaryDirectory() as sibling_directory:
                sibling = Path(sibling_directory)
                (sibling / "Cargo.toml").write_text("")
                (sibling / "LICENSE").write_bytes((ROOT / "scripts/licenses/cel-0.15.0-MIT.txt").read_bytes())
                vcs = '{"git":{"sha1":"1111111111111111111111111111111111111111"}}'
                for directory in (root, sibling):
                    (directory / ".cargo_vcs_info.json").write_text(vcs)
                donor = dict(dependency, id="sibling", name="sibling",
                             manifest_path=str(sibling / "Cargo.toml"))
                metadata["packages"].append(donor)
                metadata["resolve"]["nodes"][0]["deps"].append(
                    {"pkg": "sibling", "dep_kinds": [{"kind": None}]})
                metadata["resolve"]["nodes"].append({"id": "sibling", "deps": []})
                with self.assertRaisesRegex(ValueError, "missing actual license"):
                    PACKAGER["dependency_notices"](metadata, "not a copyright fallback")

    def test_local_dependencies_need_explicit_verified_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "vendor/third-party"
            source.mkdir(parents=True)
            dependency = {"id": "third-party", "name": "third-party", "version": "1",
                          "source": None, "manifest_path": str(source / "Cargo.toml"),
                          "license_file": None, "license": "Apache-2.0",
                          "repository": "https://example.invalid/upstream", "authors": []}
            metadata = {"workspace_root": str(workspace), "workspace_members": ["kronik"],
                        "packages": [{"id": "kronik", "name": "kronik", "source": None}, dependency],
                        "resolve": {"nodes": [{"id": "kronik", "deps": [
                            {"pkg": "third-party", "dep_kinds": [{"kind": None}]}]},
                            {"id": "third-party", "deps": []}]}}
            for members in (["kronik"], ["kronik", "third-party"]):
                metadata["workspace_members"] = members
                with self.assertRaisesRegex(ValueError, "unclassified local"):
                    PACKAGER["packages"](metadata)
            (source / "Cargo.toml").write_text('[package]\nname="third-party"\n')
            (source / "LICENSE").write_bytes((ROOT / "proto/opentelemetry/LICENSE").read_bytes())
            (source / "NOTICE").write_text("Downstream attribution index; no upstream NOTICE.\n")
            (source / "src").mkdir()
            (source / "src/lib.rs").write_text("// SPDX-License-Identifier: Apache-2.0\n")
            (source / "patches").mkdir()
            patches = []
            for name in ("first.patch", "second.patch"):
                patch = source / "patches" / name
                patch.write_text(f"fixture delta: {name}\n")
                patches.append({"path": f"patches/{name}",
                                "repository_path": str(patch.relative_to(workspace)),
                                "sha256": hashlib.sha256(patch.read_bytes()).hexdigest()})
            inventory = [{"path": str(p.relative_to(workspace)),
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                         for p in source.rglob("*") if p.is_file()]
            origin = {"schema_version": 1, "name": "third-party",
                      "repository": dependency["repository"], "revision": "1" * 40,
                      "archive": {"url": "https://example.invalid/source.tar.gz", "sha256": "2" * 64},
                      "license": {"spdx": "Apache-2.0", "text": "LICENSE",
                                  "downstream_attribution_index": "NOTICE"},
                      "patches": patches, "maintained_files": inventory}
            path = source / "ORIGIN.json"
            path.write_text(json.dumps(origin))
            # A workspace member under vendor is still third-party.
            _, dependencies = PACKAGER["packages"](metadata)
            self.assertEqual([p["name"] for p in dependencies], ["third-party"])
            text = PACKAGER["dependency_notices"](metadata, "unused")
            self.assertIn("SPDX-License-Identifier: Apache-2.0", text)
            start = text.index("\n{", text.index("Verified third-party ORIGIN.json")) + 1
            embedded, _ = json.JSONDecoder().raw_decode(text[start:])
            self.assertEqual(embedded["patches"], patches)
            self.assertIn("Verified third-party ORIGIN.json", text)
            (source / "untracked-license").write_bytes((source / "LICENSE").read_bytes())
            dependency["license_file"] = "untracked-license"
            with self.assertRaisesRegex(ValueError, "unverified third-party license_file"):
                PACKAGER["dependency_notices"](metadata, "unused")
            dependency["license_file"] = None
            # Build outputs are not source/attribution inputs.
            (source / "target").mkdir()
            (source / "target/unrelated.rs").write_text("// Copyright unrelated build output\n")
            self.assertEqual(PACKAGER["dependency_notices"](metadata, "unused"), text)
            for relative in ("patches/first.patch", "LICENSE", "src/lib.rs"):
                target = source / relative
                original = target.read_bytes()
                target.write_bytes(original + b"changed")
                with self.assertRaises(ValueError):
                    PACKAGER["dependency_notices"](metadata, "unused")
                target.write_bytes(original)
            origin["name"] = "not-this-package"
            path.write_text(json.dumps(origin))
            with self.assertRaisesRegex(ValueError, "invalid third-party origin"):
                PACKAGER["dependency_notices"](metadata, "unused")

    def test_legal_and_source_symlinks_cannot_disclose_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside"
            outside.write_text("private fixture data")
            root = Path(directory) / "crate"
            root.mkdir()
            (root / "LICENSE").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                PACKAGER["legal_files"](root)
            (root / "source.rs").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                PACKAGER["source_notices"](root)
            (root / ".cargo_vcs_info.json").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                PACKAGER["revision"](root)

    def test_missing_native_runtime_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing runtime source"):
                PACKAGER["source_notices"](Path(directory) / "absent")


if __name__ == "__main__":
    unittest.main()
