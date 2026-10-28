//! `kronik build`: a TypeScript, Rust, Python or Go project to
//! `dist/<name>.wasm` (Python and Go: `build_sdk.rs`, ADR 0030).
//!
//! TypeScript (ADR 0002): `tsc --noEmit`, then `jco componentize` with
//! `--disable http fetch-event stdio` on an entry that exports the module's
//! default export as `handler`. ComponentizeJS builds are not reproducible,
//! so the hash of every input goes into a custom section of the component,
//! and a build whose inputs are unchanged keeps the previous component.
//!
//! Rust: `cargo build --release --target wasm32-wasip2`, with the project
//! and Cargo home paths remapped so the component's hash does not depend on
//! where the sources are.
//!
//! Both check the component's imports against the deploy allowlist, as
//! `kronik deploy` does (`IMPORT_NOT_ALLOWED`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use kronik_core::error::ErrorCode;
use kronik_runtime::KRONIK_VERSION;
use kronik_runtime::allowlist;
use schemars::JsonSchema;
use serde::Serialize;

use super::Failure;

/// The custom section that records the build's input hash.
pub(super) const INPUT_SECTION: &str = "kronik-build-input";

/// ComponentizeJS features Kronik's allowlist needs off (ADR 0002).
const DISABLED_FEATURES: [&str; 3] = ["http", "fetch-event", "stdio"];

/// Directories whose contents are not build inputs.
const SKIPPED_DIRS: [&str; 6] = [
    "node_modules",
    "dist",
    ".kronik",
    ".git",
    "target",
    "__pycache__",
];

/// The oldest Node.js that runs the pinned TypeScript toolchain: every
/// package's `engines` admits it (the strictest, `@napi-rs/lzma`, asks for
/// `^22.20 || ^24.12 || >=25`). docs/guides/install.md gives the same.
const MIN_NODE: (u32, u32) = (22, 20);

impl From<serde_json::Error> for Failure {
    fn from(e: serde_json::Error) -> Self {
        Failure::new(e.to_string())
    }
}

/// A built component.
pub struct Built {
    pub path: PathBuf,
    /// The inputs were unchanged, so the previous component was kept.
    pub cached: bool,
}

/// What `kronik build --json` prints.
#[derive(Debug, Serialize, JsonSchema)]
pub struct BuildOutput {
    /// The component, relative to the current directory when it is inside
    /// it.
    pub wasm: String,
    /// `b3:` and 12 hex characters of the component's BLAKE3 hash, as
    /// `kronik deploy` and `kronik deployments list` show it.
    pub code_hash: String,
    pub bytes: u64,
    /// The inputs were unchanged since the last build, so the previous
    /// component was kept.
    pub cached: bool,
    /// The interfaces the component imports, all within the allowlist.
    pub imports: Vec<String>,
}

/// The `--json` output for a built component.
pub fn output(built: &Built) -> Result<BuildOutput, Failure> {
    let bytes = std::fs::read(&built.path)?;
    let imports = allowlist::component_imports(&bytes)
        .map_err(|e| Failure::new(format!("not a component: {e}")))?;
    let cwd = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .unwrap_or_default();
    Ok(BuildOutput {
        wasm: built
            .path
            .strip_prefix(&cwd)
            .unwrap_or(&built.path)
            .display()
            .to_string(),
        code_hash: kronik_core::ids::CodeHash::of(&bytes).short(),
        bytes: bytes.len() as u64,
        cached: built.cached,
        imports,
    })
}

/// Builds the project in `dir` and returns the path of its component; see
/// [`component`].
pub fn run(dir: &Path, force: bool, entry: Option<&str>) -> Result<PathBuf, Failure> {
    component(dir, force, entry).map(|b| b.path)
}

/// Builds the project in `dir`. One build runs at a time per project (tests
/// may start several at once). Progress goes to stderr: `kronik test-host`
/// answers on stdout. `entry` builds another TypeScript entry than
/// package.json's, as a variant.
pub fn component(dir: &Path, force: bool, entry: Option<&str>) -> Result<Built, Failure> {
    let dir = dir
        .canonicalize()
        .map_err(|e| Failure::new(format!("{}: {e}", dir.display())))?;
    let is_rust = dir.join("Cargo.toml").is_file();
    let is_python = dir.join("pyproject.toml").is_file();
    let is_go = dir.join("go.mod").is_file();
    if !is_rust && !is_python && !is_go && !dir.join("package.json").is_file() {
        return Err(Failure::new(format!(
            "{} has no Cargo.toml, package.json, pyproject.toml or go.mod",
            dir.display()
        ))
        .hint("create a project with: kronik init --lang ts|rust|python|go <name>"));
    }
    let work = dir.join(".kronik");
    std::fs::create_dir_all(&work)?;
    let lock = std::fs::File::create(work.join("build.lock"))?;
    lock.lock()?;
    if is_rust {
        if let Some(entry) = entry {
            return Err(Failure::new(format!(
                "--entry {entry} is for TypeScript, Python and Go projects"
            ))
            .hint("build Rust variants with Cargo features"));
        }
        rust(&dir).map(|path| Built {
            path,
            cached: false,
        })
    } else if is_python {
        super::build_sdk::python(&dir, force, entry)
    } else if is_go {
        super::build_sdk::go(&dir, force, entry)
    } else {
        typescript(&dir, force, entry)
    }
}

fn typescript(dir: &Path, force: bool, entry: Option<&str>) -> Result<Built, Failure> {
    let package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("package.json"))?)?;
    let package_name = package["name"]
        .as_str()
        .map(|n| n.rsplit('/').next().unwrap_or(n).to_string())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Failure::new("package.json has no name"))?;
    let default_entry = package["kronik"]["entry"]
        .as_str()
        .unwrap_or("src/actor.ts");
    // Another entry is a variant, named after its file: `--entry src/step2.ts`
    // builds dist/<name>-step2.wasm.
    let (entry, name) = match entry {
        Some(e) if e != default_entry => {
            let stem = Path::new(e)
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Failure::new(format!("--entry {e:?} names no file")))?;
            (e.to_string(), format!("{package_name}-{stem}"))
        }
        _ => (default_entry.to_string(), package_name),
    };
    if !dir.join(&entry).is_file() {
        return Err(Failure::new(format!(
            "the entry {entry} is not a file in {}",
            dir.display()
        ))
        .hint("set package.json's kronik.entry, or pass --entry"));
    }
    let modules = find_up(dir, "node_modules/.bin/jco")
        .map(|bin| {
            bin.parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .unwrap_or_default()
        })
        .ok_or_else(|| {
            Failure::new("the TypeScript toolchain is not installed (no node_modules/.bin/jco)")
                .hint(format!("run: (cd {} && npm install)", dir.display()))
        })?;
    let sdk = find_up(dir, "node_modules/@kronik/sdk")
        .and_then(|p| p.canonicalize().ok())
        .ok_or_else(|| {
            Failure::new("@kronik/sdk is not installed")
                .hint(format!("run: (cd {} && npm install)", dir.display()))
        })?;
    let wit = sdk.join("wit/kronik-actor.wit");
    let mut versions = Vec::new();
    for package in [
        "@bytecodealliance/jco",
        "@bytecodealliance/componentize-js",
        "typescript",
    ] {
        let json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(modules.join(package).join("package.json"))
                .map_err(|e| Failure::new(format!("{package} is not installed: {e}")))?,
        )?;
        versions.push(format!(
            "{package}@{}",
            json["version"].as_str().unwrap_or("?")
        ));
    }
    eprintln!("building {name} (TypeScript, {})", versions.join(", "));

    // Everything the component is made from: the project, the SDK if it
    // lives outside it, the toolchain versions and the flags.
    let mut hasher = blake3::Hasher::new();
    hasher.update(
        format!(
            "kronik build ts\0{KRONIK_VERSION}\0{}\0{}\0{entry}\0",
            versions.join(","),
            DISABLED_FEATURES.join(",")
        )
        .as_bytes(),
    );
    hash_tree(&mut hasher, dir, dir)?;
    if !sdk.starts_with(dir) {
        hash_tree(&mut hasher, &sdk, &sdk)?;
    }
    let input = hasher.finalize().to_hex().to_string();

    let out = dir.join("dist").join(format!("{name}.wasm"));
    if !force
        && let Ok(previous) = std::fs::read(&out)
        && custom_section(&previous, INPUT_SECTION).as_deref() == Some(input.as_bytes())
    {
        eprintln!(
            "  inputs unchanged since the last build (input b3:{}), kept the component",
            &input[..12]
        );
        check_imports(&previous)?;
        summary(&out, &previous);
        return Ok(Built {
            path: out,
            cached: true,
        });
    }

    check_node()?;
    step("tsc --noEmit", || {
        tool(
            Command::new(modules.join(".bin/tsc"))
                .args(["--noEmit", "-p", "tsconfig.json"])
                .current_dir(dir),
        )
        .map(drop)
    })?;
    let work = dir.join(".kronik");
    std::fs::write(
        work.join("entry.ts"),
        format!(
            "// Written by kronik build: the actor's handler export.\nexport {{ default as handler }} from '../{entry}';\n"
        ),
    )?;
    let built = work.join(format!("{name}.wasm"));
    step("jco componentize", || {
        tool(
            Command::new(modules.join(".bin/jco"))
                .arg("componentize")
                .arg(work.join("entry.ts"))
                .arg("--wit")
                .arg(&wit)
                .args(["--world-name", "actor", "--disable"])
                .args(DISABLED_FEATURES)
                .arg("-o")
                .arg(&built)
                .current_dir(dir),
        )
        .map(drop)
    })?;
    let mut bytes = std::fs::read(&built)?;
    check_imports(&bytes)?;
    append_custom_section(&mut bytes, INPUT_SECTION, input.as_bytes());
    write_output(&out, &bytes)?;
    summary(&out, &bytes);
    Ok(Built {
        path: out,
        cached: false,
    })
}

/// Node.js is on PATH and at least [`MIN_NODE`]. tsc and jco need it, and
/// an older one fails later with errors that blame npm.
fn check_node() -> Result<(), Failure> {
    let (major, minor) = MIN_NODE;
    let hint = format!(
        "install Node.js {major}.{minor} or later, from https://nodejs.org/en/download \
         or NodeSource's packages; Ubuntu 24.04's own nodejs is 18"
    );
    let out = Command::new("node")
        .arg("--version")
        .output()
        .map_err(|e| Failure::new(format!("Node.js is not installed: node: {e}")).hint(&hint))?;
    let version = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    match node_version(&version) {
        Some(v) if v >= MIN_NODE => Ok(()),
        _ => Err(Failure::new(format!(
            "Node.js {version} is too old for the TypeScript toolchain, which needs \
             {major}.{minor} or later"
        ))
        .hint(hint)),
    }
}

/// `(major, minor)` of `node --version`, such as `v22.20.0`.
fn node_version(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.strip_prefix('v')?.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn rust(dir: &Path) -> Result<PathBuf, Failure> {
    let manifest = dir.join("Cargo.toml");
    let metadata = tool(
        Command::new("cargo")
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--manifest-path",
            ])
            .arg(&manifest),
    )?;
    let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|p| p["manifest_path"].as_str().map(Path::new) == Some(manifest.as_path()))
        })
        .ok_or_else(|| Failure::new(format!("{} defines no package", manifest.display())))?;
    let name = package["name"].as_str().unwrap_or_default().to_string();
    let lib = package["targets"]
        .as_array()
        .and_then(|targets| {
            targets.iter().find(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|k| k == "cdylib"))
            })
        })
        .and_then(|t| t["name"].as_str())
        .map(|n| n.replace('-', "_"))
        .ok_or_else(|| {
            Failure::new(format!("{name} has no cdylib library"))
                .hint("add to Cargo.toml: [lib] crate-type = [\"cdylib\"]")
        })?;
    let target_dir = PathBuf::from(metadata["target_directory"].as_str().unwrap_or("target"));
    eprintln!("building {name} (Rust, wasm32-wasip2)");

    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .and_then(|p| p.canonicalize().ok());
    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    rustflags.push_str(&format!(" --remap-path-prefix={}=/project", dir.display()));
    if let Some(home) = cargo_home {
        rustflags.push_str(&format!(" --remap-path-prefix={}=/cargo", home.display()));
    }
    let mut cargo = Command::new("cargo");
    cargo
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .env("RUSTFLAGS", rustflags.trim_start())
        .stdout(Stdio::from(std::io::stderr()))
        .current_dir(dir);
    if dir.join("Cargo.lock").exists() {
        cargo.arg("--locked");
    }
    step("cargo build --release --target wasm32-wasip2", || {
        let status = cargo.status().map_err(|e| {
            Failure::new(format!("cargo: {e}")).hint("install Rust: https://rustup.rs")
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(Failure::new("cargo build failed"))
        }
    })?;
    let built = target_dir
        .join("wasm32-wasip2/release")
        .join(format!("{lib}.wasm"));
    let bytes =
        std::fs::read(&built).map_err(|e| Failure::new(format!("{}: {e}", built.display())))?;
    check_imports(&bytes)?;
    let out = dir.join("dist").join(format!("{name}.wasm"));
    write_output(&out, &bytes)?;
    summary(&out, &bytes);
    Ok(out)
}

/// Runs a step and prints how long it took.
// `kronik build` is a CLI command, not daemon code: its wall-clock step
// timings are only printed.
#[allow(clippy::disallowed_methods)]
pub(super) fn step(what: &str, f: impl FnOnce() -> Result<(), Failure>) -> Result<(), Failure> {
    let start = Instant::now();
    f()?;
    eprintln!("  {what:<45} {:>6.1} s", start.elapsed().as_secs_f64());
    Ok(())
}

/// Runs a tool and captures its output; on failure the output is printed.
pub(super) fn tool(command: &mut Command) -> Result<Output, Failure> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Failure::new(format!("{program}: {e}")))?;
    if output.status.success() {
        return Ok(output);
    }
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    Err(Failure::new(format!(
        "{} failed ({})",
        Path::new(&program)
            .file_name()
            .map_or(program.clone(), |f| f.to_string_lossy().into_owned()),
        output.status
    )))
}

/// The deploy-time import check (ADR 0001 §8).
pub(super) fn check_imports(bytes: &[u8]) -> Result<(), Failure> {
    let imports = allowlist::component_imports(bytes)
        .map_err(|e| Failure::new(format!("not a component: {e}")))?;
    let denied = allowlist::disallowed_imports(bytes)
        .map_err(|e| Failure::new(format!("not a component: {e}")))?;
    if !denied.is_empty() {
        return Err(Failure::new(format!(
            "{}: the component imports interfaces outside the allowlist: {}",
            ErrorCode::ImportNotAllowed.as_str(),
            denied.join(", ")
        ))
        .code(ErrorCode::ImportNotAllowed)
        .hint("remove the code that uses them (std::fs, std::net, fetch, ...)")
        .docs(ErrorCode::ImportNotAllowed.docs()));
    }
    eprintln!("  imports: {}, all within the allowlist", imports.len());
    Ok(())
}

pub(super) fn summary(out: &Path, bytes: &[u8]) {
    let hash = blake3::hash(bytes).to_hex();
    // Relative to the current directory when the component is inside it.
    let cwd = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .unwrap_or_default();
    let shown = out.strip_prefix(&cwd).unwrap_or(out);
    eprintln!(
        "{}  b3:{}  {} bytes",
        shown.display(),
        &hash[..12],
        bytes.len()
    );
}

pub(super) fn write_output(out: &Path, bytes: &[u8]) -> Result<(), Failure> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = out.with_extension("wasm.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, out)?;
    Ok(())
}

/// The nearest `path` in `dir` or one of its parents.
fn find_up(dir: &Path, path: &str) -> Option<PathBuf> {
    dir.ancestors().map(|d| d.join(path)).find(|p| p.exists())
}

/// Hashes every file under `dir` (sorted, by path relative to `root`),
/// skipping dependencies and build output.
pub(super) fn hash_tree(
    hasher: &mut blake3::Hasher,
    root: &Path,
    dir: &Path,
) -> Result<(), Failure> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if SKIPPED_DIRS.iter().any(|skip| name == *skip) {
            continue;
        }
        if path.is_dir() {
            hash_tree(hasher, root, &path)?;
        } else if path.is_file() {
            let contents = std::fs::read(&path)?;
            let rel = path.strip_prefix(root).unwrap_or(&path);
            hasher.update(rel.to_string_lossy().as_bytes());
            hasher.update(&(contents.len() as u64).to_le_bytes());
            hasher.update(&contents);
        }
    }
    Ok(())
}

fn leb128(mut n: usize, out: &mut Vec<u8>) {
    loop {
        // Seven bits per byte, the high bit set on all but the last.
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_leb128(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    let mut n = 0usize;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        n |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(n);
        }
    }
    None
}

/// Appends a custom section (id 0) to a component or module.
pub(super) fn append_custom_section(bytes: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let mut body = Vec::new();
    leb128(name.len(), &mut body);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(payload);
    bytes.push(0);
    leb128(body.len(), bytes);
    bytes.extend_from_slice(&body);
}

/// The payload of the top-level custom section `name`, if there is one.
pub(super) fn custom_section(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut pos = 8; // magic and version
    while pos < bytes.len() {
        let id = bytes[pos];
        pos += 1;
        let size = read_leb128(bytes, &mut pos)?;
        let end = pos.checked_add(size).filter(|&e| e <= bytes.len())?;
        if id == 0 {
            let mut p = pos;
            let len = read_leb128(bytes, &mut p)?;
            let section_name = bytes.get(p..p.checked_add(len)?)?;
            if section_name == name.as_bytes() {
                return Some(bytes[p + len..end].to_vec());
            }
        }
        pos = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_sections_round_trip() {
        // An empty component: magic, version 0x0d, layer 1.
        let mut bytes = b"\0asm\x0d\x00\x01\x00".to_vec();
        assert_eq!(custom_section(&bytes, INPUT_SECTION), None);
        append_custom_section(&mut bytes, "other", b"x");
        append_custom_section(&mut bytes, INPUT_SECTION, &[b'a'; 200]);
        assert_eq!(custom_section(&bytes, INPUT_SECTION), Some(vec![b'a'; 200]));
        assert_eq!(custom_section(&bytes, "other"), Some(b"x".to_vec()));
        assert_eq!(
            custom_section(&bytes[..bytes.len() - 1], INPUT_SECTION),
            None
        );
    }

    #[test]
    fn reads_node_versions() {
        assert_eq!(node_version("v22.20.0"), Some((22, 20)));
        assert_eq!(node_version("v18.19.1"), Some((18, 19)));
        assert!(node_version("v18.19.1").unwrap() < MIN_NODE);
        assert!(node_version("v24.12.0").unwrap() >= MIN_NODE);
        assert_eq!(node_version("22.20.0"), None);
        assert_eq!(node_version(""), None);
    }
}
