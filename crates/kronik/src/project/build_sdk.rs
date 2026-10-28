//! `kronik build` for Python and Go projects (ADR 0030): componentize-py or
//! TinyGo, then the WASI-Virt deny adapter for the filesystem and sockets,
//! the allowlist check, and the input hash that keeps the previous component
//! when nothing changed (componentize-py builds are not reproducible).
//!
//! The tools come from `$KRONIK_SDK_TOOLS/bin` (default
//! `~/.cache/kronik/sdk-tools/bin`), installed by
//! `scripts/install-sdk-tools.sh`, and must be the pinned versions.

use std::path::{Path, PathBuf};
use std::process::Command;

use kronik_runtime::KRONIK_VERSION;

use super::Failure;
use super::build::{
    Built, INPUT_SECTION, append_custom_section, check_imports, custom_section, hash_tree, step,
    summary, tool, write_output,
};

pub const COMPONENTIZE_PY: &str = "0.25.1";
pub const TINYGO: &str = "0.43.0";
pub const GO: &str = "go1.27.2";
/// TinyGo runs `wasm-tools component embed/new` from PATH.
pub const WASM_TOOLS: &str = "1.262.0";
/// The WASI-Virt revision (its `--version` says only 0.2.0).
pub const WASI_VIRT: &str = "bca61c27";

/// What WASI-Virt passes to the host; the filesystem and sockets stay
/// virtual (empty, failing).
const VIRT_FLAGS: [&str; 5] = [
    "--allow-clocks",
    "--allow-random",
    "--allow-stdio",
    "--allow-exit",
    "--allow-env",
];

const INSTALL_HINT: &str = "install the pinned tools: scripts/install-sdk-tools.sh \
     (from a Kronik checkout), or set KRONIK_SDK_TOOLS to where they are";

/// The directory with the pinned tools' binaries.
fn tools_bin() -> PathBuf {
    std::env::var_os("KRONIK_SDK_TOOLS")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kronik/sdk-tools"))
        })
        .unwrap_or_else(|| PathBuf::from(".cache/kronik/sdk-tools"))
        .join("bin")
}

/// A command for the tool `name` from the tools directory, with that
/// directory first on PATH (TinyGo runs `go`).
fn command(bin: &Path, name: &str) -> Result<Command, Failure> {
    let path = bin.join(name);
    if !path.exists() {
        return Err(
            Failure::new(format!("{name} is not installed in {}", bin.display()))
                .hint(INSTALL_HINT),
        );
    }
    let mut c = Command::new(path);
    let mut paths = vec![bin.to_path_buf()];
    if let Some(p) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&p));
    }
    c.env("PATH", std::env::join_paths(paths).unwrap_or_default())
        .env("GOTOOLCHAIN", "local");
    Ok(c)
}

/// The first line of a tool's version output, checked to contain `want`.
fn version(bin: &Path, name: &str, args: &[&str], want: &[&str]) -> Result<String, Failure> {
    let out = tool(command(bin, name)?.args(args))?;
    let text = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    if want.iter().all(|w| text.contains(w)) {
        Ok(text)
    } else {
        Err(Failure::new(format!(
            "{name} is not the pinned version ({}): {text}",
            want.join(", ")
        ))
        .hint(INSTALL_HINT))
    }
}

fn wasi_virt(bin: &Path) -> Result<String, Failure> {
    // The pinned build lives in wasi-virt-<rev>/; the link points there.
    let real = bin.join("wasi-virt").canonicalize().unwrap_or_default();
    if !real
        .to_string_lossy()
        .contains(&format!("wasi-virt-{WASI_VIRT}"))
    {
        return Err(Failure::new(format!(
            "wasi-virt in {} is not the pinned revision {WASI_VIRT}",
            bin.display()
        ))
        .hint(INSTALL_HINT));
    }
    Ok(format!("wasi-virt@{WASI_VIRT}"))
}

/// The variant name of `entry`: its last path element (`./step2`, `step2`).
fn variant(name: &str, entry: &str, default: &str) -> Result<String, Failure> {
    if entry == default {
        return Ok(name.to_owned());
    }
    let stem = entry
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty() && *s != ".")
        .ok_or_else(|| Failure::new(format!("--entry {entry:?} names no module or package")))?;
    Ok(format!("{name}-{stem}"))
}

/// The rest of the pipeline once the tool versions and the inputs are
/// known: keep the previous component if the inputs are unchanged, else
/// compile, virtualize, check and write it.
struct Job<'a> {
    dir: &'a Path,
    bin: &'a Path,
    name: String,
    lang: &'a str,
    versions: Vec<String>,
    flags: String,
    sdk: &'a Path,
}

impl Job<'_> {
    fn run(
        self,
        force: bool,
        compile: impl FnOnce(&Path) -> Result<(), Failure>,
    ) -> Result<Built, Failure> {
        eprintln!(
            "building {} ({}, {})",
            self.name,
            self.lang,
            self.versions.join(", ")
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            format!(
                "kronik build {}\0{KRONIK_VERSION}\0{}\0{}\0{}\0",
                self.lang,
                self.versions.join(","),
                self.flags,
                VIRT_FLAGS.join(","),
            )
            .as_bytes(),
        );
        hash_tree(&mut hasher, self.dir, self.dir)?;
        if !self.sdk.starts_with(self.dir) {
            hash_tree(&mut hasher, self.sdk, self.sdk)?;
        }
        let input = hasher.finalize().to_hex().to_string();
        let out = self.dir.join("dist").join(format!("{}.wasm", self.name));
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
        let work = self.dir.join(".kronik");
        let raw = work.join(format!("{}.raw.wasm", self.name));
        compile(&raw)?;
        let virt = work.join(format!("{}.wasm", self.name));
        step("wasi-virt (deny filesystem and sockets)", || {
            tool(
                command(self.bin, "wasi-virt")?
                    .arg(&raw)
                    .args(VIRT_FLAGS)
                    .arg("-o")
                    .arg(&virt),
            )
            .map(drop)
        })?;
        let mut bytes = std::fs::read(&virt)?;
        check_imports(&bytes)?;
        append_custom_section(&mut bytes, INPUT_SECTION, input.as_bytes());
        write_output(&out, &bytes)?;
        summary(&out, &bytes);
        Ok(Built {
            path: out,
            cached: false,
        })
    }
}

/// A Python project: `pyproject.toml` with `[project] name` and
/// `[tool.kronik] entry` (a module in `src/`, default `actor`) and `sdk`
/// (default `vendor/kronik-sdk`).
pub fn python(dir: &Path, force: bool, entry: Option<&str>) -> Result<Built, Failure> {
    let text = std::fs::read_to_string(dir.join("pyproject.toml"))?;
    let doc: toml::Table = text
        .parse()
        .map_err(|e| Failure::new(format!("pyproject.toml: {e}")))?;
    let name = doc
        .get("project")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Failure::new("pyproject.toml has no [project] name"))?
        .to_owned();
    let kronik = doc.get("tool").and_then(|t| t.get("kronik"));
    let default_entry = kronik
        .and_then(|k| k.get("entry"))
        .and_then(toml::Value::as_str)
        .unwrap_or("actor")
        .to_owned();
    let sdk_rel = kronik
        .and_then(|k| k.get("sdk"))
        .and_then(toml::Value::as_str)
        .unwrap_or("vendor/kronik-sdk");
    let sdk = dir.join(sdk_rel).canonicalize().map_err(|e| {
        Failure::new(format!("the SDK {sdk_rel}: {e}")).hint("set [tool.kronik] sdk")
    })?;
    let entry = entry.unwrap_or(&default_entry).to_owned();
    if !entry.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(Failure::new(format!(
            "--entry {entry:?} is not a Python module name"
        )));
    }
    if !dir.join("src").join(format!("{entry}.py")).is_file() {
        return Err(Failure::new(format!(
            "the entry src/{entry}.py is not a file in {}",
            dir.display()
        ))
        .hint("set [tool.kronik] entry in pyproject.toml, or pass --entry"));
    }
    let name = variant(&name, &entry, &default_entry)?;
    let bin = tools_bin();
    let versions = vec![
        version(&bin, "componentize-py", &["--version"], &[COMPONENTIZE_PY])?,
        wasi_virt(&bin)?,
    ];
    let job = Job {
        dir,
        bin: &bin,
        name,
        lang: "Python",
        versions,
        flags: entry.clone(),
        sdk: &sdk,
    };
    job.run(force, |raw| {
        let work = dir.join(".kronik");
        std::fs::write(
            work.join("kronik_entry.py"),
            format!(
                "# Written by kronik build: the actor's handler export.\n\
                 from {entry} import handler as _handler\n\
                 from kronik._export import export as _export\n\
                 Handler = _export(_handler)\n"
            ),
        )?;
        step("componentize-py componentize", || {
            tool(
                command(&bin, "componentize-py")?
                    .arg("-d")
                    .arg(sdk.join("wit/kronik-actor.wit"))
                    .args(["-w", "actor", "componentize"])
                    .arg("-p")
                    .arg(&work)
                    .arg("-p")
                    .arg(dir.join("src"))
                    .arg("-p")
                    .arg(&sdk)
                    .arg("kronik_entry")
                    .arg("-o")
                    .arg(raw)
                    .current_dir(dir),
            )
            .map(drop)
        })
    })
}

/// A Go project: `go.mod` whose module path's last element is the name and
/// which replaces `kronik.dev/sdk` with the SDK's directory; the entry is a
/// package (default `.`).
pub fn go(dir: &Path, force: bool, entry: Option<&str>) -> Result<Built, Failure> {
    let text = std::fs::read_to_string(dir.join("go.mod"))?;
    let (module, sdk_rel) = parse_go_mod(&text);
    let name = module
        .as_deref()
        .and_then(|m| m.rsplit('/').next())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Failure::new("go.mod has no module line"))?
        .to_owned();
    let sdk_rel = sdk_rel.ok_or_else(|| {
        Failure::new("go.mod does not replace kronik.dev/sdk with the SDK's directory")
            .hint("add: replace kronik.dev/sdk => ./kronik-sdk")
    })?;
    let sdk = dir
        .join(&sdk_rel)
        .canonicalize()
        .map_err(|e| Failure::new(format!("the SDK {sdk_rel}: {e}")))?;
    let entry = entry.unwrap_or(".").to_owned();
    if !dir.join(&entry).is_dir() {
        return Err(Failure::new(format!(
            "the entry {entry} is not a package directory in {}",
            dir.display()
        ))
        .hint("pass --entry ./<package>"));
    }
    let name = variant(&name, &entry, ".")?;
    let bin = tools_bin();
    let versions = vec![
        version(&bin, "tinygo", &["version"], &[TINYGO, GO])?,
        version(&bin, "wasm-tools", &["--version"], &[WASM_TOOLS])?,
        wasi_virt(&bin)?,
    ];
    let job = Job {
        dir,
        bin: &bin,
        name,
        lang: "Go",
        versions,
        flags: format!("{entry}\0-target=wasip2\0actor-go"),
        sdk: &sdk,
    };
    job.run(force, |raw| {
        step("tinygo build -target=wasip2", || {
            tool(
                command(&bin, "tinygo")?
                    .args(["build", "-target=wasip2", "--wit-package"])
                    .arg(sdk.join("wit"))
                    .args(["--wit-world", "actor-go", "-o"])
                    .arg(raw)
                    .arg(&entry)
                    .current_dir(dir),
            )
            .map(drop)
        })
    })
}

/// The module path and the replacement directory of `kronik.dev/sdk`.
fn parse_go_mod(text: &str) -> (Option<String>, Option<String>) {
    let mut module = None;
    let mut sdk = None;
    let mut in_replace = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        if let Some(m) = line.strip_prefix("module ") {
            module = Some(m.trim().trim_matches('"').to_owned());
        } else if line == "replace (" {
            in_replace = true;
        } else if in_replace && line == ")" {
            in_replace = false;
        } else {
            let spec = if in_replace {
                Some(line)
            } else {
                line.strip_prefix("replace ")
            };
            if let Some((from, to)) = spec.and_then(|s| s.split_once("=>"))
                && from.split_whitespace().next() == Some("kronik.dev/sdk")
            {
                sdk = to.split_whitespace().next().map(str::to_owned);
            }
        }
    }
    (module, sdk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_mod_names_the_module_and_the_sdk() {
        let (m, s) = parse_go_mod(
            "module counter-go\n\ngo 1.27\n\nrequire kronik.dev/sdk v0.0.0\n\n\
             replace kronik.dev/sdk => ../../sdk/go // the SDK\n",
        );
        assert_eq!(m.as_deref(), Some("counter-go"));
        assert_eq!(s.as_deref(), Some("../../sdk/go"));
        let (m, s) = parse_go_mod(
            "module example.com/a/notes\nreplace (\n\tgolang.org/x/y => ./y\n\tkronik.dev/sdk v0.0.0 => ./vendor/kronik-sdk\n)\n",
        );
        assert_eq!(m.as_deref(), Some("example.com/a/notes"));
        assert_eq!(s.as_deref(), Some("./vendor/kronik-sdk"));
        assert_eq!(parse_go_mod("go 1.27\n"), (None, None));
    }

    #[test]
    fn variants_are_named_after_the_entry() {
        assert_eq!(
            variant("counter-py", "actor", "actor").unwrap(),
            "counter-py"
        );
        assert_eq!(
            variant("counter-py", "step2", "actor").unwrap(),
            "counter-py-step2"
        );
        assert_eq!(
            variant("counter-go", "./step2", ".").unwrap(),
            "counter-go-step2"
        );
        assert_eq!(variant("counter-go", ".", ".").unwrap(), "counter-go");
        assert!(variant("counter-go", "./", ".").is_err());
    }
}
