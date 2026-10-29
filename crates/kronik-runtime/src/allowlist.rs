//! Deploy-time import allowlist (`IMPORT_NOT_ALLOWED`).
//!
//! A component may import Kronik's own interfaces plus a deterministic WASI
//! subset: `wasi:clocks` (logical time), `wasi:random` (turn seed), `wasi:cli`
//! (stdout/stderr become log events, empty environment, no args), outgoing
//! `wasi:http` (`types` and `outgoing-handler`, the `http.fetch` effect, M22)
//! and the `wasi:io` streams those need. Everything else (`wasi:filesystem`,
//! `wasi:sockets`, `wasi:http/incoming-handler`, WASI 0.3, unknown packages,
//! bare function imports, unversioned names) is rejected.
//!
//! The check works on the component bytes alone, before compilation, by
//! reading the top-level import section of the outer component. Imports of
//! nested core modules/components are satisfied inside the component and are
//! not host imports.

use wasmparser::{Encoding, Parser, Payload};

/// Kronik interfaces and the package version range they are accepted at.
const KRONIK_INTERFACES: &[&str] = &[
    "types",
    "state",
    "sql",
    "context",
    "messaging",
    "timers",
    "http-client",
    "crypto",
    "secrets",
    "log",
    "privacy",
];

/// Allowed WASI 0.2 interfaces, per package.
const WASI_INTERFACES: &[(&str, &[&str])] = &[
    ("io", &["error", "poll", "streams"]),
    ("clocks", &["wall-clock", "monotonic-clock"]),
    ("random", &["random", "insecure", "insecure-seed"]),
    (
        "cli",
        &[
            "environment",
            "exit",
            "stdin",
            "stdout",
            "stderr",
            "terminal-input",
            "terminal-output",
            "terminal-stdin",
            "terminal-stdout",
            "terminal-stderr",
        ],
    ),
    ("http", &["types", "outgoing-handler"]),
];

#[derive(Debug)]
pub enum CheckError {
    NotAComponent,
    Parse(wasmparser::BinaryReaderError),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::NotAComponent => write!(f, "input is a core module, not a component"),
            CheckError::Parse(e) => write!(f, "invalid component: {e}"),
        }
    }
}

impl std::error::Error for CheckError {}

/// Returns all top-level import names of a component, in binary order.
pub fn component_imports(bytes: &[u8]) -> Result<Vec<String>, CheckError> {
    let mut depth = 0usize;
    let mut imports = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(CheckError::Parse)? {
            Payload::Version { encoding, .. } => {
                if depth == 0 && encoding != Encoding::Component {
                    return Err(CheckError::NotAComponent);
                }
                depth += 1;
            }
            Payload::End(_) => depth = depth.saturating_sub(1),
            Payload::ComponentImportSection(reader) if depth == 1 => {
                for import in reader {
                    let import = import.map_err(CheckError::Parse)?;
                    imports.push(import.name.full_name().into_owned());
                }
            }
            _ => {}
        }
    }
    Ok(imports)
}

/// Returns the imports that are not allowed, in binary order. An empty vector
/// means the component passes the check.
pub fn disallowed_imports(bytes: &[u8]) -> Result<Vec<String>, CheckError> {
    Ok(component_imports(bytes)?
        .into_iter()
        .filter(|name| !is_allowed(name))
        .collect())
}

pub fn is_allowed(name: &str) -> bool {
    let Some((path, version)) = name.split_once('@') else {
        return false;
    };
    let Some((package, interface)) = path.split_once('/') else {
        return false;
    };
    let Some((namespace, package)) = package.split_once(':') else {
        return false;
    };
    match namespace {
        "kronik" => {
            package == "actor"
                && version_in(version, 0, 1)
                && KRONIK_INTERFACES.contains(&interface)
        }
        "wasi" => {
            version_in(version, 0, 2)
                && WASI_INTERFACES
                    .iter()
                    .any(|(p, ifaces)| *p == package && ifaces.contains(&interface))
        }
        _ => false,
    }
}

/// `true` when `version` is `<major>.<minor>.<patch>` (optionally with a
/// pre-release/build suffix) with the given major and minor.
fn version_in(version: &str, major: u64, minor: u64) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or("");
    let mut parts = core.split('.');
    let (Some(ma), Some(mi), Some(pa), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    ma.parse::<u64>() == Ok(major) && mi.parse::<u64>() == Ok(minor) && pa.parse::<u64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::is_allowed;

    #[test]
    fn allows_kronik_and_deterministic_wasi() {
        assert!(is_allowed("kronik:actor/state@0.1.0"));
        assert!(is_allowed("wasi:io/streams@0.2.12"));
        assert!(is_allowed("wasi:clocks/wall-clock@0.2.0"));
        assert!(is_allowed("wasi:random/insecure-seed@0.2.3"));
        assert!(is_allowed("wasi:cli/terminal-stderr@0.2.12"));
        // ComponentizeJS 0.23's `fetch` (M22).
        assert!(is_allowed("wasi:http/types@0.2.10"));
        assert!(is_allowed("wasi:http/outgoing-handler@0.2.10"));
    }

    #[test]
    fn rejects_everything_else() {
        assert!(!is_allowed("wasi:filesystem/types@0.2.12"));
        assert!(!is_allowed("wasi:filesystem/preopens@0.2.12"));
        assert!(!is_allowed("wasi:sockets/tcp@0.2.12"));
        assert!(!is_allowed("wasi:http/incoming-handler@0.2.12"));
        assert!(!is_allowed("wasi:http/handler@0.3.0"));
        assert!(!is_allowed("wasi:http/types@0.3.0"));
        assert!(!is_allowed("wasi:clocks/timezone@0.2.12"));
        assert!(!is_allowed("wasi:io/streams@0.3.0"));
        assert!(!is_allowed("wasi:io/streams"));
        assert!(!is_allowed("kronik:actor/state@0.2.0"));
        assert!(!is_allowed("kronik:actor/blobs@0.1.0"));
        assert!(!is_allowed("my-func"));
    }
}
