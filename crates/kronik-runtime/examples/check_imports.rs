//! Lists the imports of Kronik components and checks them against the
//! deploy allowlist, with the same check `kronik deploy` runs
//! (`IMPORT_NOT_ALLOWED`, ADR 0001). CI runs it on the example actors after
//! building them (`scripts/ci.sh examples`).
//!
//! Usage: `cargo run -p kronik-runtime --example check_imports -- <component.wasm>...`
//!
//! Exits with 1 if a component imports an interface outside the allowlist or
//! cannot be read, and with 2 on bad usage.

use std::process::ExitCode;

use kronik_runtime::allowlist::{component_imports, disallowed_imports, is_allowed};

fn check(path: &str) -> Result<bool, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let imports = component_imports(&bytes).map_err(|e| format!("{path}: {e}"))?;
    let denied = disallowed_imports(&bytes).map_err(|e| format!("{path}: {e}"))?;
    println!("{path}: {} imports", imports.len());
    for name in &imports {
        let verdict = if is_allowed(name) {
            "allowed"
        } else {
            "DENIED "
        };
        println!("  {verdict} {name}");
    }
    if denied.is_empty() {
        println!("  allowlist OK");
        return Ok(true);
    }
    eprintln!(
        "{path}: IMPORT_NOT_ALLOWED: the component imports interfaces outside the allowlist: {}",
        denied.join(", ")
    );
    Ok(false)
}

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: check_imports <component.wasm>...");
        return ExitCode::from(2);
    }
    let mut ok = true;
    for path in &paths {
        match check(path) {
            Ok(allowed) => ok &= allowed,
            Err(e) => {
                eprintln!("{e}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
