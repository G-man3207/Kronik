//! Packs directories into a deterministic single-image OCI layout and
//! prints its manifest digest (one line, `sha256:<hex>`). `DIR` is replaced
//! if it exists. Used by the scripts that build the foreign example images.
//!
//! Usage:
//!   oci_pack --out DIR --ref NAME --layer gzip:DIR [--layer tar:DIR]...
//!            [--entrypoint JSON] [--cmd JSON] [--env K=V]... [--workdir P]
//!            [--user U] [--expose 8080/tcp]...

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use kronik_foreign::oci::{ImageSpec, LayerSource, pack};

fn main() -> ExitCode {
    match run() {
        Ok(digest) => {
            println!("{digest}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("oci_pack: {e}");
            ExitCode::FAILURE
        }
    }
}

fn json_list(flag: &str, s: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(s).map_err(|e| format!("{flag}: not a JSON list of strings: {e}"))
}

fn run() -> Result<String, String> {
    let mut out: Option<PathBuf> = None;
    let mut layers = Vec::new();
    let mut spec = ImageSpec {
        workdir: "/".into(),
        ..ImageSpec::default()
    };
    let mut reference = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--out" => out = Some(PathBuf::from(value)),
            "--ref" => reference = Some(value),
            "--layer" => {
                let (gzip, dir) = match value.split_once(':') {
                    Some(("gzip", dir)) => (true, dir),
                    Some(("tar", dir)) => (false, dir),
                    _ => return Err(format!("bad --layer {value}: expected gzip:DIR or tar:DIR")),
                };
                layers.push(LayerSource {
                    dir: dir.into(),
                    gzip,
                });
            }
            "--entrypoint" => spec.entrypoint = json_list(&flag, &value)?,
            "--cmd" => spec.cmd = json_list(&flag, &value)?,
            "--env" => {
                if !value.contains('=') {
                    return Err(format!("bad --env {value}: expected K=V"));
                }
                spec.env.push(value);
            }
            "--workdir" => spec.workdir = value,
            "--user" => spec.user = value,
            "--expose" => spec.exposed_ports.push(value),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    let out = out.ok_or("--out is required")?;
    spec.reference = reference.ok_or("--ref is required")?;
    if layers.is_empty() {
        return Err("at least one --layer is required".into());
    }
    match fs::remove_dir_all(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove {}: {e}", out.display())),
    }
    pack(&out, &layers, &spec).map_err(|e| e.to_string())
}
