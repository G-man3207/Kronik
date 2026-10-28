use std::process::Command;

use kronik_runtime::{KRONIK_VERSION, WASMTIME_VERSION};

#[test]
fn version_flag_prints_kronik_wasmtime_and_engine_versions() {
    let output = Command::new(env!("CARGO_BIN_EXE_kronik"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "kronik --version failed: {output:?}"
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "kronik {KRONIK_VERSION}\n\
             wasmtime {WASMTIME_VERSION}\n\
             engine kronik-{KRONIK_VERSION}+wasmtime-{WASMTIME_VERSION}\n"
        )
    );
}
