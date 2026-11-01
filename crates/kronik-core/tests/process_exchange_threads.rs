//! Startup's temporary runtime must leave one OS thread before namespace entry.

use kronik_core::env::{ProcessRunner as _, ProcessSpec, SensitiveProcessRequest, Stdio};
use kronik_core::env::real::RealProcs;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    assert_eq!(std::fs::read_dir("/proc/self/task")?.count(), 1);

    let dir = tempfile::tempdir()?;
    let pin = dir.path().join("pin");
    std::fs::write(&pin, b"owned-test-pin\n")?;
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o600))?;
    let request = SensitiveProcessRequest {
        spec: ProcessSpec {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "IFS= read -r pin <&3 || exit 7; IFS= read -r request || exit 8; \
                 if IFS= read -r extra; then exit 9; fi; printf bounded-response".into(),
            ],
            env: vec![],
            cwd: Some(dir.path().to_owned()),
            stdout: Stdio::Null,
            stderr: Stdio::Null,
        },
        stdin: b"single-thread-boundary\n".to_vec().into(),
        pin_file: pin,
        timeout: Duration::from_secs(3),
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(RealProcs.exchange(request));
    #[cfg(target_os = "linux")]
    drop(result?);
    #[cfg(not(target_os = "linux"))]
    match result {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported),
        Ok(_) => panic!("non-Linux sensitive exchange unexpectedly succeeded"),
    }
    drop(runtime);

    #[cfg(target_os = "linux")]
    assert_eq!(std::fs::read_dir("/proc/self/task")?.count(), 1);
    Ok(())
}
