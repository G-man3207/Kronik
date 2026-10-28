//! `kronik test-host` (hidden): an in-memory node for the SDK testkits. It
//! builds and deploys the project, prints a ready line, then answers one
//! JSON request per stdin line with one JSON line on stdout (the protocol is
//! in kronik_testhost's protocol module). Progress and errors go to stderr.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::Args;
use kronik_core::env::real::RealSpawner;
use kronik_testhost::{Options, TestHost};
use serde_json::{Value, json};

use super::Failure;

#[derive(Debug, Args)]
pub struct TestHostArgs {
    /// A project to build (as kronik build does) and deploy.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// TypeScript: the entries of `--dir` to build and deploy, instead of
    /// package.json's `kronik.entry`; repeat for more (such as a second
    /// actor type, or a variant).
    #[arg(long, requires = "dir")]
    entry: Vec<String>,
    /// A component to deploy; repeat for more.
    #[arg(long)]
    wasm: Vec<PathBuf>,
    /// Seeds ids, execution seeds and guest randomness.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Where the clock starts, in ms since the Unix epoch.
    #[arg(long, default_value_t = kronik_testhost::DEFAULT_START_MS)]
    start_ms: u64,
}

pub fn run(args: TestHostArgs) -> Result<(), Failure> {
    let mut components = Vec::new();
    if let Some(dir) = &args.dir {
        if args.entry.is_empty() {
            components.push(super::build::run(dir, false, None)?);
        }
        for entry in &args.entry {
            components.push(super::build::run(dir, false, Some(entry))?);
        }
    }
    components.extend(args.wasm);
    let mut wasm = Vec::new();
    for path in &components {
        wasm.push(
            std::fs::read(path).map_err(|e| Failure::new(format!("{}: {e}", path.display())))?,
        );
    }
    // A project's test hosts share its compiled code in .kronik/code, which
    // keeps the components being tested and the project's current builds in
    // dist/ (tests may start hosts with different entries), and drops older
    // builds. They start one at a time, so that one compiles and the others
    // load its result.
    let (code_cache, lock) = match &args.dir {
        Some(dir) => {
            let work = dir.join(".kronik");
            let lock = std::fs::File::create(work.join("build.lock"))?;
            lock.lock()?;
            let cache = work.join("code");
            let built = std::fs::read_dir(dir.join("dist"))
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "wasm"))
                .filter_map(|e| std::fs::read(e.path()).ok());
            let keep: Vec<String> = wasm
                .iter()
                .map(|w| blake3::hash(w).to_hex().to_string())
                .chain(built.map(|w| blake3::hash(&w).to_hex().to_string()))
                .collect();
            for entry in std::fs::read_dir(&cache).into_iter().flatten().flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !keep.iter().any(|hash| name.starts_with(hash.as_str())) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            (Some(cache), Some(lock))
        }
        None => (None, None),
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kronik-test-host")
        .build()?;
    let spawner = Arc::new(RealSpawner(rt.handle().clone()));
    let options = Options {
        seed: args.seed,
        start_ms: args.start_ms,
        code_cache,
    };
    let host = rt
        .block_on(TestHost::start(spawner, options))
        .map_err(|e| Failure::new(e.to_string()))?;
    let mut kinds = Vec::new();
    for (path, bytes) in components.iter().zip(wasm) {
        let body = json!({ "wasm_base64": STANDARD.encode(bytes), "reason": "kronik test-host" });
        let res =
            rt.block_on(host.api("POST", "/v1/deployments", "", body.to_string().into_bytes()));
        let answer: Value = serde_json::from_slice(&res.body).unwrap_or(Value::Null);
        if res.status != 200 {
            return Err(Failure::new(format!(
                "deploying {}: {}",
                path.display(),
                answer["error"]["message"].as_str().unwrap_or("failed")
            )));
        }
        kinds.push(answer["deployment"]["kind"].clone());
    }
    drop(lock);

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{}",
        json!({ "ok": true, "ready": true, "kinds": kinds })
    )?;
    out.flush()?;
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        writeln!(out, "{}", rt.block_on(host.handle_line(&line)))?;
        out.flush()?;
    }
    Ok(())
}
