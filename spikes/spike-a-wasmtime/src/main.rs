//! Spike A harness CLI: load any component targeting `kronik:actor@0.1.0`,
//! check its imports against the allowlist, run `describe` and `handle` on
//! fresh instances, and print the result plus the ordered host-call trace.

mod allowlist;
mod checks;
mod engine;
mod host;
mod turn;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use host::TurnSpec;
use host::bindings::kronik::actor::types::{
    ActorRef, Header, HttpBody, HttpRequest, Incoming, Input, Message,
};

#[derive(Parser)]
#[command(
    name = "spike-a-wasmtime",
    about = "Kronik spike A: deterministic Wasmtime harness"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
enum Cmd {
    /// Print the engine version string.
    Version,
    /// List a component's imports and exports and run the allowlist check.
    Imports { component: PathBuf },
    /// Run `describe` in an isolated turn without state and effects.
    Describe {
        component: PathBuf,
        #[command(flatten)]
        code: CodeOpts,
    },
    /// Run `handle` for one input on fresh instances and print the result and trace.
    Handle {
        component: PathBuf,
        #[command(flatten)]
        code: CodeOpts,
        #[command(flatten)]
        turn: TurnOpts,
        /// Run the same turn N times on fresh instances and compare digests.
        #[arg(long, default_value_t = 1)]
        repeat: u32,
    },
    /// Run spike A's acceptance checks against the spike's Rust guest.
    Demo {
        component: PathBuf,
        /// A guest built with `--features fs-probe`, expected to be rejected.
        #[arg(long)]
        fs_guest: Option<PathBuf>,
        #[command(flatten)]
        code: CodeOpts,
    },
    /// Measure compile, instantiation and per-turn overhead.
    Bench {
        component: PathBuf,
        #[arg(long, default_value_t = 5000)]
        iterations: u32,
        /// Message name used for the per-turn measurement.
        #[arg(long, default_value = "noop")]
        msg: String,
    },
}

#[derive(Args, Clone)]
struct CodeOpts {
    /// Precompiled-code cache directory (`<blake3>.<engine-version>.cwasm`).
    #[arg(long)]
    cache: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct TurnOpts {
    /// Deliver a message with this name (default: `probe`).
    #[arg(long, conflicts_with = "http")]
    msg: Option<String>,
    /// Deliver an HTTP request, e.g. "POST /spike/acme/probe".
    #[arg(long)]
    http: Option<String>,
    /// Body of the message or HTTP request.
    #[arg(long, default_value = "")]
    body: String,
    /// HTTP header "name: value" (repeatable).
    #[arg(long)]
    header: Vec<String>,
    /// Message sender "kind/key".
    #[arg(long)]
    sender: Option<String>,
    /// The actor "kind/key" this turn runs as.
    #[arg(long, default_value = "spike-a/acme")]
    actor: String,
    #[arg(long, default_value = "root-1/0")]
    causal_id: String,
    /// Logical time of the turn in ms since the Unix epoch.
    #[arg(long, default_value_t = 1_761_300_000_000)]
    time_ms: u64,
    /// 32-byte turn seed as 64 hex chars (default: a fixed test seed).
    #[arg(long)]
    seed: Option<String>,
    #[arg(long, default_value_t = engine::DEFAULT_FUEL)]
    fuel: u64,
    #[arg(long, default_value_t = 64)]
    memory_mib: usize,
    /// Starting state "key=value" (repeatable).
    #[arg(long)]
    state: Vec<String>,
}

pub const DEFAULT_SEED: [u8; 32] = *b"kronik-spike-a-fixed-test-seed!!";

fn parse_actor(s: &str) -> Result<(String, String), String> {
    s.split_once('/')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected kind/key, got {s:?}"))
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("seed must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out[i] = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

impl TurnOpts {
    pub fn spec(&self) -> Result<TurnSpec, String> {
        let (kind, key) = parse_actor(&self.actor)?;
        let mut state = BTreeMap::new();
        for kv in &self.state {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| format!("expected key=value, got {kv:?}"))?;
            state.insert(k.to_string(), v.as_bytes().to_vec());
        }
        Ok(TurnSpec {
            kind,
            key,
            causal_id: self.causal_id.clone(),
            logical_time_ms: self.time_ms,
            seed: match &self.seed {
                Some(s) => parse_seed(s)?,
                None => DEFAULT_SEED,
            },
            state,
            fuel: self.fuel,
            memory_bytes: self.memory_mib << 20,
        })
    }

    pub fn input(&self) -> Result<Input, String> {
        if let Some(http) = &self.http {
            let (method, target) = http.split_once(' ').ok_or("expected \"METHOD /path\"")?;
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let mut headers = Vec::new();
            for h in &self.header {
                let (n, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("bad header {h:?}"))?;
                headers.push(Header {
                    name: n.trim().to_lowercase(),
                    value: v.trim().to_string(),
                });
            }
            return Ok(Input::Http(HttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: query.to_string(),
                params: Vec::new(),
                headers,
                body: HttpBody::Inline(self.body.as_bytes().to_vec()),
            }));
        }
        let sender = match &self.sender {
            Some(s) => {
                let (kind, key) = parse_actor(s)?;
                Some(ActorRef { kind, key })
            }
            None => None,
        };
        Ok(Input::Message(Incoming {
            sender,
            msg: Message {
                name: self.msg.clone().unwrap_or_else(|| "probe".to_string()),
                content_type: "text/plain".to_string(),
                body: self.body.as_bytes().to_vec(),
                blobs: Vec::new(),
            },
        }))
    }
}

/// Refuses components that import anything outside the allowlist, the way
/// `kronik deploy` will.
pub fn deploy_check(bytes: &[u8]) -> Result<(), String> {
    match allowlist::disallowed_imports(bytes) {
        Ok(bad) if bad.is_empty() => Ok(()),
        Ok(bad) => Err(format!(
            "IMPORT_NOT_ALLOWED: the component imports interfaces outside the allowlist: {}\n\
             hint: only kronik:actor/*, wasi:clocks, wasi:random, wasi:cli and wasi:io (0.2.x) may be imported",
            bad.join(", ")
        )),
        Err(e) => Err(format!("IMPORT_NOT_ALLOWED: {e}")),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

async fn run(cli: Cli) -> Result<ExitCode, String> {
    let e = |e: wasmtime::Error| format!("{e:?}");
    match cli.cmd {
        Cmd::Version => {
            println!("{}", engine::engine_version());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Imports { component } => {
            let bytes = read(&component)?;
            let imports = allowlist::component_imports(&bytes).map_err(|e| e.to_string())?;
            println!(
                "component  {}",
                engine::short_hash(&engine::code_hash(&bytes))
            );
            println!("imports    {}", imports.len());
            for name in &imports {
                let verdict = if allowlist::is_allowed(name) {
                    "allowed"
                } else {
                    "DENIED"
                };
                println!("  {verdict:<8} {name}");
            }
            let engine = engine::build_engine().map_err(e)?;
            let loaded = engine::load_component(&engine, &bytes, None).map_err(e)?;
            let ty = loaded.component.component_type();
            for (name, _) in ty.exports(&engine) {
                println!("export     {name}");
            }
            match deploy_check(&bytes) {
                Ok(()) => {
                    println!("allowlist  OK");
                    Ok(ExitCode::SUCCESS)
                }
                Err(msg) => {
                    println!("{msg}");
                    Ok(ExitCode::from(2))
                }
            }
        }
        Cmd::Describe { component, code } => {
            let bytes = read(&component)?;
            if let Err(msg) = deploy_check(&bytes) {
                eprintln!("{msg}");
                return Ok(ExitCode::from(2));
            }
            let engine = engine::build_engine().map_err(e)?;
            let loaded =
                engine::load_component(&engine, &bytes, code.cache.as_deref()).map_err(e)?;
            let runner = turn::Runner::new(&engine, &loaded.component).map_err(e)?;
            let spec = TurnOpts::default_spec();
            let (manifest, trace) = runner.describe(&spec).await.map_err(e)?;
            println!(
                "code       {} ({})",
                engine::short_hash(&loaded.code_hash),
                engine::engine_version()
            );
            println!("kind       {}", manifest.kind);
            println!("schema     {}", manifest.schema_version);
            for r in &manifest.routes {
                println!("route      {} {}", r.method, r.pattern);
            }
            for c in &manifest.capabilities {
                println!("capability {c}");
            }
            for line in trace {
                println!("call       {line}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Handle {
            component,
            code,
            turn: opts,
            repeat,
        } => {
            let bytes = read(&component)?;
            if let Err(msg) = deploy_check(&bytes) {
                eprintln!("{msg}");
                return Ok(ExitCode::from(2));
            }
            let spec = opts.spec()?;
            let input = opts.input()?;
            let engine = engine::build_engine().map_err(e)?;
            let loaded =
                engine::load_component(&engine, &bytes, code.cache.as_deref()).map_err(e)?;
            let runner = turn::Runner::new(&engine, &loaded.component).map_err(e)?;
            println!(
                "code       {} ({:?}, compile {:?}, load {:?})",
                engine::short_hash(&loaded.code_hash),
                loaded.source,
                loaded.compile_time,
                loaded.load_time
            );
            println!("engine     {}", engine::engine_version());
            let mut digests = Vec::new();
            for i in 0..repeat.max(1) {
                let r = runner.handle(&spec, &input).await.map_err(e)?;
                if i == 0 {
                    print!("{}", r.canonical());
                    println!("memory     peak {} KiB", r.peak_memory_bytes / 1024);
                    println!(
                        "timing     instantiate {:?}, call {:?} (not part of the outcome)",
                        r.instantiate_time, r.call_time
                    );
                }
                println!("digest {i}   {}", r.digest());
                digests.push(r.digest());
            }
            let identical = digests.windows(2).all(|w| w[0] == w[1]);
            if repeat > 1 {
                println!("identical  {}", if identical { "yes" } else { "NO" });
            }
            Ok(if identical {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Cmd::Demo {
            component,
            fs_guest,
            code,
        } => {
            let bytes = read(&component)?;
            let fs = match fs_guest {
                Some(p) => Some(read(&p)?),
                None => None,
            };
            let ok = checks::demo(&bytes, fs.as_deref(), code.cache.as_deref())
                .await
                .map_err(e)?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Cmd::Bench {
            component,
            iterations,
            msg,
        } => {
            let bytes = read(&component)?;
            checks::bench(&bytes, iterations, &msg).await.map_err(e)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

impl TurnOpts {
    pub fn default_spec() -> TurnSpec {
        TurnSpec {
            kind: "spike-a".into(),
            key: "acme".into(),
            causal_id: "root-1/0".into(),
            logical_time_ms: 1_761_300_000_000,
            seed: DEFAULT_SEED,
            state: BTreeMap::new(),
            fuel: engine::DEFAULT_FUEL,
            memory_bytes: engine::DEFAULT_MEMORY_BYTES,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Single-threaded executor: the same shape the DST executor will have.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
