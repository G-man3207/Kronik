//! Spike A acceptance checks (`demo`) and measurements (`bench`).

use std::path::Path;
use std::time::{Duration, Instant};

use crate::host::TurnSpec;
use crate::host::bindings::kronik::actor::types::{Incoming, Input, Message};
use crate::turn::{Outcome, Runner};
use crate::{TurnOpts, allowlist, deploy_check, engine};

fn msg(name: &str, body: &str) -> Input {
    Input::Message(Incoming {
        sender: None,
        msg: Message {
            name: name.into(),
            content_type: "text/plain".into(),
            body: body.as_bytes().to_vec(),
            blobs: Vec::new(),
        },
    })
}

struct Report {
    failures: u32,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        let tag = if ok { "PASS" } else { "FAIL" };
        println!("{tag}  {name}: {}", detail.as_ref());
        if !ok {
            self.failures += 1;
        }
    }
}

fn line<'a>(outcome: &'a Outcome, key: &str) -> Option<&'a str> {
    let Outcome::Committed(text) = outcome else {
        return None;
    };
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

/// Minimal component (component-model text format) importing denied interfaces.
const DENIED_COMPONENT_WAT: &str = r#"
(component
  (import "wasi:clocks/wall-clock@0.2.12" (instance))
  (import "wasi:filesystem/preopens@0.2.12" (instance))
  (import "wasi:sockets/tcp@0.2.12" (instance))
  (import "wasi:http/outgoing-handler@0.2.12" (instance))
)
"#;

pub async fn demo(
    bytes: &[u8],
    fs_guest: Option<&[u8]>,
    cache: Option<&Path>,
) -> wasmtime::Result<bool> {
    let mut r = Report { failures: 0 };
    println!("engine {}", engine::engine_version());

    // 1. Allowlist.
    let imports = allowlist::component_imports(bytes)?;
    let bad = allowlist::disallowed_imports(bytes)?;
    r.check(
        "allowlist/rust-guest",
        bad.is_empty(),
        format!("{} imports, {} denied", imports.len(), bad.len()),
    );
    let denied = wat::parse_str(DENIED_COMPONENT_WAT)?;
    let bad = allowlist::disallowed_imports(&denied)?;
    r.check(
        "allowlist/synthetic-denied",
        bad == [
            "wasi:filesystem/preopens@0.2.12",
            "wasi:sockets/tcp@0.2.12",
            "wasi:http/outgoing-handler@0.2.12",
        ],
        format!("IMPORT_NOT_ALLOWED lists {bad:?}"),
    );
    if let Some(fs) = fs_guest {
        let msg = deploy_check(fs).err().unwrap_or_default();
        r.check(
            "allowlist/rust-guest-using-std-fs",
            msg.starts_with("IMPORT_NOT_ALLOWED"),
            msg.lines().next().unwrap_or(""),
        );
    }

    // 2. Code cache: compile + precompile/deserialize keyed by hash and engine version.
    let engine = engine::build_engine()?;
    let tmp_cache;
    let cache = match cache {
        Some(c) => c,
        None => {
            tmp_cache =
                std::env::temp_dir().join(format!("kronik-spike-a-cache-{}", std::process::id()));
            &tmp_cache
        }
    };
    let compiled = engine::load_component(&engine, bytes, None)?;
    let first = engine::load_component(&engine, bytes, Some(cache))?;
    let second = engine::load_component(&engine, bytes, Some(cache))?;
    r.check(
        "code-cache",
        second.source == engine::CodeSource::CacheHit,
        format!(
            "{:?} then {:?}, file {}",
            first.source,
            second.source,
            second
                .cache_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
    );

    let runner = Runner::new(&engine, &second.component)?;
    let runner_compiled = Runner::new(&engine, &compiled.component)?;
    let spec = TurnOpts::default_spec();

    // 3. describe.
    let (manifest, trace) = runner.describe(&spec).await?;
    r.check(
        "describe",
        manifest.kind == "spike-a" && trace.is_empty(),
        format!("kind={} routes={}", manifest.kind, manifest.routes.len()),
    );

    // 4. Determinism: same input + seed + logical time + state on fresh instances.
    let probe = msg("probe", "");
    let a = runner.handle(&spec, &probe).await?;
    let b = runner.handle(&spec, &probe).await?;
    let c = runner_compiled.handle(&spec, &probe).await?;
    let engine2 = engine::build_engine()?;
    let loaded2 = engine::load_component(&engine2, bytes, Some(cache))?;
    let d = Runner::new(&engine2, &loaded2.component)?
        .handle(&spec, &probe)
        .await?;
    r.check(
        "determinism/byte-identical",
        a.canonical() == b.canonical()
            && a.canonical() == c.canonical()
            && a.canonical() == d.canonical(),
        format!(
            "4 fresh instances (2 engines, compiled + deserialized code), digest {}",
            a.digest()
        ),
    );
    r.check(
        "determinism/committed",
        matches!(a.outcome, Outcome::Committed(_)),
        format!("{} host calls, fuel {}", a.trace.len(), a.fuel_used),
    );
    let wasi_calls = a.trace.iter().filter(|l| l.starts_with("wasi:")).count();
    r.check(
        "determinism/wasi-calls-traced",
        wasi_calls > 0,
        format!("{wasi_calls} wasi clock/random/stdio calls in the trace"),
    );
    let sys = line(&a.outcome, "std_system_time_ms").unwrap_or("");
    r.check(
        "std-clock=logical-time",
        sys == spec.logical_time_ms.to_string(),
        format!("SystemTime::now() = {sys} ms"),
    );
    let elapsed = line(&a.outcome, "std_instant_elapsed_ns").unwrap_or("");
    r.check(
        "std-instant-constant",
        elapsed == "0",
        format!("Instant elapsed across busy loop = {elapsed} ns"),
    );

    let mut other_seed = spec.clone();
    other_seed.seed[0] ^= 1;
    let e = runner.handle(&other_seed, &probe).await?;
    let rb = |o: &Outcome| line(o, "random_bytes").map(str::to_string);
    let hs = |o: &Outcome| line(o, "std_random_state_hash").map(str::to_string);
    r.check(
        "seed-drives-randomness",
        rb(&e.outcome) != rb(&a.outcome) && hs(&e.outcome) != hs(&a.outcome),
        format!("random_bytes {:?} -> {:?}", rb(&a.outcome), rb(&e.outcome)),
    );
    let mut later = spec.clone();
    later.logical_time_ms += 1234;
    let f = runner.handle(&later, &probe).await?;
    r.check(
        "time-drives-clocks",
        line(&f.outcome, "std_system_time_ms") == Some(&later.logical_time_ms.to_string()),
        format!("now_ms {:?}", line(&f.outcome, "now_ms")),
    );

    // 5. I3: the guest static counter resets every turn; state survives only via the host.
    let mut spec_n = spec.clone();
    let mut counters = Vec::new();
    let mut ns = Vec::new();
    for _ in 0..3 {
        let t = runner.handle(&spec_n, &probe).await?;
        counters.push(
            line(&t.outcome, "static_counter")
                .unwrap_or("?")
                .to_string(),
        );
        ns.push(line(&t.outcome, "state.n").unwrap_or("?").to_string());
        for (k, v) in t.writes {
            match v {
                Some(v) => spec_n.state.insert(k, v),
                None => spec_n.state.remove(&k),
            };
        }
    }
    r.check(
        "fresh-instance/static-counter",
        counters.iter().all(|c| c == "1"),
        format!("static_counter per turn {counters:?}"),
    );
    r.check(
        "fresh-instance/host-state",
        ns == ["1", "2", "3"],
        format!("state.n per turn {ns:?}"),
    );

    // 6. Fuel.
    let mut low_fuel = spec.clone();
    low_fuel.fuel = 5_000_000;
    let s1 = runner.handle(&low_fuel, &msg("spin", "")).await?;
    let s2 = runner.handle(&low_fuel, &msg("spin", "")).await?;
    r.check(
        "fuel/exhausted",
        s1.outcome == Outcome::FuelExhausted
            && s1.fuel_used == low_fuel.fuel
            && s1.canonical() == s2.canonical(),
        format!(
            "{} after {} fuel, deterministic",
            s1.outcome.code(),
            s1.fuel_used
        ),
    );

    // 7. Memory limit.
    let big = runner.handle(&spec, &msg("alloc", "100")).await?;
    r.check(
        "memory/limit-enforced",
        matches!(big.outcome, Outcome::MemoryLimit(_)),
        format!(
            "alloc 100 MiB with 64 MiB limit -> {:?}, peak {} KiB",
            big.outcome,
            big.peak_memory_bytes / 1024
        ),
    );
    let small = runner.handle(&spec, &msg("alloc", "16")).await?;
    r.check(
        "memory/within-limit",
        matches!(small.outcome, Outcome::Committed(_)),
        format!(
            "alloc 16 MiB -> {}, peak {} KiB",
            small.outcome.code(),
            small.peak_memory_bytes / 1024
        ),
    );
    let mut roomy = spec.clone();
    roomy.memory_bytes = 256 << 20;
    // Bulk memory ops are charged fuel per byte, so 100 MiB of zeroing needs
    // more than the default 50M fuel.
    roomy.fuel = 500_000_000;
    let raised = runner.handle(&roomy, &msg("alloc", "100")).await?;
    r.check(
        "memory/per-kind-limit",
        matches!(raised.outcome, Outcome::Committed(_)),
        format!(
            "alloc 100 MiB with a 256 MiB limit -> {}, fuel {}",
            raised.outcome.code(),
            raised.fuel_used
        ),
    );

    // 8. Traps, stderr capture, denied effects.
    let trap = runner.handle(&spec, &msg("trap", "")).await?;
    let stderr_seen = trap
        .trace
        .iter()
        .any(|l| l.starts_with("wasi:cli/stderr.write") && l.contains("deliberate trap"));
    r.check(
        "trap/classified",
        matches!(trap.outcome, Outcome::Trap(_)) && stderr_seen,
        format!("{:?}, panic message captured from stderr", trap.outcome),
    );
    let denied = runner.handle(&spec, &msg("denied", "")).await?;
    let text = match &denied.outcome {
        Outcome::Committed(t) => t.clone(),
        o => format!("{o:?}"),
    };
    r.check(
        "effects/denied",
        text.matches("Denied").count() == 3 && text.contains("CAPABILITY_NOT_GRANTED"),
        "http.fetch, crypto, sql denied; secrets.reveal err",
    );

    // 9. Memory isolation across pooled slots: a turn after a 100 MiB allocation
    // sees a fresh static counter and an outcome identical to the very first one.
    let after = runner.handle(&spec, &probe).await?;
    r.check(
        "fresh-instance/after-reuse",
        after.canonical() == a.canonical(),
        "pooled slot reuse leaves no trace",
    );

    // 10. Async host functions: `messaging.call` runs the callee's whole turn
    // on a second fresh instance while the caller's instance is suspended.
    let c1 = runner.handle(&spec, &msg("call", "")).await?;
    let c2 = runner.handle(&spec, &msg("call", "")).await?;
    let text = match &c1.outcome {
        Outcome::Committed(t) => t.clone(),
        o => format!("{o:?}"),
    };
    r.check(
        "nested-call/async-host",
        text.contains("self=spike-a/callee")
            && text.contains("caller_static_counter=1")
            && c1.canonical() == c2.canonical(),
        format!(
            "callee turn ran inside the caller's call, {} trace lines, deterministic",
            c1.trace.len()
        ),
    );

    if cache.starts_with(std::env::temp_dir())
        && cache
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("kronik-spike-a-cache-"))
    {
        let _ = std::fs::remove_dir_all(cache);
    }

    println!("{} check(s) failed", r.failures);
    Ok(r.failures == 0)
}

struct Stats {
    p50: Duration,
    p99: Duration,
    mean: Duration,
}

fn stats(mut v: Vec<Duration>) -> Stats {
    v.sort();
    let pct = |p: f64| v[((v.len() as f64 - 1.0) * p).round() as usize];
    let mean = v.iter().sum::<Duration>() / v.len() as u32;
    Stats {
        p50: pct(0.50),
        p99: pct(0.99),
        mean,
    }
}

fn fmt(s: &Stats) -> String {
    format!(
        "p50 {:>9.1?}  p99 {:>9.1?}  mean {:>9.1?}",
        s.p50, s.p99, s.mean
    )
}

pub async fn bench(bytes: &[u8], iterations: u32, msg_name: &str) -> wasmtime::Result<()> {
    println!("engine      {}", engine::engine_version());
    println!(
        "component   {} ({} bytes)",
        engine::short_hash(&engine::code_hash(bytes)),
        bytes.len()
    );
    let engine = engine::build_engine()?;

    // Compile time (Cranelift, parallel compilation on).
    let mut compiles = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let _ = wasmtime::component::Component::new(&engine, bytes)?;
        compiles.push(t.elapsed());
    }
    println!("compile     {} (5 runs)", fmt(&stats(compiles)));

    let dir = std::env::temp_dir().join(format!("kronik-spike-a-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = engine::load_component(&engine, bytes, Some(&dir))?;
    let mut loads = Vec::new();
    for _ in 0..20 {
        loads.push(engine::load_component(&engine, bytes, Some(&dir))?.load_time);
    }
    println!("deserialize {} (cache hit, 20 runs)", fmt(&stats(loads)));
    let _ = std::fs::remove_dir_all(&dir);

    let spec: TurnSpec = TurnOpts::default_spec();
    let input = msg(msg_name, "");
    for pooling in [true, false] {
        let engine = engine::build_engine_with(pooling)?;
        let component = wasmtime::component::Component::new(&engine, bytes)?;
        let runner = Runner::new(&engine, &component)?;
        // Warm up.
        for _ in 0..100 {
            runner.handle(&spec, &input).await?;
        }
        let mut inst = Vec::with_capacity(iterations as usize);
        let mut call = Vec::with_capacity(iterations as usize);
        let mut total = Vec::with_capacity(iterations as usize);
        let mut fuel = 0;
        for _ in 0..iterations {
            let t = Instant::now();
            let r = runner.handle(&spec, &input).await?;
            total.push(t.elapsed());
            inst.push(r.instantiate_time);
            call.push(r.call_time);
            fuel = r.fuel_used;
        }
        let label = if pooling { "pooling" } else { "on-demand" };
        println!("[{label}] {iterations} turns of {msg_name:?}, fuel/turn {fuel}");
        println!("  instantiate {}", fmt(&stats(inst)));
        println!("  call        {}", fmt(&stats(call)));
        let t = stats(total);
        println!(
            "  whole turn  {}  (~{:.0} turns/s single-threaded)",
            fmt(&t),
            1.0 / t.mean.as_secs_f64()
        );
    }
    Ok(())
}
