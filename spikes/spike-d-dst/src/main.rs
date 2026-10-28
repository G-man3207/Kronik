//! Spike D CLI.
//!
//!   spike-d-dst seed 12345            one seed, verbose report
//!   spike-d-dst seeds 0..200 [-j 8]   a seed range, in parallel threads
//!   spike-d-dst determinism 0..20     every seed twice, compare trace hashes
//!   spike-d-dst long --requests N     one long run (the >= 1M-step run)
//!   spike-d-dst real                  the same daemon on tokio multi-thread + real fs
//!   spike-d-dst madsim-seed 12345     the same scenario on madsim (needs --cfg madsim)

use std::ops::Range;
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use clap::{Parser, Subcommand};
use spike_d_dst::scenario::{Report, ScenarioConfig, run_own};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Seed {
        seed: u64,
    },
    Seeds {
        range: String,
        #[arg(short, default_value_t = 1)]
        j: usize,
    },
    Determinism {
        range: String,
    },
    Long {
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 2500)]
        requests: usize,
        /// Mean ms between injected crashes (0 disables crashes).
        #[arg(long, default_value_t = 400)]
        crash_ms: u64,
        #[arg(long)]
        no_replay: bool,
    },
    Real,
    /// Executor overhead only: 100 tasks x 10k random sleeps + mutex.
    ExecBench,
    /// Seed deliberate bugs and count the seeds that catch each one.
    Mutants {
        range: String,
        #[arg(short, default_value_t = 8)]
        j: usize,
    },
    #[cfg(madsim)]
    MadsimSeed {
        seed: u64,
    },
    #[cfg(madsim)]
    MadsimSeeds {
        range: String,
    },
}

fn parse_range(s: &str) -> Result<Range<u64>, String> {
    let (a, b) = s.split_once("..").ok_or("expected A..B")?;
    Ok(
        a.parse::<u64>().map_err(|e| e.to_string())?
            ..b.parse::<u64>().map_err(|e| e.to_string())?,
    )
}

fn print_failure(r: &Report) {
    println!("{}", r.line());
    for v in &r.violations {
        println!("  violation: {v}");
    }
    println!("  last events:");
    for e in &r.recent {
        println!("    {e}");
    }
    println!("  reproduce: cargo run --release -- seed {}", r.seed);
}

fn run_range(
    range: Range<u64>,
    threads: usize,
    f: impl Fn(u64) -> Report + Sync,
) -> (u64, u64, u64, u64) {
    let next = AtomicU64::new(range.start);
    let failed = AtomicU64::new(0);
    let polls = AtomicU64::new(0);
    let events = AtomicU64::new(0);
    let out = Mutex::new(());
    std::thread::scope(|s| {
        for _ in 0..threads.max(1) {
            s.spawn(|| {
                loop {
                    let seed = next.fetch_add(1, Ordering::SeqCst);
                    if seed >= range.end {
                        break;
                    }
                    let r = f(seed);
                    polls.fetch_add(r.polls, Ordering::Relaxed);
                    events.fetch_add(r.events, Ordering::Relaxed);
                    let _g = out.lock();
                    if r.ok() {
                        println!("{}", r.line());
                    } else {
                        failed.fetch_add(1, Ordering::SeqCst);
                        print_failure(&r);
                    }
                }
            });
        }
    });
    (
        range.end - range.start,
        failed.load(Ordering::SeqCst),
        polls.load(Ordering::Relaxed),
        events.load(Ordering::Relaxed),
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let ok = match cli.cmd {
        Cmd::Seed { seed } => {
            let r = run_own(seed, ScenarioConfig::for_seed(seed));
            if r.ok() {
                println!("{}", r.line())
            } else {
                print_failure(&r)
            }
            r.ok()
        }
        Cmd::Seeds { range, j } => {
            let Ok(range) = parse_range(&range) else {
                return ExitCode::FAILURE;
            };
            // Compile the guest once before timing.
            let _ = spike_d_dst::wasm::code();
            let t = Instant::now();
            let (n, failed, polls, events) =
                run_range(range, j, |s| run_own(s, ScenarioConfig::for_seed(s)));
            let el = t.elapsed().as_secs_f64();
            println!(
                "{n} seeds, {failed} failed, {:.1}s wall with {j} thread(s): {:.1} seeds/s, {:.0} polls/s, {:.0} events/s",
                el,
                n as f64 / el,
                polls as f64 / el,
                events as f64 / el
            );
            failed == 0
        }
        Cmd::Determinism { range } => {
            let Ok(range) = parse_range(&range) else {
                return ExitCode::FAILURE;
            };
            let mut hashes = std::collections::BTreeMap::new();
            let mut same = true;
            for seed in range.clone() {
                let a = run_own(seed, ScenarioConfig::for_seed(seed));
                let b = run_own(seed, ScenarioConfig::for_seed(seed));
                let eq = a.trace_hash == b.trace_hash && a.polls == b.polls && a.events == b.events;
                same &= eq;
                println!(
                    "seed {seed}: {} / {} polls {} / {} -> {}",
                    a.trace_hash,
                    b.trace_hash,
                    a.polls,
                    b.polls,
                    if eq { "identical" } else { "DIFFERENT" }
                );
                hashes.insert(a.trace_hash.clone(), seed);
            }
            let distinct = hashes.len() as u64 == range.end - range.start;
            println!(
                "same seed twice: {}; distinct hashes across seeds: {} of {}",
                if same { "all identical" } else { "MISMATCH" },
                hashes.len(),
                range.end - range.start
            );
            same && distinct
        }
        Cmd::Long {
            seed,
            requests,
            crash_ms,
            no_replay,
        } => {
            let mut cfg = ScenarioConfig::for_seed(seed);
            cfg.clients = 8;
            cfg.requests_per_client = requests;
            cfg.actors = 16;
            cfg.crash_every = std::time::Duration::from_millis(crash_ms);
            cfg.replay_check = !no_replay;
            cfg.max_polls = u64::MAX;
            cfg.db_snapshot_every_commit = false;
            cfg.rebuild_check_every = 25;
            let _ = spike_d_dst::wasm::code();
            let r = run_own(seed, cfg);
            if r.ok() {
                println!("{}", r.line())
            } else {
                print_failure(&r)
            }
            println!(
                "long run: {} polls in {:.1}s wall = {:.0} polls/s; {:.0}s simulated ({:.0}x real time)",
                r.polls,
                r.wall_time.as_secs_f64(),
                r.polls as f64 / r.wall_time.as_secs_f64(),
                r.sim_time.as_secs_f64(),
                r.sim_time.as_secs_f64() / r.wall_time.as_secs_f64()
            );
            r.ok()
        }
        Cmd::Mutants { range, j } => {
            let Ok(range) = parse_range(&range) else {
                return ExitCode::FAILURE;
            };
            mutants(range, j)
        }
        Cmd::ExecBench => {
            let (polls, wall) = spike_d_dst::scenario::exec_bench_own(1, 100, 10_000);
            println!(
                "own executor: {polls} polls in {:.2}s = {:.0} polls/s",
                wall.as_secs_f64(),
                polls as f64 / wall.as_secs_f64()
            );
            #[cfg(madsim)]
            {
                let (polls, wall) = spike_d_dst::madsim_backend::exec_bench_madsim(1, 100, 10_000);
                println!(
                    "madsim:       {polls} polls in {:.2}s = {:.0} polls/s",
                    wall.as_secs_f64(),
                    polls as f64 / wall.as_secs_f64()
                );
            }
            true
        }
        Cmd::Real => match spike_d_dst::scenario::run_real() {
            Ok(line) => {
                println!("{line}");
                true
            }
            Err(e) => {
                println!("real mode failed: {e}");
                false
            }
        },
        #[cfg(madsim)]
        Cmd::MadsimSeed { seed } => {
            let r = spike_d_dst::madsim_backend::run_madsim(seed, ScenarioConfig::for_seed(seed));
            if r.ok() {
                println!("{}", r.line())
            } else {
                print_failure(&r)
            }
            r.ok()
        }
        #[cfg(madsim)]
        Cmd::MadsimSeeds { range } => {
            let Ok(range) = parse_range(&range) else {
                return ExitCode::FAILURE;
            };
            let _ = spike_d_dst::wasm::code();
            let t = Instant::now();
            let (n, failed, polls, events) = run_range(range, 1, |s| {
                spike_d_dst::madsim_backend::run_madsim(s, ScenarioConfig::for_seed(s))
            });
            let el = t.elapsed().as_secs_f64();
            println!(
                "{n} seeds, {failed} failed, {el:.1}s wall: {:.1} seeds/s, {:.0} polls/s, {:.0} events/s",
                n as f64 / el,
                polls as f64 / el,
                events as f64 / el
            );
            failed == 0
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Every mutation must be caught by at least one seed in the range; the
/// determinism mutation is caught by running each seed twice.
fn mutants(range: Range<u64>, threads: usize) -> bool {
    use spike_d_dst::daemon::Mutation;
    let _ = spike_d_dst::wasm::code();
    let all = [
        Mutation::EffectBeforeTurnBegin,
        Mutation::AckBeforeFsync,
        Mutation::NoTruncateTail,
        Mutation::NoDirSync,
        Mutation::WallClockTime,
        Mutation::NoRerun,
        Mutation::HashMapRerunOrder,
    ];
    let mut all_caught = true;
    for m in all {
        let caught = AtomicU64::new(0);
        let example = Mutex::new(None::<(u64, String)>);
        let next = AtomicU64::new(range.start);
        std::thread::scope(|s| {
            for _ in 0..threads.max(1) {
                s.spawn(|| {
                    loop {
                        let seed = next.fetch_add(1, Ordering::SeqCst);
                        if seed >= range.end {
                            break;
                        }
                        let mut cfg = ScenarioConfig::for_seed(seed);
                        cfg.mutation = Some(m);
                        let a = run_own(seed, cfg.clone());
                        let detail = if m == Mutation::HashMapRerunOrder {
                            let b = run_own(seed, cfg);
                            (a.trace_hash != b.trace_hash).then(|| {
                                format!(
                                    "trace hash {} vs {} for the same seed",
                                    a.trace_hash, b.trace_hash
                                )
                            })
                        } else {
                            a.violations.first().cloned()
                        };
                        if let Some(d) = detail {
                            caught.fetch_add(1, Ordering::SeqCst);
                            let mut e = example.lock().unwrap_or_else(|e| e.into_inner());
                            if e.as_ref().is_none_or(|(s, _)| seed < *s) {
                                *e = Some((seed, d));
                            }
                        }
                    }
                });
            }
        });
        let n = caught.load(Ordering::SeqCst);
        all_caught &= n > 0;
        let ex = example.into_inner().unwrap_or_else(|e| e.into_inner());
        println!(
            "{:<24} caught by {n:>3} of {} seeds{}",
            format!("{m:?}"),
            range.end - range.start,
            ex.map(|(s, d)| format!(
                "; e.g. seed {s}: {}",
                d.chars().take(140).collect::<String>()
            ))
            .unwrap_or_default()
        );
    }
    all_caught
}
