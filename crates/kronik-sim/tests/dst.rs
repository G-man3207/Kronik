//! DST entry point with a custom harness (`harness = false`), so a failing
//! seed can be re-run exactly:
//!
//!   cargo test -p kronik-sim --release --test dst -- --seed 12345
//!   cargo test -p kronik-sim --release --test dst -- --seeds 0..200
//!   cargo test -p kronik-sim --test dst          (default: seeds 0..4)
//!
//! `--scenario counter|effects|webhook|all` (default all) picks the
//! workload: the M1 counter workload, the M2 effects workload against a
//! simulated external service, webhook-relay-rs against the same service,
//! or all three for every seed. `--scenario rebuild` (not part of `all`)
//! runs the effects workload with tiny startup-replay thresholds and
//! segments, and checks every start's recovered state against a rebuild
//! from the log.
//! `--long STEPS` runs the counter workload as one long run per seed (default
//! seed 0) of at least STEPS executor steps, with crashes throughout; the
//! Definition of done asks for at least 1 000 000 (`--long 1000000`).
//! `KRONIK_DST_RELAY=<component>` runs the webhook workload with another
//! relay (e.g. webhook-relay-ts) instead of webhook-relay-rs.
//! `--twice` runs every seed twice and fails if the traces differ
//! (determinism check). `--mutation ack-before-fsync` seeds a deliberate
//! log bug; the run is then expected to report violations for some seeds.
//! libtest rejects unknown flags such as `--seed`, hence the custom harness.

// The harness reports on stdout like libtest does.
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

use kronik_sim::scenario::{ScenarioConfig, run};

fn parse_range(s: &str) -> Option<std::ops::Range<u64>> {
    let (a, b) = s.split_once("..")?;
    Some(a.parse().ok()?..b.parse().ok()?)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut seeds = 0..4u64;
    let mut twice = false;
    let mut mutation = false;
    let mut scenarios = vec!["counter", "effects", "webhook"];
    let mut long = None;
    let mut seeds_given = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => match args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                Some(s) => {
                    seeds = s..s + 1;
                    seeds_given = true;
                    i += 1;
                }
                None => {
                    eprintln!("--seed needs a number");
                    return ExitCode::FAILURE;
                }
            },
            "--seeds" => match args.get(i + 1).and_then(|r| parse_range(r)) {
                Some(r) => {
                    seeds = r;
                    seeds_given = true;
                    i += 1;
                }
                None => {
                    eprintln!("--seeds needs A..B");
                    return ExitCode::FAILURE;
                }
            },
            "--twice" => twice = true,
            "--long" => match args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                Some(steps) => {
                    long = Some(steps);
                    scenarios = vec!["long"];
                    i += 1;
                }
                None => {
                    eprintln!("--long needs a number of steps");
                    return ExitCode::FAILURE;
                }
            },
            "--scenario" => match args.get(i + 1).map(String::as_str) {
                Some("counter") => {
                    scenarios = vec!["counter"];
                    i += 1;
                }
                Some("effects") => {
                    scenarios = vec!["effects"];
                    i += 1;
                }
                Some("webhook") => {
                    scenarios = vec!["webhook"];
                    i += 1;
                }
                Some("rebuild") => {
                    scenarios = vec!["rebuild"];
                    i += 1;
                }
                Some("all") => i += 1,
                _ => {
                    eprintln!("--scenario needs counter, effects, webhook, rebuild or all");
                    return ExitCode::FAILURE;
                }
            },
            "--mutation" => match args.get(i + 1).map(String::as_str) {
                Some("ack-before-fsync") => {
                    mutation = true;
                    i += 1;
                }
                _ => {
                    eprintln!("--mutation needs ack-before-fsync");
                    return ExitCode::FAILURE;
                }
            },
            // Flags cargo passes to every test binary.
            _ => {}
        }
        i += 1;
    }
    if long.is_some() && !seeds_given {
        seeds = 0..1;
    }
    let mut failed = Vec::new();
    let config = |seed, scenario: &str| ScenarioConfig {
        mutation_ack_before_fsync: mutation,
        ..if scenario == "effects" {
            ScenarioConfig::effects_for_seed(seed)
        } else if scenario == "webhook" {
            ScenarioConfig::webhook_for_seed(seed)
        } else if scenario == "rebuild" {
            ScenarioConfig::rebuild_for_seed(seed)
        } else if let Some(steps) = long {
            ScenarioConfig::long(seed, steps)
        } else {
            ScenarioConfig::for_seed(seed)
        }
    };
    let runs: Vec<(u64, &str)> = seeds
        .clone()
        .flat_map(|s| scenarios.iter().map(move |sc| (s, *sc)))
        .collect();
    for (seed, scenario) in runs {
        let r = run(seed, config(seed, scenario));
        println!("{scenario:<8} {}", r.line());
        let mut ok = r.ok();
        if let Some(steps) = long
            && r.polls < steps
        {
            println!(
                "  the long run ended after {} steps, before {steps}",
                r.polls
            );
            ok = false;
        }
        if !r.ok() {
            for v in &r.violations {
                println!("  violation: {v}");
            }
            for line in r.recent.iter().rev().take(20).rev() {
                println!("  | {line}");
            }
        }
        if twice {
            let again = run(seed, config(seed, scenario));
            if again.trace_hash != r.trace_hash {
                println!(
                    "  nondeterminism: trace {} then {}",
                    r.trace_hash, again.trace_hash
                );
                ok = false;
            }
        }
        if !ok {
            let what = match long {
                Some(steps) => format!("--long {steps}"),
                None => format!("--scenario {scenario}"),
            };
            println!(
                "  reproduce: cargo test -p kronik-sim --release --test dst -- --seed {seed} {what}"
            );
            failed.push(seed);
        }
    }
    println!(
        "dst: {} seeds x {:?}, {} failed {failed:?}",
        seeds.end - seeds.start,
        scenarios,
        failed.len()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
