//! DST entry point with a custom harness (`harness = false`), so that a
//! failing seed can be re-run exactly as the brief asks:
//!
//!   cargo test --release --test dst -- --seed 12345
//!   cargo test --release --test dst -- --seeds 0..200
//!   cargo test --release --test dst            (default: seeds 0..16)
//!
//! libtest rejects unknown flags such as `--seed`, which is why `kronik-sim`
//! needs a custom harness target too.

use std::process::ExitCode;

use spike_d_dst::scenario::{ScenarioConfig, run_own};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut seeds = 0..16u64;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                let Some(s) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) else {
                    eprintln!("--seed needs a number");
                    return ExitCode::FAILURE;
                };
                seeds = s..s + 1;
                i += 1;
            }
            "--seeds" => {
                let parsed = args
                    .get(i + 1)
                    .and_then(|r| r.split_once(".."))
                    .and_then(|(a, b)| Some(a.parse::<u64>().ok()?..b.parse::<u64>().ok()?));
                let Some(r) = parsed else {
                    eprintln!("--seeds needs A..B");
                    return ExitCode::FAILURE;
                };
                seeds = r;
                i += 1;
            }
            // Flags cargo passes to every test binary.
            _ => {}
        }
        i += 1;
    }
    let mut failed = Vec::new();
    for seed in seeds.clone() {
        let r = run_own(seed, ScenarioConfig::for_seed(seed));
        println!("{}", r.line());
        if !r.ok() {
            for v in &r.violations {
                println!("  violation: {v}");
            }
            println!("  reproduce: cargo test --release --test dst -- --seed {seed}");
            failed.push(seed);
        }
    }
    println!(
        "dst: {} seeds, {} failed {failed:?}",
        seeds.end - seeds.start,
        failed.len()
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
