//! Spike E CLI.
//!
//!   spike-e-sql check            all acceptance checks
//!   spike-e-sql probe            determinism probe output (used with TZ=...)
//!   spike-e-sql bench [--actors N] [--dir PATH]   cost measurements

mod bench;
mod checks;
mod ffi;
mod sqlstate;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let exe = std::env::current_exe().unwrap_or_default();
    let ok = match args.get(1).map(String::as_str) {
        Some("check") => checks::run_all(&exe),
        Some("probe") => {
            let (lines, _) = checks::probe(1_761_300_000_000, 7);
            for l in lines {
                println!("{l}");
            }
            true
        }
        Some("bench") => {
            let mut actors = 10_000usize;
            let mut dir =
                std::env::temp_dir().join(format!("kronik-spike-e-bench-{}", std::process::id()));
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--actors" => {
                        actors = args
                            .get(i + 1)
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(actors)
                    }
                    "--dir" => dir = args.get(i + 1).map(Into::into).unwrap_or(dir),
                    _ => {}
                }
                i += 2;
            }
            bench::run(actors, &dir)
        }
        _ => {
            eprintln!("usage: spike-e-sql check | probe | bench [--actors N] [--dir PATH]");
            false
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
