//! A fatal stop during the blob workload's final drain.
//!
//! The blob workload ends with two collector passes (B6) and checks the
//! state after them. A pass can meet an injected fsync error, which stops
//! the node: the daemon must not retry the write, but the harness must
//! restart the node and run the passes on the next start, as it does the
//! workload's own turns. Reporting the stop as a lost invariant failed the
//! nightly DST's 10,000-seed run on three seeds.

use kronik_sim::scenario::{Report, ScenarioConfig, run};

/// What a failed run says, for an assertion message.
fn why(report: &Report) -> String {
    let tail: Vec<&str> = report
        .recent
        .iter()
        .rev()
        .take(12)
        .rev()
        .map(String::as_str)
        .collect();
    format!("{:?}\n{}", report.violations, tail.join("\n"))
}

/// The seeds of the nightly run at v0.5.0 that reported the final passes'
/// injected fsync error as a violation. A seed pins a place in the run's
/// random draws; every seed must pass whatever it does, and these three
/// keep the drain's restart covered.
#[test]
fn the_seeds_of_the_nightly_run_that_failed_the_last_passes_pass() {
    for seed in [2257, 3895, 9336] {
        let report = run(seed, ScenarioConfig::blobs_for_seed(seed));
        assert!(report.ok(), "seed {seed}: {}", why(&report));
    }
}
