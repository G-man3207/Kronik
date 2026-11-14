//! Failed fsyncs while a node starts.
//!
//! A start writes to the disk: it opens the log (the first segment of a fresh
//! log is created and synced), and the webhook workload, which has a secret
//! store, also appends records to the log itself: the secret format fence of
//! a fresh log, and the final state of a secret version that an earlier node
//! left reserved. Each of those fsyncs can fail. A daemon whose start fails
//! exits and its supervisor starts it again; the simulator restarts the node
//! the same way, and the run must end without a violation.
//!
//! The nightly DST failed 43 of 10,000 webhook seeds because only the log
//! open's own error restarted the node, and the fence reported the same
//! injected failure as a secret error. The first two tests fail those writes
//! on purpose, and do not depend on a seed; the last pins the seeds of that
//! run.

use kronik_sim::fs::INJECTED_FSYNC_EIO;
use kronik_sim::scenario::{Report, ScenarioConfig, run};

/// A webhook run on a quiet disk (no random fsync failures, no scheduled
/// crashes) in which the `n`th fsync of the disk fails.
fn failing_fsync(seed: u64, n: u64) -> Report {
    let mut cfg = ScenarioConfig::webhook_for_seed(seed);
    cfg.fsync_error = 0.0;
    cfg.max_crashes = 0;
    cfg.fail_fsyncs = vec![n];
    run(seed, cfg)
}

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

#[test]
fn the_log_open_and_the_first_record_of_a_start_can_fail_their_fsync() {
    for seed in [0, 1] {
        // The first fsync of a fresh disk makes the first segment of the log:
        // the log open fails with its own I/O error.
        let opened = failing_fsync(seed, 1);
        assert!(opened.ok(), "seed {seed}, fsync 1: {}", why(&opened));
        assert_eq!(opened.start_failures, [INJECTED_FSYNC_EIO], "seed {seed}");

        // The second is the first record the start appends, the secret
        // format fence: the start fails with a secret error that reports the
        // stopped log writer (the failure of the nightly run).
        let fenced = failing_fsync(seed, 2);
        assert!(fenced.ok(), "seed {seed}, fsync 2: {}", why(&fenced));
        assert!(
            matches!(&fenced.start_failures[..], [e] if e.contains("log writer stopped")),
            "seed {seed}: {:?}",
            fenced.start_failures
        );
    }
}

#[test]
fn an_fsync_that_fails_anywhere_in_the_first_writes_is_survived() {
    // Start-time writes, later writes of the start (the coverage watermark,
    // whose failure is no failure to start) and the first turns.
    for seed in [0, 1] {
        for n in 1..=10 {
            let report = failing_fsync(seed, n);
            assert!(report.ok(), "seed {seed}, fsync {n}: {}", why(&report));
        }
    }
}

/// (seed, the write of the start that fails its fsync), pinned again once
/// the log open fsyncs what a dead process left, each start writes the
/// keystore backup retention through the node's file system, and DST fixes
/// the startup decode width at 4.
const NIGHTLY_SEEDS: &[(u64, &str)] = &[
    (
        18,
        "the log open of the first node: the fsync of a fresh log's first segment",
    ),
    (
        564,
        "a record the first node's start appends to its fresh log, the store kept",
    ),
    (
        834,
        "a record the first node's start appends to its fresh log, the store lost",
    ),
    (
        43,
        "the log open of the second node, after a crash that kept the store",
    ),
    (
        229,
        "a record the second node's start appends, after a crash that kept the store",
    ),
    (727, "a record the fourth node's start appends"),
    (
        314,
        "the log opens of the fifth and of the ninth node: two failed starts in one run",
    ),
];

/// A seed pins a place in the run's random draws: a change in the number of
/// fsyncs a start makes moves it, and the run then passes without failing a
/// start. Every seed must pass whatever it does, and at least one must still
/// fail a start, or the group tests nothing: then find new seeds with
/// `scripts/dst.sh`, whose run lines show `start-failures=N`, and replace the
/// ones that moved. The tests above are the guard of the writes themselves.
#[test]
fn the_seeds_of_the_nightly_run_that_failed_a_start_pass() {
    let mut failed_starts = 0;
    for &(seed, write) in NIGHTLY_SEEDS {
        let report = run(seed, ScenarioConfig::webhook_for_seed(seed));
        assert!(report.ok(), "seed {seed} ({write}): {}", why(&report));
        failed_starts += report.start_failures.len();
    }
    assert!(
        failed_starts > 0,
        "no pinned seed fails a start any more: pin other seeds (see the comment above)"
    );
}
