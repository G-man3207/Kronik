//! Startup speed (docs/perf.md, m6-storage §9): "start with 1 GB of log
//! after the latest snapshot: under 30 seconds".
//!
//!   cargo run --release -p kronik-sched --example startup_speed -- \
//!     [--gib 1.0] [--actors 4096] [--apply-batch N] [--data DIR] [--reuse] [--read-only]
//!
//! Writes a snapshot, then about `--gib` GiB of counter turn records after
//! it, and stops the node as a crash would. It then times `start_local`
//! (which returns once the log is replayed and the node serves) twice:
//! without `state.db` and `sql/`, so the start installs the snapshot and
//! replays everything after it, and with `state.db` as it was at the
//! snapshot, which is a crash with 1 GiB unapplied. `--reuse` skips the
//! writing and measures an existing directory again, for example with
//! another `--apply-batch`; `--read-only` times only reading and decoding
//! the records after the snapshot. The data directory (default
//! /var/tmp/kronik-startup-speed) is wiped first unless `--reuse` or
//! `--read-only` is given.

// A measurement tool: wall-clock timing, tokio runtimes and stdout output.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Ingress, NodeConfig, start_local};

const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");
const GIB: f64 = (1u64 << 30) as f64;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn config(data: &Path, apply_batch: Option<usize>) -> NodeConfig {
    let defaults = NodeConfig::default();
    NodeConfig {
        concurrency: 64,
        storage: Some(StorageConfig::new(data.to_path_buf())),
        apply_batch: apply_batch.unwrap_or(defaults.apply_batch),
        ..defaults
    }
}

/// Bytes in the log's segment files.
fn log_bytes(data: &Path) -> u64 {
    std::fs::read_dir(data.join("branches/main/log"))
        .map(|dir| {
            dir.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// The state.db copy taken right after the snapshot.
fn saved_state(data: &Path) -> PathBuf {
    data.join("state-at-snapshot.db")
}

/// Writes the snapshot and the log after it; returns the snapshot's LSN and
/// the log's size at the snapshot.
fn write(data: &Path, gib: f64, actors: usize) -> (u64, u64) {
    let rt = runtime();
    let out = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let node = start_local(env, data, config(data, None)).await.unwrap();
        let audit = pb::Audit {
            token_id: "bench".into(),
            reason: "startup speed".into(),
            wall_time_ms: 0,
        };
        node.deploy(COUNTER, audit, false).await.unwrap();
        let manifest = node.snapshot("manual").await.unwrap();
        node.store().db().backup_to(&saved_state(data)).unwrap();
        let at_snapshot = log_bytes(data);
        let target = at_snapshot + (gib * GIB) as u64;
        println!(
            "snapshot {} at lsn {}; writing {gib} GiB of counter turns over {actors} actors",
            manifest.id, manifest.lsn
        );
        let start = Instant::now();
        let mut turns = 0u64;
        let mut next_report = 0.1;
        while log_bytes(data) < target {
            let mut waiters = Vec::with_capacity(actors);
            for a in 0..actors {
                let key = format!("k{a}");
                let http = pb::HttpInput {
                    method: "POST".into(),
                    path: format!("/counter/{key}/increment"),
                    params: vec![
                        pb::Param {
                            name: "key".into(),
                            value: key.clone(),
                            sealed_value: None,
                        },
                        pb::Param {
                            name: "op".into(),
                            value: "increment".into(),
                            sealed_value: None,
                        },
                    ],
                    route: "/counter/{key}/{op}".into(),
                    ..Default::default()
                };
                let actor = ActorRef::parse(&format!("counter/{key}")).unwrap();
                match node.ingress(actor, http, None).unwrap() {
                    Ingress::Started(w) | Ingress::Joined(w) => waiters.push(w),
                    Ingress::Done(_) => {}
                }
            }
            for w in waiters {
                w.wait().await.unwrap();
                turns += 1;
            }
            let done = (log_bytes(data) - at_snapshot) as f64 / (target - at_snapshot) as f64;
            if done >= next_report {
                println!(
                    "  {:>3.0}%: {turns} turns, {:.0} turns/s",
                    done * 100.0,
                    turns as f64 / start.elapsed().as_secs_f64()
                );
                next_report += 0.1;
            }
        }
        println!(
            "wrote {turns} turns, {:.2} GiB after the snapshot, in {:.0} s; lsn {}",
            (log_bytes(data) - at_snapshot) as f64 / GIB,
            start.elapsed().as_secs_f64(),
            node.applied_lsn()
        );
        (manifest.lsn, at_snapshot)
    });
    // Dropping the runtime stops every task: a crash after durable writes.
    drop(rt);
    out
}

/// Times `start_local` until it returns: replay done, serving.
fn start(data: &Path, apply_batch: Option<usize>, what: &str, from_lsn: u64, replay_bytes: u64) {
    let rt = runtime();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let t = Instant::now();
        let node = start_local(env, data, config(data, apply_batch)).await.unwrap();
        let took = t.elapsed().as_secs_f64();
        let lsn = node.applied_lsn();
        println!(
            "{what}: {took:.2} s to serve; replayed lsn {}..={lsn} ({} records, {:.2} GiB, {:.0} MiB/s, {:.0} records/s)",
            from_lsn + 1,
            lsn - from_lsn,
            replay_bytes as f64 / GIB,
            replay_bytes as f64 / (1u64 << 20) as f64 / took,
            (lsn - from_lsn) as f64 / took,
        );
    });
    drop(rt);
}

fn remove_state(data: &Path) {
    let branch = data.join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    let _ = std::fs::remove_dir_all(branch.join("sql"));
}

/// Times reading and decoding the log after the snapshot without applying
/// it: the reader's share of a start.
fn read_only(data: &Path, from_lsn: u64, replay_bytes: u64) {
    let rt = runtime();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, data.join("branches/main/log"), "main");
        let t = Instant::now();
        let mut records = 0u64;
        reader
            .read(from_lsn + 1, u64::MAX, |_| {
                records += 1;
                Ok(())
            })
            .await
            .unwrap();
        let took = t.elapsed().as_secs_f64();
        println!(
            "reading the log alone: {took:.2} s for {records} records ({:.2} GiB, {:.0} records/s)",
            replay_bytes as f64 / GIB,
            records as f64 / took
        );
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let gib: f64 = arg(&args, "--gib").map_or(1.0, |v| v.parse().unwrap());
    let actors: usize = arg(&args, "--actors").map_or(4096, |v| v.parse().unwrap());
    let apply_batch: Option<usize> = arg(&args, "--apply-batch").map(|v| v.parse().unwrap());
    let reuse = args.iter().any(|a| a == "--reuse" || a == "--read-only");
    let data = PathBuf::from(
        arg(&args, "--data").unwrap_or_else(|| "/var/tmp/kronik-startup-speed".into()),
    );
    let (snapshot_lsn, at_snapshot) = if reuse {
        let lsn: u64 = std::fs::read_to_string(data.join("snapshot-lsn"))
            .expect("--reuse needs a directory from an earlier run")
            .trim()
            .parse()
            .unwrap();
        let bytes: u64 = std::fs::read_to_string(data.join("snapshot-log-bytes"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        (lsn, bytes)
    } else {
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).unwrap();
        let (lsn, bytes) = write(&data, gib, actors);
        std::fs::write(data.join("snapshot-lsn"), lsn.to_string()).unwrap();
        std::fs::write(data.join("snapshot-log-bytes"), bytes.to_string()).unwrap();
        (lsn, bytes)
    };
    let replay_bytes = log_bytes(&data).saturating_sub(at_snapshot);
    if args.iter().any(|a| a == "--read-only") {
        read_only(&data, snapshot_lsn, replay_bytes);
        return;
    }
    let batch = apply_batch.unwrap_or(NodeConfig::default().apply_batch);
    println!("apply_batch={batch}");

    remove_state(&data);
    start(
        &data,
        apply_batch,
        "without state.db (the snapshot is installed)",
        snapshot_lsn,
        replay_bytes,
    );
    if std::env::var_os("KRONIK_STARTUP_ONCE").is_some() {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        println!("cores={cores}");
        return;
    }

    remove_state(&data);
    std::fs::copy(saved_state(&data), data.join("branches/main/state.db")).unwrap();
    start(
        &data,
        apply_batch,
        "with state.db at the snapshot (a crash)",
        snapshot_lsn,
        replay_bytes,
    );
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("cores={cores}");
}
