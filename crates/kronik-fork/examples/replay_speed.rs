//! Replay speed (docs/perf.md, m3-fork §10): records the reference counter
//! workload open loop at a fixed rate, then replays the window with the
//! same code and reports production wall time / replay wall time.
//!
//!   cargo run --release -p kronik-fork --example replay_speed -- \
//!     [--requests 12000] [--rate 200] [--actors 256] [--workers N] [--data DIR]
//!
//! The data directory (default /var/tmp/kronik-replay-speed) is wiped first.

// A measurement tool: wall-clock timing, a tokio runtime and stdout output.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::{ProductionIndex, ReplaySetup, config_at, fork_kinds};
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, NodeConfig, start_local};

const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let requests: usize = arg(&args, "--requests").map_or(12_000, |v| v.parse().unwrap());
    let rate: f64 = arg(&args, "--rate").map_or(200.0, |v| v.parse().unwrap());
    let actors: usize = arg(&args, "--actors").map_or(256, |v| v.parse().unwrap());
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    let workers: usize = arg(&args, "--workers").map_or(cores, |v| v.parse().unwrap());
    let data = PathBuf::from(
        arg(&args, "--data").unwrap_or_else(|| "/var/tmp/kronik-replay-speed".into()),
    );
    let _ = std::fs::remove_dir_all(&data);
    std::fs::create_dir_all(&data).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let env = Env::real(tokio::runtime::Handle::current());
        let node = start_local(env, &data, NodeConfig { concurrency: 64, ..NodeConfig::default() })
            .await
            .unwrap();
        let audit = pb::Audit { token_id: "bench".into(), reason: "replay speed".into(), wall_time_ms: 0 };
        node.deploy(COUNTER, audit, false).await.unwrap();
        let fork_lsn = node.applied_lsn();

        // Record: open loop at `rate`.
        println!("recording {requests} requests at {rate} req/s over {actors} actors");
        let start = Instant::now();
        let mut waiters = Vec::with_capacity(requests);
        for i in 0..requests {
            let due = start + Duration::from_secs_f64(i as f64 / rate);
            tokio::time::sleep_until(due.into()).await;
            let key = format!("k{}", i % actors);
            let http = pb::HttpInput {
                method: "POST".into(),
                path: format!("/counter/{key}/increment"),
                params: vec![
                    pb::Param { name: "key".into(), value: key.clone(), sealed_value: None },
                    pb::Param { name: "op".into(), value: "increment".into(), sealed_value: None },
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
        }
        let prod_wall = start.elapsed();
        let to = node.applied_lsn();
        println!("production window: {:.2} s, LSNs {}..={to}", prod_wall.as_secs_f64(), fork_lsn + 1);

        let mut decoded = Vec::new();
        node.reader()
            .read(1, to, |c| {
                decoded.push(c);
                Ok(())
            })
            .await
            .unwrap();
        let t = Instant::now();
        let index = Arc::new(ProductionIndex::from_records(decoded, fork_lsn, to));
        let load = t.elapsed();
        let code = node.code().clone();
        let fc = fork_kinds(&index, fork_lsn, |h| code.get(h).map_err(|e| e.to_string()), &[]).unwrap();
        let config = config_at(&index, fork_lsn);
        let mut setup = ReplaySetup::new("f-bench".into(), index.clone(), fc.kinds, config, None);
        let t = Instant::now();
        let rebuilt = kronik_fork::replay::production_store(&index).unwrap();
        println!("applying the window to a fresh cursor: {:.3} s", t.elapsed().as_secs_f64());
        if kronik_fork::replay::same_diff_rows(node.store(), &rebuilt).unwrap() {
            setup.prod_store = Some(node.store().clone());
        }
        let setup = Arc::new(setup);
        // Isolated replay alone, without building the diff.
        let t = Instant::now();
        let trees = kronik_fork::replay::isolated(node.env(), setup.clone(), index.roots.clone(), workers)
            .await
            .unwrap();
        println!("isolated replay without the diff: {:.3} s ({} trees)", t.elapsed().as_secs_f64(), trees.len());
        let t = Instant::now();
        let d = kronik_fork::diff::build(kronik_fork::diff::DiffInput {
            fork: "f-bench",
            proposal_id: None,
            index: &index,
            before: fc.before.clone(),
            after: fc.after.clone(),
            options: &DiffOptions { mode: Mode::Isolated, ..DiffOptions::default() },
            isolated: Some(&trees),
            continuous: None,
            rebase: false,
        })
        .unwrap();
        println!("diff build: {:.3} s (changed {})", t.elapsed().as_secs_f64(), d.summary.changed);
        let mut results = Vec::new();
        for mode in [Mode::Isolated, Mode::Continuous, Mode::Both] {
            let opts = DiffOptions { mode, ..DiffOptions::default() };
            let t = Instant::now();
            let out = kronik_fork::run(node.env(), setup.clone(), &opts, workers, None, fc.before.clone(), fc.after.clone(), &[])
                .await
                .unwrap();
            let took = t.elapsed() + load;
            if mode == Mode::Both && out.diff.summary.changed {
                panic!("identity diff is not empty");
            }
            let speed = prod_wall.as_secs_f64() / took.as_secs_f64();
            println!(
                "{mode:?}: {:.2} s (index {:.2} s), {:.1}x real time, {} root inputs, {} turns, {:.0} turns/s",
                took.as_secs_f64(),
                load.as_secs_f64(),
                speed,
                out.diff.summary.root_inputs,
                out.diff.summary.turns_fork.max(out.diff.summary.root_inputs),
                out.diff.summary.root_inputs as f64 / took.as_secs_f64(),
            );
            results.push((mode, speed));
        }
        println!("workers={workers} cores={cores}");
    });
}
