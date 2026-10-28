//! I8 in forks (v0.1 security review H4, H5): a fork never gets a secret's
//! value, and its turns are scrubbed exactly like production's, so fork
//! logs, diff.json and diffs never hold a revealed value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use common::*;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::Proposals;

const SECRET: &str = "VALUE-fork-8e31d0";

fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan(&p, hits);
        } else if std::fs::read(&p)
            .unwrap()
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
        {
            hits.push(p.display().to_string());
        }
    }
}

#[test]
fn a_fork_reveals_only_the_placeholder_and_writes_no_secret_value() {
    let (addr, _) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(guest("leaky")).unwrap(), audit(), false),
    )
    .unwrap();
    p.node
        .secret_set("k1", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    for cap in ["secret-reveal:k1", "http:127.0.0.1"] {
        p.rt.block_on(p.node.grant("leaky", cap, None, None, audit(), false))
            .unwrap();
    }
    let fork_lsn = p.settle();
    let r = p.send("leaky/a", "reveal-fetch", &format!("k1 http://{addr}/x"));
    assert!(r.committed(), "{r:?}");
    p.settle();

    let props = Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap();
    p.rt.block_on(props.create_fork(Some("probe".into()), fork_lsn, false, audit(), false))
        .unwrap();
    for mode in [Mode::Isolated, Mode::Continuous] {
        p.rt.block_on(props.fork_replay(
            "probe",
            None,
            DiffOptions {
                mode,
                ..DiffOptions::default()
            },
            None,
        ))
        .unwrap();
        let d: serde_json::Value =
            serde_json::from_slice(&p.rt.block_on(props.diff("probe", false, false)).unwrap())
                .unwrap();
        // The placeholder rebuilds production's (scrubbed) requests: every
        // effect is answered exactly, nothing changed.
        let s = &d["summary"];
        assert_eq!(
            (&s["changed"], &s["approximate"], &s["synthetic"]),
            (&false.into(), &0.into(), &0.into()),
            "{mode:?}: {d}"
        );
        assert!(!d.to_string().contains(SECRET), "{mode:?}: {d}");
        let md =
            String::from_utf8(p.rt.block_on(props.diff("probe", true, false)).unwrap()).unwrap();
        assert!(!md.contains(SECRET), "{md}");
    }
    drop(props);
    drop(p);
    let mut hits = Vec::new();
    scan(dir.path(), &mut hits);
    assert!(hits.is_empty(), "the secret value is in {hits:?}");
}
