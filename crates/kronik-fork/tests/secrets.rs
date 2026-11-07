//! I8 in forks (v0.1 security review H4, H5): a fork never gets a secret's
//! value, and its turns are scrubbed exactly like production's, so fork
//! logs, diff.json and diffs never hold a revealed value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

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
    p.rt.block_on(p.node.deploy(
        &std::fs::read(guest("leaky")).unwrap(),
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.rt.block_on(
        p.node
            .secret_set("k1", SECRET.as_bytes().to_vec(), &audit(), false, p.owner()),
    )
    .unwrap();
    for cap in ["secret-reveal:k1", "http:127.0.0.1"] {
        p.rt.block_on(
            p.node
                .grant("leaky", cap, None, None, audit(), false, p.owner()),
        )
        .unwrap();
    }
    let fork_lsn = p.settle();
    let r = p.send("leaky/a", "reveal-fetch", &format!("k1 http://{addr}/x"));
    assert!(r.committed(), "{r:?}");
    p.settle();

    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(
        Some("probe".into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
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
            p.owner(),
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

/// A turn whose secret it did not get recorded an error for the effect that
/// asked for it: a secret that does not exist, or, with a secret backend, one
/// that cannot be reached (the same recording, with another error). A fork
/// replays the recorded error exactly, whatever kind of effect asked.
///
/// `text` is sent as `name` to a counter whose secret `nokey` does not exist;
/// the guest of `fetch-ok` answers with the error, the others fail with it
/// (`committed` says which). Every effect of the replay must be answered from
/// the recording, in both modes, and no request is sent by anyone.
fn replay_of_an_effect_without_its_secret(name: &str, text: &str, committed: bool) {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    for cap in ["secret:nokey", "secret-reveal:nokey", "http:127.0.0.1"] {
        p.grant(cap);
    }
    let fork_lsn = p.settle();
    let text = text.replace("ADDR", &addr);
    let turn = p.send("counter/a", name, &text);
    assert_eq!(turn.committed(), committed, "{name}: {turn:?}");
    p.settle();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the request had no credential"
    );

    let props = Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(
        Some("probe".into()),
        fork_lsn,
        false,
        audit(),
        false,
        p.owner(),
    ))
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
            p.owner(),
        ))
        .unwrap();
        let d: serde_json::Value =
            serde_json::from_slice(&p.rt.block_on(props.diff("probe", false, false)).unwrap())
                .unwrap();
        let s = &d["summary"];
        assert_eq!(
            (
                &s["changed"],
                &s["divergent_turns"],
                &s["approximate"],
                &s["synthetic"]
            ),
            (&false.into(), &0.into(), &0.into(), &0.into()),
            "{name} {mode:?}: {d}"
        );
        assert!(s["exact"].as_u64() >= Some(1), "{name} {mode:?}: {d}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "a fork sent a request");
}

#[test]
fn a_fork_replays_a_fetch_whose_secret_header_got_no_secret() {
    replay_of_an_effect_without_its_secret(
        "fetch-ok",
        "POST http://ADDR/x\nS x-api-key nokey {}\n\nbody",
        true,
    );
}

#[test]
fn a_fork_replays_an_hmac_whose_secret_does_not_exist() {
    replay_of_an_effect_without_its_secret("hmac", "nokey\ndata", false);
}

#[test]
fn a_fork_replays_a_reveal_whose_secret_does_not_exist_as_the_failure_it_was() {
    replay_of_an_effect_without_its_secret("reveal", "nokey", false);
}
