//! I8 in forks (v0.1 security review H4, H5): a fork never gets a secret's
//! value, and its turns are scrubbed exactly like production's, so fork
//! logs, diff.json and diffs never hold a revealed value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::*;
use kronik_core::error::ErrorCode;
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::Proposals;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::NodeConfig;
use prost::Message as _;

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
        p.rt.block_on(p.node.grant(
            "leaky",
            cap,
            None,
            None,
            kronik_effects::InForks::Recorded,
            audit(),
            false,
            p.owner(),
        ))
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

/// Damages every `http.fetch` record in the log of a node that is stopped: the
/// effect becomes a timeout (no response, an error text) and its secret
/// reference loses its version and hash, the name and the template staying.
/// Returns how many records changed.
fn damage_the_fetch_records(data: &std::path::Path) -> usize {
    let log = data.join("branches/main/log");
    let mut damaged = 0;
    for start in kronik_log::segment_starts(&log).unwrap() {
        let path = log.join(kronik_log::segment_name(start));
        kronik_log::rewrite_segment(&path, |_lsn, record| {
            let effects: Vec<&mut pb::EffectRecord> = match record {
                Record::EffectResult(result) => result.effect.iter_mut().collect(),
                Record::TurnRecord(turn) => turn.effects.iter_mut().collect(),
                _ => return Ok(false),
            };
            let mut changed = false;
            for effect in effects.into_iter().filter(|e| e.kind == "http.fetch") {
                let Some(pb::sealable::Value::Plain(bytes)) = effect
                    .request
                    .as_mut()
                    .and_then(|request| request.value.as_mut())
                else {
                    continue;
                };
                let mut request =
                    pb::HttpEffectRequest::decode(bytes.as_slice()).map_err(|e| e.to_string())?;
                for header in &mut request.headers {
                    if let Some(pb::http_effect_header::Value::Secret(reference)) =
                        &mut header.value
                    {
                        reference.version = 0;
                        reference.wide_version = 0;
                        reference.version_hash.clear();
                        changed = true;
                    }
                }
                *bytes = request.encode_to_vec();
                effect.status = pb::EffectStatus::Timeout as i32;
                effect.error = "no response within 2000 ms".into();
                effect.response = None;
            }
            damaged += usize::from(changed);
            Ok(changed)
        })
        .unwrap();
    }
    damaged
}

/// A fork at `lsn`, replayed in isolation: its diff, or why it could not be made.
fn replay_probe(
    p: &Proc,
    dir: &std::path::Path,
    name: &str,
    lsn: u64,
) -> Result<serde_json::Value, kronik_core::error::ApiError> {
    let props = Arc::new(Proposals::open(p.node.clone(), dir.to_path_buf()).unwrap());
    p.rt.block_on(props.create_fork(Some(name.into()), lsn, false, audit(), false, p.owner()))
        .unwrap();
    p.rt.block_on(props.fork_replay(
        name,
        None,
        DiffOptions {
            mode: Mode::Isolated,
            ..DiffOptions::default()
        },
        None,
        p.owner(),
    ))?;
    Ok(serde_json::from_slice(&p.rt.block_on(props.diff(name, false, false)).unwrap()).unwrap())
}

/// Production records a secret header without a version only for an effect that
/// did not get its secret: the secret does not exist, the backend could not be
/// had, or an unsafe effect was ended as outcome unknown without asking. A
/// fetch record that has one and another status is damaged, and a fork must
/// refuse it, not replay it as if it matched.
///
/// A real turn with a real secret is replayed (it matches). Then its records
/// are damaged on disk, while the node is stopped: a timeout, with the version
/// of the secret gone. The node still certifies its inventory, because its scan
/// takes an unresolved reference of an effect that did not succeed, so the
/// replay of the same fork point is stopped by the fork's own check and by
/// nothing else. (A *successful* record with one is stopped earlier: the scan
/// refuses it, the inventory cannot be certified, and every read that scrubs,
/// replays included, answers 503; the unit test of `may_lack_its_secret` has it.)
#[test]
fn a_fork_refuses_a_fetch_record_that_lacks_its_secret_version_without_a_reason() {
    let (addr, hits) = server();
    let dir = tempdir();
    let p = Proc::start(dir.path());
    p.rt.block_on(
        p.node
            .secret_set("k1", SECRET.as_bytes().to_vec(), &audit(), false, p.owner()),
    )
    .unwrap();
    for cap in ["secret:k1", "http:127.0.0.1"] {
        p.grant(cap);
    }
    let fork_lsn = p.settle();
    let turn = p.send(
        "counter/a",
        "fetch-ok",
        &format!("POST http://{addr}/x\nS x-api-key k1 {{}}\n\nbody"),
    );
    assert!(turn.committed(), "{turn:?}");
    p.settle();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // The control: the undamaged records replay, every effect exact.
    let d = replay_probe(&p, dir.path(), "control", fork_lsn).unwrap();
    let s = &d["summary"];
    assert_eq!(
        (&s["changed"], &s["approximate"], &s["synthetic"]),
        (&false.into(), &0.into(), &0.into()),
        "{d}"
    );
    assert!(s["exact"].as_u64() >= Some(1), "{d}");
    drop(p);

    // The damage, on disk. The state is derived from the log, so it goes and is
    // rebuilt at the next start.
    assert!(damage_the_fetch_records(dir.path()) >= 2);
    let branch = dir.path().join("branches/main");
    for name in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(name));
    }
    let _ = std::fs::remove_dir_all(branch.join("sql"));
    let _ = std::fs::remove_dir_all(dir.path().join("snapshots"));
    let p = Proc::open(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    );
    // A 503 for a certificate that is not there yet is not the answer under test.
    p.rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            p.node.secret_cycle_settled(),
        )
        .await
    })
    .expect("the secret cycle never settled");
    let error = replay_probe(&p, dir.path(), "damaged", fork_lsn).unwrap_err();
    assert_eq!(error.code, ErrorCode::SecretUnavailable, "{error}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a fork sent a request");
}
