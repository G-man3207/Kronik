//! `kronik upgrade check` and the startup gate (docs/design/m6-storage.md
//! §7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::ENGINE_VERSION;
use kronik_sched::upgrade::{REPORT_SCHEMA, UpgradeReport};
use kronik_sched::{Node, NodeConfig, StartError, start_local};
use tokio::runtime::Runtime;

fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn msg(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn start(rt: &Runtime, dir: &Path) -> Result<Arc<Node>, StartError> {
    rt.block_on(async {
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig::default(),
        )
        .await
    })
}

/// A stopped node's background workers keep the data-directory lock's file
/// descriptor until they wind down (admitted capabilities share the owner
/// `File`, native_execution.rs), so an immediate restart can briefly answer
/// `KeySource(DataInUse)`. Await exactly that window — the CLI retries the
/// deployment-epoch recertification window the same way (known
/// gaps) — and treat any other start error, or a wait that runs out, as
/// fatal: a genuinely owned directory still fails here.
fn start_when_released(rt: &Runtime, dir: &Path) -> Arc<Node> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match start(rt, dir) {
            Ok(node) => return node,
            Err(error @ StartError::KeySource(_))
                if error.to_string().contains("the data directory is owned by") =>
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the stopped node's data lock was not released: {error}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("start failed: {error}"),
        }
    }
}

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("upgrade-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// The local operator's original node-lifetime authority.
fn owner(node: &Node) -> kronik_core::authority::AuthLease {
    node.local_operator_authority().unwrap()
}

/// A data directory with counter and notes turns, and a snapshot halfway.
fn workload(dir: &Path) -> u64 {
    let rt = rt();
    let node = start(&rt, dir).unwrap();
    rt.block_on(async {
        node.deploy(&guest("counter"), audit(), false, owner(&node))
            .await
            .unwrap();
        node.deploy(&guest("notes"), audit(), false, owner(&node))
            .await
            .unwrap();
        for i in 0..40 {
            if i == 20 {
                node.snapshot("manual", owner(&node)).await.unwrap();
            }
            let (actor, name, body) = if i % 2 == 0 {
                (format!("counter/c{}", i % 3), "increment", String::new())
            } else {
                (format!("notes/n{}", i % 4), "add", format!("note {i}"))
            };
            let r = node
                .send(
                    ActorRef::parse(&actor).unwrap(),
                    msg(name, &body),
                    audit(),
                    false,
                    owner(&node),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(r.committed(), "{r:?}");
        }
    });
    node.applied_lsn()
}

#[test]
fn the_check_replays_the_window_with_this_engine_and_passes() {
    let dir = tempdir();
    let head = workload(dir.path());
    let rt = rt();
    let checked = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(&env, dir.path(), Duration::from_secs(6 * 3600), 2, None)
                .await
        })
        .unwrap();
    let r = &checked.report;
    assert!(r.passed, "{}", String::from_utf8_lossy(&checked.diff_bytes));
    assert_eq!(r.schema, REPORT_SCHEMA);
    assert_eq!(
        (r.from_engine.as_str(), r.to_engine.as_str()),
        (ENGINE_VERSION, ENGINE_VERSION)
    );
    assert_eq!(r.checked_through_lsn, head);
    // Six hours back covers the whole run: the window starts before the
    // first turn, and the replay reads from the log's start.
    assert_eq!(r.root_inputs, 40);
    assert!(r.fork_lsn < head);
    // A short window starts later; the snapshot serves as its base.
    let short = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(&env, dir.path(), Duration::ZERO, 2, None).await
        })
        .unwrap();
    assert!(short.report.passed);
    assert_eq!(short.report.root_inputs, 1);
}

/// Sealed values in the window (privacy mode on, a message with a subject)
/// open with the data directory's keystore and master key, as the daemon
/// opens them; without them the replay cannot read its inputs.
#[test]
fn the_check_opens_sealed_values_with_the_directorys_keystore() {
    let dir = tempdir();
    workload(dir.path());
    let rt = rt();
    let node = start(&rt, dir.path()).unwrap();
    rt.block_on(async {
        node.set_privacy_mode(pb::PrivacyState::On, audit(), false, owner(&node))
            .await
            .unwrap();
        let mut m = msg("increment", "");
        m.body.as_mut().unwrap().subject = Some("user:1".into());
        let r = node
            .send(
                ActorRef::parse("counter/c9").unwrap(),
                m,
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
    });
    drop(node);
    let check = |sealer| {
        rt.block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(&env, dir.path(), Duration::from_secs(6 * 3600), 2, sealer)
                .await
        })
    };
    let err = check(None).err().unwrap();
    assert!(err.contains("KEYSTORE_INCOMPLETE"), "{err}");
    let sealer = rt
        .block_on(kronik_sched::offline_sealer(
            Env::real(rt.handle().clone()),
            dir.path(),
            Default::default(),
        ))
        .unwrap();
    assert!(sealer.is_some());
    let checked = check(sealer).unwrap();
    assert!(
        checked.report.passed,
        "{}",
        String::from_utf8_lossy(&checked.diff_bytes)
    );
    assert_eq!(checked.report.root_inputs, 41);
}

#[test]
fn another_engine_needs_a_passing_report_and_records_the_upgrade() {
    let dir = tempdir();
    let head = workload(dir.path());
    // Pretend an older engine wrote the data.
    let old = "kronik-0.0.1+wasmtime-1.0.0";
    {
        let db = rusqlite::Connection::open(dir.path().join("branches/main/state.db")).unwrap();
        db.execute("UPDATE meta SET v = ?1 WHERE k = 'engine_version'", [old])
            .unwrap();
    }
    let rt = rt();
    let err = start(&rt, dir.path()).err().unwrap();
    assert!(matches!(err, StartError::EngineMismatch(_)), "{err}");
    assert!(
        err.to_string().contains("kronik upgrade check --window 6h"),
        "{err}"
    );

    let report = UpgradeReport {
        schema: REPORT_SCHEMA.into(),
        from_engine: old.into(),
        to_engine: ENGINE_VERSION.into(),
        window_ms: 6 * 3_600_000,
        fork_lsn: 1,
        checked_through_lsn: head,
        root_inputs: 40,
        turns: 40,
        diff_hash: "b3:00".into(),
        unverifiable: 0,
        passed: true,
        checked_wall_ms: 0,
    };
    let path = report.write(dir.path()).unwrap();
    let node = start_when_released(&rt, dir.path());
    let mut upgrades = Vec::new();
    rt.block_on(node.reader().read(1, node.applied_lsn(), |c| {
        if let Record::EngineUpgrade(u) = c.record {
            upgrades.push(u);
        }
        Ok(())
    }))
    .unwrap();
    assert_eq!(upgrades.len(), 1);
    let u = &upgrades[0];
    assert_eq!(u.from_engine_version, old);
    assert_eq!(u.to_engine_version, ENGINE_VERSION);
    assert_eq!(u.checked_through_lsn, head);
    assert_eq!(
        u.check_report_hash,
        blake3::hash(&std::fs::read(&path).unwrap())
            .as_bytes()
            .to_vec()
    );
    // The record stays in the append-only log and in every audit export: its
    // reason names the report relative to the data directory, never by the
    // path of this machine.
    let reason = &u.audit.as_ref().unwrap().reason;
    assert_eq!(
        reason,
        &format!("engine upgrade checked by the upgrade report upgrade/{ENGINE_VERSION}.json")
    );
    assert!(
        !reason.contains(dir.path().to_str().unwrap()),
        "the reason holds the data directory: {reason}"
    );
    assert!(
        !reason
            .split_whitespace()
            .any(|word| Path::new(word).is_absolute()),
        "the reason holds an absolute path: {reason}"
    );
    assert_eq!(
        node.store().db().engine_version().unwrap().as_deref(),
        Some(ENGINE_VERSION)
    );
    drop(node);
    // From now on the data is this engine's: no second record.
    let node = start_when_released(&rt, dir.path());
    assert_eq!(node.applied_lsn(), head + 1);
}

#[test]
fn upgrade_replays_grant_and_revoke_but_fork_overrides_stay_fixed() {
    let dir = tempdir();
    let rt = rt();
    let node = start(&rt, dir.path()).unwrap();
    rt.block_on(async {
        node.deploy(&guest("counter"), audit(), false, owner(&node))
            .await
            .unwrap();
        node.secret_set(
            "key",
            b"upgrade-policy-test-key".to_vec(),
            &audit(),
            false,
            owner(&node),
        )
        .await
        .unwrap();
        let fork_lsn = node.applied_lsn();
        let actor = ActorRef::parse("counter/policy").unwrap();
        let denied = node
            .send(
                actor.clone(),
                msg("hmac", "key\ndata"),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!denied.committed());
        node.grant(
            "counter",
            "secret:key",
            None,
            None,
            kronik_effects::InForks::Recorded,
            audit(),
            false,
            owner(&node),
        )
        .await
        .unwrap();
        let allowed = node
            .send(
                actor.clone(),
                msg("hmac", "key\ndata"),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(allowed.committed());
        node.revoke("counter", "secret:key", audit(), false, owner(&node))
            .await
            .unwrap();
        let revoked = node
            .send(
                actor,
                msg("hmac", "key\ndata"),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!revoked.committed());
        let checked = kronik_fork::upgrade::check(
            node.env(),
            dir.path(),
            Duration::from_secs(6 * 3600),
            2,
            None,
        )
        .await
        .unwrap();
        assert!(checked.report.passed, "{:?}", checked.diff);
        assert_eq!(checked.report.root_inputs, 3);
        assert_eq!(checked.diff.summary.live, 0);

        let index = Arc::new(
            kronik_fork::ProductionIndex::load(node.reader(), fork_lsn, node.applied_lsn())
                .await
                .unwrap(),
        );
        let code = kronik_fork::fork_kinds(
            &index,
            fork_lsn,
            |hash| node.code().get(hash).map_err(|e| e.to_string()),
            &[],
        )
        .unwrap();
        let mut config = kronik_fork::config_at(&index, fork_lsn);
        config.apply(&Record::Grant(pb::Grant {
            epoch: 99,
            op: pb::GrantOp::Revoke as i32,
            kind: "counter".into(),
            capability: "secret:key".into(),
            ..Default::default()
        }));
        let setup = Arc::new(kronik_fork::ReplaySetup::recorded(
            "fixed-policy".into(),
            index,
            code.kinds,
            config,
            None,
        ));
        let replay = kronik_fork::run(
            node.env(),
            setup,
            &kronik_fork::diff::DiffOptions::default(),
            2,
            None,
            code.before,
            code.after,
            &[],
        )
        .await
        .unwrap();
        assert!(replay.diff.summary.changed);
        assert_eq!(replay.diff.summary.live, 0);
        let turns = replay.continuous.unwrap().turns();
        assert!(turns.iter().all(|t| t.record.config_epoch == 99));
        let effects: Vec<_> = turns.iter().flat_map(|t| &t.record.effects).collect();
        assert_eq!(effects.len(), 3);
        assert!(
            effects
                .iter()
                .all(|e| e.status == pb::EffectStatus::Denied as i32)
        );
    });
}

#[test]
fn upgrade_replays_recorded_code_across_a_same_kind_deployment() {
    let dir = tempdir();
    let rt = rt();
    let node = start(&rt, dir.path()).unwrap();
    rt.block_on(async {
        node.deploy(&guest("counter"), audit(), false, owner(&node))
            .await
            .unwrap();
        let actor = ActorRef::parse("counter/code").unwrap();
        let first = node
            .send(
                actor.clone(),
                msg("increment", ""),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(first.committed());
        let bytes = guest("counter-step2");
        let (hash, _, manifest) = node.prepare_code(&bytes, owner(&node)).await.unwrap();
        assert_ne!(node.deployed("counter").unwrap().code_hash, hash.0);
        node.switch_code(
            kronik_sched::CodeSwitch {
                kinds: vec![pb::KindVersion {
                    kind: manifest.kind.clone(),
                    code_hash: hash.0.to_vec(),
                    schema_version: manifest.schema_version,
                    manifest: Some(manifest),
                    code_size: bytes.len() as u64,
                }],
                pinned: vec![node.deployed("counter").unwrap()],
                cause: pb::DeploymentCause::Promote,
                verified_through_lsn: node.applied_lsn(),
                unverified_inputs: 0,
                proposal_id: "checked-code-transition".into(),
                rollback_of_epoch: 0,
            },
            audit(),
            false,
            owner(&node),
        )
        .await
        .unwrap();
        let second = node
            .send(actor, msg("increment", ""), audit(), false, owner(&node))
            .await
            .unwrap()
            .unwrap();
        assert!(second.committed());
        let checked = kronik_fork::upgrade::check(
            node.env(),
            dir.path(),
            Duration::from_secs(6 * 3600),
            2,
            None,
        )
        .await
        .unwrap();
        assert!(checked.report.passed, "{:?}", checked.diff);
        assert_eq!(checked.report.root_inputs, 2);
        assert_eq!(checked.diff.summary.live, 0);
    });
}

// ---------------------------------------------------------------- S-16

/// A message whose body is tagged with `subject`: the turn's default subject,
/// so the effects it records are sealed for that subject.
fn subject_msg(name: &str, body: &str, subject: &str) -> pb::Message {
    let mut m = msg(name, body);
    m.body.as_mut().unwrap().subject = Some(subject.into());
    m
}

/// Privacy mode on; one turn whose `http.fetch` request is sealed for
/// `user:1` (the target refuses the connection, so nothing listens), the
/// subject erased, then one new turn with no subject. Returns the erasure
/// snapshot's LSN.
fn erased_workload(rt: &Runtime, dir: &Path) -> u64 {
    let node = start(rt, dir).unwrap();
    let erased = rt.block_on(async {
        node.deploy(&guest("counter"), audit(), false, owner(&node))
            .await
            .unwrap();
        node.grant(
            "counter",
            "http:127.0.0.1",
            None,
            None,
            kronik_effects::InForks::Recorded,
            audit(),
            false,
            owner(&node),
        )
        .await
        .unwrap();
        node.set_privacy_mode(pb::PrivacyState::On, audit(), false, owner(&node))
            .await
            .unwrap();
        let r = node
            .send(
                ActorRef::parse("counter/bob").unwrap(),
                subject_msg("fetch-ok", "GET http://127.0.0.1:1/hook", "user:1"),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
        let done = node
            .erase_subject("user:1", audit(), false, owner(&node))
            .await
            .unwrap();
        let erased = done.lsn.unwrap();
        // The window is chosen against the gap between the erased turn and
        // this one, so make it unambiguous.
        std::thread::sleep(Duration::from_millis(50));
        let r = node
            .send(
                ActorRef::parse("counter/k9").unwrap(),
                msg("increment", ""),
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
        erased
    });
    drop(node);
    erased
}

/// Evidence hook: `KRONIK_S16_KEEP=<directory>` keeps the S-16 fixture instead
/// of deleting it with the temporary directory (drafts/16 §7 reproduction).
fn keep(dir: &tempfile::TempDir, name: &str) {
    let Ok(root) = std::env::var("KRONIK_S16_KEEP") else {
        return;
    };
    let dest = Path::new(&root).join(name);
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::rename(dir.path(), &dest).unwrap();
}

fn check_dir(rt: &Runtime, dir: &Path, window: Duration) -> kronik_fork::upgrade::Checked {
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let sealer = kronik_sched::offline_sealer(env.clone(), dir, Default::default())
            .await
            .unwrap();
        assert!(sealer.is_some(), "privacy mode left no keystore");
        kronik_fork::upgrade::check(&env, dir, window, 2, sealer)
            .await
            .unwrap()
    })
}

/// S-16 (1): a sealed request whose subject was erased is replayed from its
/// recording and reported, not declared divergent. A window shorter than the
/// gap to the erased turn skips it and reports nothing - that is the v0.4.1
/// workaround, still passing.
#[test]
fn an_erased_request_is_unverifiable_not_divergence() {
    let dir = tempdir();
    let rt = rt();
    let _erased = erased_workload(&rt, dir.path());

    let long = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    assert!(
        long.report.passed,
        "{}",
        String::from_utf8_lossy(&long.diff_bytes)
    );
    assert_eq!(long.report.root_inputs, 2);
    assert_eq!(long.diff.summary.divergent_turns, 0);
    assert_eq!(long.report.unverifiable, 1);
    assert_eq!(long.diff.summary.unverifiable, 1);
    assert_eq!(long.diff.effects.removed, 0);
    assert_eq!(long.diff.effects.added, 0);

    let short = check_dir(&rt, dir.path(), Duration::from_millis(10));
    assert!(short.report.passed, "{:?}", short.report);
    assert_eq!(short.report.root_inputs, 1);
    assert_eq!(short.report.unverifiable, 0);
    keep(&dir, "erased-only");
}

/// Issue #16 (ADR 0109 points 3-5): an erased turn that committed a state or
/// SQL write in production and does not reproduce it from `[erased]` is
/// unverifiable, not a behavior change. The write is not counted in either
/// state section, so the check passes and `serve` keeps accepting the
/// directory.
#[test]
fn an_erased_turns_state_write_is_not_a_change() {
    let dir = tempdir();
    let rt = rt();
    {
        let node = start(&rt, dir.path()).unwrap();
        rt.block_on(async {
            node.deploy(&guest("counter"), audit(), false, owner(&node))
                .await
                .unwrap();
            node.deploy(&guest("notes"), audit(), false, owner(&node))
                .await
                .unwrap();
            node.set_privacy_mode(pb::PrivacyState::On, audit(), false, owner(&node))
                .await
                .unwrap();
            // The note's body is sealed for user:1, so the turn's recorded
            // input is erased with the subject; production commits the insert.
            let r = node
                .send(
                    ActorRef::parse("notes/n1").unwrap(),
                    subject_msg("add", "note text", "user:1"),
                    audit(),
                    false,
                    owner(&node),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(r.committed(), "{r:?}");
            node.erase_subject("user:1", audit(), false, owner(&node))
                .await
                .unwrap();
            // Make the default window unambiguous about the gap.
            std::thread::sleep(Duration::from_millis(50));
            let r = node
                .send(
                    ActorRef::parse("counter/k9").unwrap(),
                    msg("increment", ""),
                    audit(),
                    false,
                    owner(&node),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(r.committed(), "{r:?}");
        });
    }
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    assert!(
        checked.report.passed,
        "{}",
        String::from_utf8_lossy(&checked.diff_bytes)
    );
    assert_eq!(checked.report.root_inputs, 2);
    assert_eq!(checked.report.unverifiable, 1);
    assert_eq!(checked.diff.summary.unverifiable, 1);
    assert_eq!(checked.diff.summary.divergent_turns, 0);
    assert!(!checked.diff.summary.changed);
    assert!(
        checked.diff.state.isolated.is_empty(),
        "{:?}",
        checked.diff.state.isolated
    );
    assert!(
        checked.diff.state.continuous.is_empty(),
        "{:?}",
        checked.diff.state.continuous
    );
    keep(&dir, "erased-state");
}

/// One step of a privacy workload (the erasure tests, issue #48).
enum Step<'a> {
    /// A message to `actor` running `op` on `body`, sealed for `subject`
    /// when there is one. It must commit, and every message it sends is
    /// consumed before the next step, so production holds its whole tree.
    Send(&'a str, &'a str, &'a str, Option<&'a str>),
    /// `privacy erase <subject>`.
    Erase(&'a str),
    /// Logical time passes: a window can start after the steps before.
    Pause(Duration),
}

/// Waits until the turn at `lsn` is applied and every message committed so
/// far is consumed: the mailbox holds a message from its sender's apply to
/// its receiver's, in the same transaction as the receiver's own sends.
async fn settle(node: &Node, lsn: u64) {
    node.store().applied.wait(lsn).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let idle = {
            let db = node.store().db();
            db.mailbox().unwrap().is_empty() && db.open_turns().unwrap().is_empty()
        };
        if idle {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the workload's messages were not consumed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Deploys `guests`, turns privacy mode on and runs `steps`.
fn privacy_workload(rt: &Runtime, dir: &Path, guests: &[&str], steps: &[Step<'_>]) {
    let node = start(rt, dir).unwrap();
    rt.block_on(async {
        for g in guests {
            node.deploy(&guest(g), audit(), false, owner(&node))
                .await
                .unwrap();
        }
        node.set_privacy_mode(pb::PrivacyState::On, audit(), false, owner(&node))
            .await
            .unwrap();
        for step in steps {
            match step {
                Step::Send(actor, op, body, subject) => {
                    let m = match subject {
                        Some(s) => subject_msg(op, body, s),
                        None => msg(op, body),
                    };
                    let r = node
                        .send(
                            ActorRef::parse(actor).unwrap(),
                            m,
                            audit(),
                            false,
                            owner(&node),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(r.committed(), "{actor} {op}: {r:?}");
                    settle(&node, r.turn_id.lsn).await;
                }
                Step::Erase(subject) => {
                    let done = node
                        .erase_subject(subject, audit(), false, owner(&node))
                        .await
                        .unwrap();
                    settle(&node, done.lsn.unwrap()).await;
                }
                Step::Pause(d) => tokio::time::sleep(*d).await,
            }
        }
    });
    drop(node);
}

/// Appends a crafted recording of a turn the guest cannot reproduce: a root
/// `increment` that claims to have failed, with no effects and no writes. A
/// replay of it is a verified difference (S-16 (2)).
fn forge_failed_increment(rt: &Runtime, dir: &Path) {
    let node = start_when_released(rt, dir);
    let head = node.applied_lsn();
    let (hash, input, epoch) = rt.block_on(async {
        let mut hash = Vec::new();
        let mut input = None;
        let mut epoch = 0;
        node.reader()
            .read(1, head, |c| {
                match &c.record {
                    Record::Deployment(d) => {
                        for k in &d.kinds {
                            if k.kind == "counter" {
                                hash = k.code_hash.clone();
                            }
                        }
                    }
                    Record::TurnRecord(t) if input.is_none() => {
                        let msg = match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
                            Some(pb::input::Kind::Message(m)) => m.msg.as_ref(),
                            _ => None,
                        };
                        if msg.is_some_and(|m| m.name == "increment") {
                            input = t.input.clone();
                            epoch = t.config_epoch;
                        }
                    }
                    _ => {}
                }
                Ok(())
            })
            .await
            .unwrap();
        (hash, input.unwrap(), epoch)
    });
    drop(node);
    let forged = pb::TurnRecord {
        execution_id: String::new(),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: "forged".into(),
        }),
        code_hash: hash,
        engine_version: ENGINE_VERSION.into(),
        causal_key: Some(pb::CausalKey {
            root: "forged-root".into(),
            path: Vec::new(),
        }),
        logical_time_ms: 0,
        random_seed: vec![0u8; 32],
        input: Some(input),
        effects: Vec::new(),
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            error_code: "TURN_FAILED".into(),
            message: "forged: the recording says this failed".into(),
            output: None,
        }),
        config_epoch: epoch,
        ..Default::default()
    };
    append(rt, dir, forged);
}

/// Appends `record` to the log of the stopped node in `dir`.
fn append(rt: &Runtime, dir: &Path, record: pb::TurnRecord) {
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (fatal, _fatal_rx) = tokio::sync::oneshot::channel();
        let (log, _) = kronik_log::Log::open(
            &env,
            kronik_log::LogConfig::new(dir.join("branches").join("main").join("log"), "main"),
            tx,
            fatal,
        )
        .await
        .unwrap();
        log.append(Record::TurnRecord(record)).await.unwrap();
        drop(log);
        drop(rx);
    });
}

/// The first recorded turn of `actor` that ran the message `op`.
fn recorded_turn(rt: &Runtime, dir: &Path, actor: &str, op: &str) -> pb::TurnRecord {
    let node = start_when_released(rt, dir);
    let head = node.applied_lsn();
    let found = rt.block_on(async {
        let mut found = None;
        node.reader()
            .read(1, head, |c| {
                if let Record::TurnRecord(t) = &c.record
                    && found.is_none()
                    && t.actor
                        .as_ref()
                        .is_some_and(|a| format!("{}/{}", a.kind, a.key) == actor)
                    && matches!(
                        t.input.as_ref().and_then(|i| i.kind.as_ref()),
                        Some(pb::input::Kind::Message(m))
                            if m.msg.as_ref().is_some_and(|m| m.name == op)
                    )
                {
                    found = Some(t.clone());
                }
                Ok(())
            })
            .await
            .unwrap();
        found
    });
    drop(node);
    found.unwrap_or_else(|| panic!("no recorded {op} of {actor}"))
}

/// A crafted recording of a root turn like the recorded `op` of `actor`,
/// under its own root, that claims to have failed: the replay of it, which
/// commits, is a verified difference.
fn forge_failed(rt: &Runtime, dir: &Path, actor: &str, op: &str) {
    let mut t = recorded_turn(rt, dir, actor, op);
    t.execution_id = String::new();
    t.causal_key = Some(pb::CausalKey {
        root: format!("forged-{op}"),
        path: Vec::new(),
    });
    t.effects.clear();
    t.writes.clear();
    t.messages.clear();
    t.timers.clear();
    t.sql_changes.clear();
    t.sql_schema.clear();
    t.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        message: "forged: the recording says this failed".into(),
        output: None,
    });
    append(rt, dir, t);
}

/// Issue #27 (workload d4b): an erased turn that wrote a state value sealed
/// for the subject is unverifiable; its write is no change in either state
/// section, so the check passes. A real divergence next to it still fails.
#[test]
fn an_erased_turns_state_value_is_no_change_but_a_real_divergence_fails() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            // `s` sealed for user:1 and `t` for user:2.
            Step::Send("counter/a", "subject", "", Some("user:1")),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(checked.report.root_inputs, 2);
    assert_eq!(checked.report.unverifiable, 1, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 0, "{text}");
    assert!(!checked.diff.summary.changed);
    assert!(checked.diff.state.isolated.is_empty(), "{text}");
    assert!(checked.diff.state.continuous.is_empty(), "{text}");

    forge_failed_increment(&rt, dir.path());
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(!checked.report.passed, "{text}");
    assert!(checked.diff.summary.changed);
    assert_eq!(checked.diff.summary.unverifiable, 1, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 1, "{text}");
    keep(&dir, "erased-kv-and-real");
}

/// Issue #28 (workload d3): the erased body of `fanout` decided how many
/// messages production sent. The replay sends none, and the five production
/// turns missing below the erased root are unverifiable like it: no
/// divergence, no origin, no consequence, no cause.
#[test]
fn production_turns_missing_below_an_erased_turn_are_unverifiable() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            Step::Send("counter/src", "fanout", "5", Some("user:1")),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(d.summary.turns_prod, 7, "{text}");
    assert_eq!(d.summary.divergent_turns, 0, "{text}");
    assert_eq!(
        (d.summary.origins, d.summary.consequences),
        (0, 0),
        "{text}"
    );
    assert!(d.causes.is_empty(), "{text}");
    assert!(d.samples.origins.is_empty() && d.samples.consequences.is_empty());
    assert_eq!(d.summary.unverifiable, 6, "{text}");
    assert_eq!(checked.report.unverifiable, 6);
    assert_eq!(d.effects.removed + d.effects.added + d.effects.changed, 0);
    keep(&dir, "erased-fanout");
}

/// A timer of the erased subject is pending at the fork point. Its body in
/// the fork's store is a tombstone since the erasure, which the replay
/// handed to the guest still sealed: the check failed for a missing key.
/// The body reads `[erased]` now, and the timer's turn (a SUBJECT_ERASED
/// dead letter in production) is unverifiable.
#[test]
fn a_timer_of_an_erased_subject_pending_at_the_fork_point_is_unverifiable() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            // `store` the body in 2.5 s, for user:1.
            Step::Send(
                "counter/t",
                "schedule",
                "2500 store\nNEEDLE",
                Some("user:1"),
            ),
            Step::Erase("user:1"),
            Step::Pause(Duration::from_millis(800)),
            Step::Send("counter/k1", "increment", "", None),
            // The timer fires here.
            Step::Pause(Duration::from_millis(2500)),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    // The window starts at `counter/k1`: after the erasure, before the timer.
    let checked = check_dir(&rt, dir.path(), Duration::from_millis(3000));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert_eq!(checked.report.root_inputs, 2, "{text}");
    assert!(checked.report.passed, "{text}");
    assert_eq!(d.summary.unverifiable, 1, "the timer's turn: {text}");
    assert_eq!(d.summary.divergent_turns, 0, "{text}");
    keep(&dir, "erased-pending-timer");
}

/// Issue #29 (workload d2, SQL): the replay skips the erased subject's
/// changeset, so until the erasure the actor database lacks a row that
/// production's `count` read. That `count` is unverifiable, not divergent;
/// the `count` after the erasure reads what production read and is verified.
#[test]
fn rows_an_erasure_removed_do_not_make_a_reader_diverge() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["notes"],
        &[
            Step::Send("notes/n1", "add", "note text", Some("user:1")),
            Step::Send("notes/n1", "count", "", None),
            Step::Erase("user:1"),
            Step::Send("notes/n1", "count", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(checked.report.root_inputs, 3);
    assert_eq!(d.summary.divergent_turns, 0, "{text}");
    assert_eq!(d.summary.origins, 0, "{text}");
    assert_eq!(d.responses.changed, 0, "{text}");
    // The erased `add` and the `count` that read its row.
    assert_eq!(d.summary.unverifiable, 2, "{text}");
    assert!(d.state.isolated.is_empty() && d.state.continuous.is_empty());
    keep(&dir, "erased-sql-reader");
}

/// Issue #29 (KV): the erased body of `forward` named the actor production
/// incremented. The replay increments another one, so production's write
/// to `counter/k2` is missing from the fork's state, and the `get` that read
/// it is unverifiable rather than a verified divergence, in both modes.
#[test]
fn a_reader_of_state_an_erased_turn_shaped_is_unverifiable() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            Step::Send("counter/w", "forward", "k2", Some("user:1")),
            Step::Send("counter/k2", "get", "", None),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(d.summary.divergent_turns, 0, "{text}");
    assert_eq!(d.responses.changed, 0, "{text}");
    // `forward`, the turn its message started (on another actor in the
    // replay) and the `get`.
    assert_eq!(d.summary.unverifiable, 3, "{text}");
    keep(&dir, "erased-kv-reader");
}

/// Issue #49: an erased state value reads as absent in a fork and marks the
/// turn that read it, also when the value was written inside the replayed
/// log: the writer and the reader are unverifiable (before, the reader got
/// the 8 bytes `[erased]` as present data, as long as the value it had read).
#[test]
fn a_reader_of_an_erased_state_value_is_unverifiable() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter-fetch-extra"],
        &[
            // `s` is "personal", sealed for user:1; `read` replies its length.
            Step::Send("counter/a", "subject", "", Some("user:1")),
            Step::Send("counter/a", "read", "", None),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(d.summary.divergent_turns, 0, "{text}");
    assert_eq!(d.summary.unverifiable, 2, "{text}");
    keep(&dir, "erased-value-reader");
}

/// Issue #29: the window starts after a turn wrote a value of the subject
/// and before its erasure. Production's erasure deletes the value; the
/// continuous replay follows that erasure, so the final states agree.
#[test]
fn an_erasure_in_the_window_removes_state_written_before_it() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            Step::Send("counter/a", "subject", "", Some("user:1")),
            Step::Pause(Duration::from_millis(600)),
            Step::Send("counter/k1", "increment", "", None),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    // The window holds the last two root inputs, not the write.
    let checked = check_dir(&rt, dir.path(), Duration::from_millis(300));
    let d = &checked.diff;
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert_eq!(checked.report.root_inputs, 2, "{text}");
    assert!(checked.report.passed, "{text}");
    assert!(d.state.continuous.is_empty(), "{text}");
    assert_eq!(d.summary.unverifiable, 0, "{text}");
    keep(&dir, "erased-before-window");
}

/// S-16 (5): the replay serves the recorded outcome of an erased request - an
/// exact effect, not a synthetic denial the guest has to handle.
#[test]
fn replay_serves_the_recorded_outcome_of_an_erased_request() {
    let dir = tempdir();
    let rt = rt();
    erased_workload(&rt, dir.path());
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let fetch = checked
        .diff
        .grounding
        .iter()
        .find(|g| g.kind == "http.fetch")
        .expect("no http.fetch grounding row");
    assert_eq!(fetch.exact, 1, "{fetch:?}");
    assert_eq!((fetch.approximate, fetch.synthetic, fetch.live), (0, 0, 0));
    assert_eq!(checked.diff.summary.synthetic, 0);
    assert_eq!(checked.diff.summary.exact, 1);
}

/// S-16 (3): an erased request whose recorded outcome was a failure does not
/// become a divergence: the failure is replayed, not recomputed.
#[test]
fn an_erased_request_with_a_recorded_failure_is_not_divergence() {
    let dir = tempdir();
    let rt = rt();
    {
        let node = start(&rt, dir.path()).unwrap();
        rt.block_on(async {
            node.deploy(&guest("counter"), audit(), false, owner(&node))
                .await
                .unwrap();
            node.grant(
                "counter",
                "http:127.0.0.1",
                None,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                owner(&node),
            )
            .await
            .unwrap();
            node.set_privacy_mode(pb::PrivacyState::On, audit(), false, owner(&node))
                .await
                .unwrap();
            // `fetch` fails its turn on a fetch error; the target refuses, so
            // the turn and the recorded outcome both fail.
            let r = node
                .send(
                    ActorRef::parse("counter/bob").unwrap(),
                    subject_msg("fetch", "GET http://127.0.0.1:1/hook", "user:1"),
                    audit(),
                    false,
                    owner(&node),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(!r.committed(), "{r:?}");
            node.erase_subject("user:1", audit(), false, owner(&node))
                .await
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let r = node
                .send(
                    ActorRef::parse("counter/k9").unwrap(),
                    msg("increment", ""),
                    audit(),
                    false,
                    owner(&node),
                )
                .await
                .unwrap()
                .unwrap();
            assert!(r.committed(), "{r:?}");
        });
    }
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    assert!(
        checked.report.passed,
        "{}",
        String::from_utf8_lossy(&checked.diff_bytes)
    );
    assert_eq!(checked.report.root_inputs, 2);
    assert_eq!(checked.report.unverifiable, 1);
    assert_eq!(checked.diff.summary.divergent_turns, 0);
}

/// S-16 (2): the erased turn is unverifiable, but it is not amnesty: a second
/// turn whose recording and replay genuinely differ still fails the check.
#[test]
fn a_real_divergence_still_fails_next_to_an_unverifiable_turn() {
    let dir = tempdir();
    let rt = rt();
    erased_workload(&rt, dir.path());
    let passed = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    assert!(passed.report.passed);
    assert_eq!(passed.report.unverifiable, 1);
    forge_failed_increment(&rt, dir.path());

    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    assert!(!checked.report.passed, "{:?}", checked.report);
    assert!(
        checked.report.unverifiable >= 1,
        "the erased turn is still unverifiable: {:?}",
        checked.report
    );
    assert_eq!(checked.diff.summary.unverifiable, 1);
    assert!(checked.diff.summary.changed);
    assert!(
        checked.diff.summary.divergent_turns >= 1,
        "{}",
        String::from_utf8_lossy(&checked.diff_bytes)
    );
    keep(&dir, "erased-and-real");
}

/// Issue #73 (a), ADR 0109 point 7: notes/n1's
/// database has a table without `_subject`, and user:1's rows in its `notes`
/// table were erased in the window. This engine refuses a subject's write
/// to a table without `_subject`, so the erasure leaves both sides equal:
/// the actor's later SQL turns are verified, and a real change in one fails
/// the check. Before, every later SQL turn of the actor was unverifiable,
/// and the check passed.
#[test]
fn a_real_change_in_a_later_sql_turn_of_an_actor_with_an_erased_subject_fails() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["notes-untagged"],
        &[
            Step::Send("notes/n1", "add", "note text", Some("user:1")),
            Step::Erase("user:1"),
            Step::Send("notes/n1", "count", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    // Only the turn whose input was erased.
    assert_eq!(checked.report.unverifiable, 1, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 0, "{text}");

    forge_failed(&rt, dir.path(), "notes/n1", "count");
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(!checked.report.passed, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 1, "{text}");
    assert_eq!(checked.diff.summary.unverifiable, 1, "{text}");
    keep(&dir, "erased-sql-untagged-table");
}

/// Issue #73 (b), ADR 0109 point 9: a turn
/// whose input is intact wrote `s` sealed for user:1, erased later. Its
/// guest read nothing erased, so it is replayed and compared like any other
/// turn, except for user:1's values, which no one can read again: it is not
/// unverifiable, and a real change in it (here its reply) fails the check.
/// Before, the erased write made the whole turn unverifiable, and the check
/// passed.
#[test]
fn a_turn_whose_outputs_alone_hold_an_erased_value_is_compared() {
    let dir = tempdir();
    let rt = rt();
    privacy_workload(
        &rt,
        dir.path(),
        &["counter"],
        &[
            // No subject on the input: `s` is sealed for user:1, `t` for
            // user:2.
            Step::Send("counter/a", "subject", "", None),
            Step::Erase("user:1"),
            Step::Send("counter/k9", "increment", "", None),
        ],
    );
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(checked.report.passed, "{text}");
    assert_eq!(checked.report.unverifiable, 0, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 0, "{text}");

    // The same turn, recorded with a reply the code does not give.
    let mut t = recorded_turn(&rt, dir.path(), "counter/a", "subject");
    t.execution_id = String::new();
    t.causal_key = Some(pb::CausalKey {
        root: "forged-reply".into(),
        path: Vec::new(),
    });
    let Some(pb::outcome::Output::Reply(reply)) =
        t.outcome.as_mut().and_then(|o| o.output.as_mut())
    else {
        panic!("no reply: {:?}", t.outcome)
    };
    reply.body = Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b"forged".to_vec())),
    });
    append(&rt, dir.path(), t);
    let checked = check_dir(&rt, dir.path(), Duration::from_secs(6 * 3600));
    let text = String::from_utf8_lossy(&checked.diff_bytes);
    assert!(!checked.report.passed, "{text}");
    assert_eq!(checked.diff.summary.divergent_turns, 1, "{text}");
    assert_eq!(checked.diff.summary.unverifiable, 0, "{text}");
    keep(&dir, "erased-output-only");
}
