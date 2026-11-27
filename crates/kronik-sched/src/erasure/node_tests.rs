//! An erasure and the plaintext of its subject already in flight
//! (docs/design/m8-privacy.md §6.8, ADR 0123).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;

use crate::test_support::{COUNTER, audit};
use crate::{Born, ForkSealHold, Node, NodeConfig};

fn message(name: &str, body: &str, subject: Option<&str>) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: subject.map(str::to_owned),
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: Vec::new(),
        retained_compensation_source: None,
    }
}

/// A value a fork copies from production predates the subject's erasure even
/// when the subject has since come back with a newer key: the copy is the
/// erasure's tombstone, while a value born after the erasure still seals
/// under the newer key and opens (ADR 0123 §3, §6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copied_value_of_a_come_back_subject_is_the_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let node = counter_node(dir.path()).await;
    let authority = node.local_operator_authority().unwrap();
    // Mode off: the erasure is recorded with no key version.
    let erased = node
        .erase_subject("user:1", audit(), false, authority.clone())
        .await
        .unwrap();
    assert_eq!(erased.key_version, 0);
    let erased_lsn = erased.lsn.unwrap();
    // The subject comes back: a post-erasure value creates key version 1.
    node.set_privacy_mode(pb::PrivacyState::On, audit(), false, authority)
        .await
        .unwrap();
    let fill = |b: &mut [u8]| b.fill(7);

    let copied = |needle: &[u8]| {
        Record::TurnRecord(pb::TurnRecord {
            writes: vec![pb::StateWrite {
                key: "n".into(),
                op: pb::StateOp::Set as i32,
                value: Some(pb::Sealable {
                    subject: Some("user:1".into()),
                    value: Some(pb::sealable::Value::Plain(needle.to_vec())),
                }),
            }],
            ..Default::default()
        })
    };

    // A fork computes a new value before the subject has come back: it is
    // still the erasure's tombstone, and creates no key version.
    let mut computed = copied(b"FORK-COMPUTED");
    drop(
        node.seal_fork_record(&mut computed, node.born_now())
            .await
            .unwrap(),
    );
    let Record::TurnRecord(t) = &computed else {
        unreachable!()
    };
    let value = t.writes[0].value.as_ref().unwrap();
    assert_eq!(
        value.value,
        Some(pb::sealable::Value::Sealed(
            kronik_privacy::sealer::erased_value(0)
        ))
    );
    assert_eq!(
        node.sealer()
            .keystore()
            .unwrap()
            .newest_version("user:1")
            .unwrap(),
        None,
        "a fork created a key version for an erased subject"
    );

    // The subject comes back: a post-erasure value creates key version 1.
    let mut fresh = pb::Sealable {
        subject: Some("user:1".into()),
        value: Some(pb::sealable::Value::Plain(b"NEW".to_vec())),
    };
    node.sealer().seal_value(&mut fresh, &fill, 1).unwrap();
    let version = match fresh.value.as_ref() {
        Some(pb::sealable::Value::Sealed(s)) => s.key_version,
        other => panic!("not sealed: {other:?}"),
    };
    assert_eq!(version, 1);

    // Written before the erasure: it becomes the erasure's tombstone even
    // though version 1 exists now.
    let mut before = copied(b"NEEDLE");
    drop(
        node.seal_fork_record(&mut before, Born::Lsn(erased_lsn - 1))
            .await
            .unwrap(),
    );
    let Record::TurnRecord(t) = &before else {
        unreachable!()
    };
    let value = t.writes[0].value.as_ref().unwrap();
    assert_eq!(
        value.value,
        Some(pb::sealable::Value::Sealed(
            kronik_privacy::sealer::erased_value(0)
        ))
    );
    assert!(matches!(
        node.sealer().open(value),
        kronik_privacy::sealer::Opened::Erased { ref subject } if subject == "user:1"
    ));

    // The control: a genuinely new post-erasure value seals under version 1
    // and opens.
    let mut after = copied(b"NEEDLE-AFTER");
    drop(
        node.seal_fork_record(&mut after, Born::Lsn(erased_lsn + 1))
            .await
            .unwrap(),
    );
    let Record::TurnRecord(t) = &after else {
        unreachable!()
    };
    let value = t.writes[0].value.as_ref().unwrap();
    assert!(matches!(
        value.value.as_ref(),
        Some(pb::sealable::Value::Sealed(s)) if s.key_version == 1
    ));
    assert_eq!(
        node.sealer().open(value).into_owned().as_deref(),
        Some(&b"NEEDLE-AFTER"[..])
    );
}

/// Issue #125: a fork's seal takes the erasure fence before its tombstone
/// check and key-version creation. An erasure that begins while the seal is
/// between them waits for the seal instead of deleting the keys first, so
/// the key the seal creates is one the erasure removes: the value is never
/// sealed under a version above the erasure's floor and left readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fork_seal_in_flight_is_not_outrun_by_an_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let hold = Arc::new(ForkSealHold::default());
    let node = crate::start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig {
            test_hold_fork_seal: Some(hold.clone()),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let authority = node.local_operator_authority().unwrap();
    node.set_privacy_mode(pb::PrivacyState::On, audit(), false, authority.clone())
        .await
        .unwrap();
    let born = node.born_now();
    let mut record = Record::TurnRecord(pb::TurnRecord {
        writes: vec![pb::StateWrite {
            key: "n".into(),
            op: pb::StateOp::Set as i32,
            value: Some(pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Plain(b"FORK-NEEDLE".to_vec())),
            }),
        }],
        ..Default::default()
    });
    let sealing = {
        let node = node.clone();
        tokio::spawn(async move {
            let _fence = node.seal_fork_record(&mut record, born).await.unwrap();
            record
        })
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        while hold.arrived.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The seal holds the read side of the fence at the hook. A write guard
    // here would mean the erasure could delete the keys first, and the seal
    // then create a key version above its floor.
    assert!(
        node.erase_lock.try_write().is_err(),
        "the fork seal does not hold the erasure fence between its check and its key"
    );
    // The seal has passed its erasure checks and holds the read side of the
    // fence. An erasure must wait, not delete the keys before the seal loads
    // them.
    let mut erasing = tokio::spawn({
        let node = node.clone();
        let authority = authority.clone();
        async move {
            node.erase_subject("user:1", audit(), false, authority)
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut erasing)
            .await
            .is_err(),
        "an erasure ran between the fork's check and its sealing key"
    );
    hold.release.add_permits(1);
    let record = sealing.await.unwrap();
    let erased = erasing.await.unwrap().unwrap();
    // The fork created key version 1 while it held the fence; the erasure
    // that followed deleted it through that version, so no version at or
    // above the floor is left readable.
    assert_eq!(
        erased.key_version, 1,
        "the erasure did not cover the fork's sealing key"
    );
    assert_eq!(
        node.sealer()
            .keystore()
            .unwrap()
            .newest_version("user:1")
            .unwrap(),
        None,
        "a key version of the erased subject survived"
    );
    let Record::TurnRecord(t) = &record else {
        unreachable!()
    };
    let value = t.writes[0].value.as_ref().unwrap();
    assert!(
        matches!(
            value.value.as_ref(),
            Some(pb::sealable::Value::Sealed(s)) if s.key_version == 1
        ),
        "the fork sealed under another key version: {value:?}"
    );
    assert!(
        matches!(
            node.sealer().open(value),
            kronik_privacy::sealer::Opened::Erased { ref subject } if subject == "user:1"
        ),
        "the fork's pre-erasure plaintext opened after the erasure"
    );
    assert_eq!(node.pending_erasures().await.unwrap(), 0);
}

/// An HTTP server on an ephemeral port that answers its first request only
/// once `release` is sent; `arrived` tells that the request came.
struct Held {
    addr: String,
    arrived: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

fn held_server() -> Held {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (arrived_tx, arrived) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = arrived_tx.send(());
            let _ = release_rx.recv();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    Held {
        addr,
        arrived,
        release,
    }
}

async fn counter_node(dir: &std::path::Path) -> Arc<Node> {
    let node = crate::start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir,
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let authority = node.local_operator_authority().unwrap();
    node.deploy(
        &std::fs::read(COUNTER).unwrap(),
        audit(),
        false,
        authority.clone(),
    )
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
        authority,
    )
    .await
    .unwrap();
    node
}

fn queued(node: &Node, actor: &ActorRef) -> usize {
    node.queued_jobs(actor)
}

/// Every key version the keystore holds for `subject`, as the log names them:
/// the versions of the sealed values in records after `after`.
async fn sealed_versions(node: &Node, subject: &str, after: u64) -> Vec<u32> {
    let mut versions = Vec::new();
    node.reader()
        .read(after + 1, node.applied_lsn(), |mut c| {
            kronik_proto::sealables::record_mut(&mut c.record, &mut |s| {
                if s.subject.as_deref() == Some(subject)
                    && let Some(pb::sealable::Value::Sealed(x)) = &s.value
                {
                    versions.push(x.key_version);
                }
            });
            Ok(())
        })
        .await
        .unwrap();
    versions
}

/// Privacy mode on. counter/b runs a turn of user:1 that waits for an HTTP
/// answer, and a message of user:1 waits behind it in counter/b's queue.
/// `privacy erase user:1` returns while the turn still waits, and `privacy
/// status` counts the erasure as pending; then the HTTP server answers. The
/// running turn commits with the erasure's tombstones in place of its values
/// of user:1; the queued message never reaches the guest (a SUBJECT_ERASED
/// dead letter whose record holds the tombstone); no key version of user:1
/// is created after its erasure; and the erasure is complete. Before, the
/// running turn's record and the queued message's value were sealed under a
/// new key version of user:1, and the guest stored the value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plaintext_in_flight_at_an_erasure_reaches_no_guest_and_no_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let node = counter_node(dir.path()).await;
    let authority = node.local_operator_authority().unwrap();
    node.set_privacy_mode(pb::PrivacyState::On, audit(), false, authority.clone())
        .await
        .unwrap();
    let start = node.applied_lsn();
    let server = held_server();
    let b = ActorRef::parse("counter/b").unwrap();
    let running = {
        let (node, b, authority) = (node.clone(), b.clone(), authority.clone());
        let spec = format!("GET http://{}/hold", server.addr);
        tokio::spawn(async move {
            node.send(
                b,
                message("fetch-ok", &spec, Some("user:1")),
                audit(),
                false,
                authority,
            )
            .await
        })
    };
    let arrived = server.arrived;
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)).unwrap())
        .await
        .unwrap();
    let waiting = {
        let (node, b, authority) = (node.clone(), b.clone(), authority.clone());
        tokio::spawn(async move {
            node.send(
                b,
                message("store", "NEEDLE-IN-FLIGHT", Some("user:1")),
                audit(),
                false,
                authority,
            )
            .await
        })
    };
    node.env
        .timeout(Duration::from_secs(30), async {
            while queued(&node, &b) == 0 {
                node.env.clock.sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    let erased = node
        .erase_subject("user:1", audit(), false, authority.clone())
        .await
        .unwrap();
    assert_eq!(erased.key_version, 1);
    assert_eq!(
        node.pending_erasures().await.unwrap(),
        1,
        "a turn that holds the subject's values still runs"
    );
    server.release.send(()).unwrap();
    let ran = running.await.unwrap().unwrap().unwrap();
    assert!(ran.committed(), "{ran:?}");
    assert!(
        ran.turn_id.lsn > erased.lsn.unwrap(),
        "the turn ran across the erasure"
    );
    // Its answer to the sender holds the tombstone too, as its record does:
    // the sender may be another party than the subject (ADR 0123).
    let Some(pb::outcome::Output::Reply(reply)) = &ran.outcome.output else {
        panic!("no reply: {ran:?}")
    };
    assert_eq!(
        reply.body.as_ref().and_then(|b| b.value.clone()),
        Some(pb::sealable::Value::Sealed(
            kronik_privacy::sealer::erased_value(1)
        )),
        "the reply to the sender"
    );
    let refused = waiting.await.unwrap().unwrap().unwrap();
    assert_eq!(refused.outcome.error_code, "SUBJECT_ERASED", "{refused:?}");
    assert!(
        node.store()
            .db()
            .kv_get("counter", "b", "stored")
            .unwrap()
            .is_none(),
        "the erased value reached the guest"
    );
    assert_eq!(
        node.sealer()
            .keystore()
            .unwrap()
            .newest_version("user:1")
            .unwrap(),
        None,
        "a key version of user:1 was created after its erasure"
    );
    assert!(
        sealed_versions(&node, "user:1", start)
            .await
            .iter()
            .all(|v| *v == 1),
        "a value of user:1 was sealed under a newer key"
    );
    // Both turns' records hold the tombstone in place of the input.
    for lsn in [ran.turn_id.lsn, refused.turn_id.lsn] {
        let mut record = None;
        node.reader()
            .read(lsn, lsn, |c| {
                record = Some(c.record);
                Ok(())
            })
            .await
            .unwrap();
        let Some(Record::TurnRecord(t)) = record else {
            panic!("no turn record at {lsn}")
        };
        let Some(pb::input::Kind::Message(m)) = t.input.and_then(|i| i.kind) else {
            panic!("not a message")
        };
        assert_eq!(
            m.msg.and_then(|m| m.body).and_then(|b| b.value),
            Some(pb::sealable::Value::Sealed(
                kronik_privacy::sealer::erased_value(1)
            )),
            "the record at {lsn}"
        );
    }
    assert_eq!(node.pending_erasures().await.unwrap(), 0);
}

/// Privacy mode off: an open turn's recorded effect holds a plain value of
/// user:1 (its open_effects row and the log). The erasure tombstones the row,
/// and the next start does not hand the value to the guest: the turn is
/// closed as SUBJECT_ERASED with the tombstone in its record. Before, the
/// re-run served the plain value to the guest.
#[test]
fn an_open_turns_recorded_value_of_an_erased_subject_is_not_served_again() {
    let dir = tempfile::tempdir().unwrap();
    let execution_id = "00112233445566778899aabbccddeeff".to_owned();
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let node = counter_node(dir.path()).await;
            let authority = node.local_operator_authority().unwrap();
            let code_hash = node.store().db().kinds().unwrap()[0]
                .version
                .code_hash
                .clone();
            let key = kronik_core::causal::root("open-root".into());
            let begin = pb::TurnBegin {
                execution_id: execution_id.clone(),
                actor: Some(ActorRef::parse("counter/b").unwrap().to_pb()),
                code_hash,
                engine_version: kronik_runtime::ENGINE_VERSION.into(),
                causal_key: Some(key),
                logical_time_ms: 1,
                random_seed: vec![1; 32],
                config_epoch: node.epoch(),
                input: Some(pb::Input {
                    kind: Some(pb::input::Kind::Message(pb::MessageInput {
                        source: pb::MessageSource::Operator as i32,
                        msg: Some(message("fetch-ok", "GET http://127.0.0.1:9/x", None)),
                        message_id: "open-root".into(),
                        ..Default::default()
                    })),
                }),
            };
            let response = pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Plain(
                    pb::HttpEffectResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: b"NEEDLE-RECORDED".to_vec(),
                        body_blob: None,
                    }
                    .encode_to_vec(),
                )),
            };
            node.commit(Record::TurnBegin(begin)).await.unwrap();
            node.commit(Record::EffectResult(pb::EffectResult {
                execution_id: execution_id.clone(),
                effect: Some(pb::EffectRecord {
                    ordinal: 1,
                    kind: "http.fetch".into(),
                    target: "http:127.0.0.1".into(),
                    status: pb::EffectStatus::Ok as i32,
                    grounding: pb::Grounding::Live as i32,
                    response: Some(response),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap();
            node.erase_subject("user:1", audit(), false, authority)
                .await
                .unwrap();
            let rows = node.store().db().open_effects(&execution_id).unwrap();
            assert_eq!(
                rows[0].response.as_ref().and_then(|r| r.value.clone()),
                Some(pb::sealable::Value::Sealed(
                    kronik_privacy::sealer::erased_value(0)
                )),
                "the erasure left the open turn's recorded value plain"
            );
        });
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            NodeConfig::default(),
        )
        .await
        .unwrap();
        node.env
            .timeout(Duration::from_secs(30), async {
                while !node.store().db().open_turns().unwrap().is_empty() {
                    node.env.clock.sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        let letters = node.store().db().dead_letters(0, 10).unwrap();
        assert_eq!(
            letters
                .iter()
                .map(|d| d.error_code.as_str())
                .collect::<Vec<_>>(),
            ["SUBJECT_ERASED"],
            "{letters:?}"
        );
        let mut plain = false;
        node.reader()
            .read(1, node.applied_lsn(), |c| {
                if let Record::TurnRecord(t) = &c.record {
                    plain |= t
                        .encode_to_vec()
                        .windows(15)
                        .any(|w| w == b"NEEDLE-RECORDED");
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(!plain, "the closing record holds the erased plaintext");
    });
}

/// A call of user:1 that timed out: its failed caller's record holds the
/// request (sealed under user:1's key in privacy mode `on`, plain and tagged
/// in `off`). user:1 is erased, and the daemon stops before the busy callee
/// runs the queued call. The next start closes the lost call (#30) with a
/// record built from the caller's, sealed with that record's provenance
/// (ADR 0123 §1): its input carries the erasure's tombstone, and no key
/// version of user:1 is created after the erasure.
#[test]
fn a_lost_call_of_an_erased_subject_closes_with_the_tombstone() {
    for (mode, erased_version) in [(pb::PrivacyState::On, 1), (pb::PrivacyState::Off, 0)] {
        let dir = tempfile::tempdir().unwrap();
        let erased_lsn = {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let erased_lsn = rt.block_on(async {
                let node = counter_node(dir.path()).await;
                let authority = node.local_operator_authority().unwrap();
                node.set_privacy_mode(mode, audit(), false, authority.clone())
                    .await
                    .unwrap();
                node.set_limits(
                    pb::Limits {
                        kind: "counter".into(),
                        effect_timeout_ms: Some(100),
                        fuel: Some(100_000_000_000),
                        ..Default::default()
                    },
                    audit(),
                    false,
                    authority.clone(),
                )
                .await
                .unwrap();
                // counter/e spins for seconds: the call waits behind it,
                // times out, and is still queued when the daemon stops.
                let started = node
                    .probe
                    .turns_run
                    .load(std::sync::atomic::Ordering::SeqCst);
                let (spinner, spin_authority) = (node.clone(), authority.clone());
                tokio::spawn(async move {
                    let _ = spinner
                        .send(
                            ActorRef::parse("counter/e").unwrap(),
                            message("spin", "1000000000", None),
                            audit(),
                            false,
                            spin_authority,
                        )
                        .await;
                });
                while node
                    .probe
                    .turns_run
                    .load(std::sync::atomic::Ordering::SeqCst)
                    == started
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let caller = node
                    .send(
                        ActorRef::parse("counter/c").unwrap(),
                        message("call-fail", "counter/e increment increment", Some("user:1")),
                        audit(),
                        false,
                        authority.clone(),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!caller.committed(), "{mode:?}: {caller:?}");
                assert_eq!(
                    node.store().db().waiting_timed_out_calls().unwrap().len(),
                    1,
                    "{mode:?}: the call waits for its callee"
                );
                let erased = node
                    .erase_subject("user:1", audit(), false, authority)
                    .await
                    .unwrap();
                erased.lsn.unwrap()
            });
            // The daemon stops: the queued call goes with it.
            drop(rt);
            erased_lsn
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let node = crate::start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir.path(),
                NodeConfig::default(),
            )
            .await
            .unwrap();
            assert!(
                node.store()
                    .db()
                    .waiting_timed_out_calls()
                    .unwrap()
                    .is_empty(),
                "{mode:?}: the start closed the lost call"
            );
            let mut closing = Vec::new();
            node.reader()
                .read(erased_lsn + 1, node.applied_lsn(), |c| {
                    if let Record::TurnRecord(t) = c.record
                        && t.actor.as_ref().is_some_and(|a| a.key == "e")
                        && matches!(
                            t.input.as_ref().and_then(|i| i.kind.as_ref()),
                            Some(pb::input::Kind::Message(m))
                                if m.source == pb::MessageSource::Call as i32
                        )
                    {
                        closing.push(t);
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(closing.len(), 1, "{mode:?}: {closing:?}");
            let t = closing.remove(0);
            assert_eq!(
                t.outcome.as_ref().map(|o| o.error_code.as_str()),
                Some("UNAVAILABLE"),
                "{mode:?}"
            );
            let Some(pb::input::Kind::Message(m)) = t.input.and_then(|i| i.kind) else {
                panic!("{mode:?}: not a message")
            };
            assert_eq!(
                m.msg.and_then(|m| m.body).and_then(|b| b.value),
                Some(pb::sealable::Value::Sealed(
                    kronik_privacy::sealer::erased_value(erased_version)
                )),
                "{mode:?}: the closing record holds the erasure's tombstone"
            );
            assert_eq!(
                node.sealer()
                    .keystore()
                    .unwrap()
                    .newest_version("user:1")
                    .unwrap(),
                None,
                "{mode:?}: a key version of user:1 was created after its erasure"
            );
            assert!(
                sealed_versions(&node, "user:1", erased_lsn)
                    .await
                    .iter()
                    .all(|v| *v == erased_version),
                "{mode:?}: a value of user:1 was sealed under a newer key"
            );
        });
    }
}

fn fk_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

type SubjectChanges = Vec<(Option<String>, Vec<u8>)>;

fn fk_changes(schema: &[&str], inserts: &[&str]) -> (Vec<String>, SubjectChanges) {
    use kronik_store::sql::{MemOpener, SqlActor, TurnOpts};
    let opts = |seed: u8, subject: Option<&str>, migrate: bool| TurnOpts {
        seed: [seed; 32],
        time_ms: i64::from(seed),
        default_subject: subject.map(str::to_owned),
        migrate,
        sql_budget: 50_000_000,
        max_bytes: 0,
    };
    let mut actor = SqlActor::open(&MemOpener, "notes/n").unwrap();
    actor.begin_turn(&opts(1, None, true)).unwrap();
    for statement in schema {
        actor.query(statement, &[]).unwrap();
    }
    let schema_turn = actor.end_turn(true).unwrap();
    actor
        .apply(&schema_turn, 1, &std::collections::BTreeSet::new())
        .unwrap();
    actor.begin_turn(&opts(2, Some("user:1"), false)).unwrap();
    for statement in inserts {
        actor.query(statement, &[]).unwrap();
    }
    let dml = actor.end_turn(true).unwrap();
    (schema_turn.ddl, dml.changesets)
}

fn sql_record(id: &str, ddl: Vec<String>, changes: SubjectChanges) -> Record {
    Record::TurnRecord(pb::TurnRecord {
        actor: Some(pb::ActorRef {
            kind: "notes".into(),
            key: "n".into(),
        }),
        causal_key: Some(kronik_core::causal::root(id.into())),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "POST".into(),
                path: "/notes".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(Vec::new())),
                    })),
                }),
                ..Default::default()
            })),
        }),
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        sql_schema: ddl
            .into_iter()
            .map(|statement| pb::SqlSchemaChange { statement })
            .collect(),
        sql_changes: changes
            .into_iter()
            .map(|(subject, cs)| pb::SqlChangeset {
                changeset: Some(pb::Sealable {
                    subject,
                    value: Some(pb::sealable::Value::Plain(cs)),
                }),
            })
            .collect(),
        ..Default::default()
    })
}

fn fk_subjects(node: &Node, table: &str) -> Vec<String> {
    let db = node.store().sql.get("notes/n").unwrap();
    let actor = db.lock().unwrap();
    actor.set_host();
    let mut st = actor
        .conn
        .prepare(&format!("SELECT _subject FROM {table} ORDER BY id"))
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

async fn load_fk(node: &Node, schema: &[&str], inserts: &[&str]) {
    let (ddl, changes) = fk_changes(schema, inserts);
    node.commit(sql_record("fk-schema", ddl, Vec::new()))
        .await
        .unwrap();
    node.commit(sql_record("fk-rows", Vec::new(), changes))
        .await
        .unwrap();
}

const FK_SCHEMA: &[&str] = &[
    "CREATE TABLE account (id INTEGER PRIMARY KEY, _subject TEXT)",
    "CREATE TABLE line (id INTEGER PRIMARY KEY, \
     account_id INTEGER NOT NULL REFERENCES account(id), _subject TEXT)",
];

/// Issue #241: erasing `user:1` deletes its account and the line that
/// references it, leaves `user:2`, and a restart applies that `Erasure`
/// and stays up.
#[test]
fn a_parent_child_erasure_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let rt = fk_runtime();
        rt.block_on(async {
            let node = crate::start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir.path(),
                NodeConfig::default(),
            )
            .await
            .unwrap();
            let authority = node.local_operator_authority().unwrap();
            load_fk(
                &node,
                FK_SCHEMA,
                &[
                    "INSERT INTO account(id, _subject) VALUES (1, 'user:1')",
                    "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:1')",
                    "INSERT INTO account(id, _subject) VALUES (2, 'user:2')",
                    "INSERT INTO line(id, account_id, _subject) VALUES (2, 2, 'user:2')",
                ],
            )
            .await;
            node.erase_subject("user:1", audit(), false, authority)
                .await
                .unwrap();
            assert_eq!(node.fatal(), None);
            assert_eq!(fk_subjects(&node, "account"), ["user:2".to_string()]);
            assert_eq!(fk_subjects(&node, "line"), ["user:2".to_string()]);
        });
    }
    let rt = fk_runtime();
    rt.block_on(async {
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            NodeConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(node.fatal(), None);
        assert_eq!(fk_subjects(&node, "account"), ["user:2".to_string()]);
        assert_eq!(fk_subjects(&node, "line"), ["user:2".to_string()]);
    });
}

/// A row of another subject that references the parent blocks the API
/// before the keys are destroyed. Restart stays up, and the rows remain.
#[test]
fn a_cross_subject_reference_does_not_append_an_erasure() {
    let dir = tempfile::tempdir().unwrap();
    {
        let rt = fk_runtime();
        rt.block_on(async {
            let node = crate::start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir.path(),
                NodeConfig::default(),
            )
            .await
            .unwrap();
            let authority = node.local_operator_authority().unwrap();
            load_fk(
                &node,
                FK_SCHEMA,
                &[
                    "INSERT INTO account(id, _subject) VALUES (1, 'user:1')",
                    "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:2')",
                ],
            )
            .await;
            let err = node
                .erase_subject("user:1", audit(), false, authority)
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                kronik_core::error::ErrorCode::ErasureBlocked,
                "{err}"
            );
            assert!(!err.to_string().contains("STORAGE_CORRUPT"), "{err}");
            assert_eq!(node.fatal(), None);
            assert!(
                node.sealer().erasures().unwrap().is_empty(),
                "keys were destroyed before the call failed"
            );
            assert!(node.store().db().erasures().unwrap().is_empty());
            assert_eq!(fk_subjects(&node, "account"), ["user:1".to_string()]);
            assert_eq!(fk_subjects(&node, "line"), ["user:2".to_string()]);
        });
    }
    let rt = fk_runtime();
    rt.block_on(async {
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            NodeConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(node.fatal(), None);
        assert_eq!(fk_subjects(&node, "account"), ["user:1".to_string()]);
        assert_eq!(fk_subjects(&node, "line"), ["user:2".to_string()]);
        assert!(node.sealer().erasures().unwrap().is_empty());
    });
}
