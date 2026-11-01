use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

async fn native_node(branch: &str) -> (tempfile::TempDir, Arc<Node>) {
    let data = tempfile::tempdir().unwrap();
    let config = NodeConfig {
        branch: branch.into(),
        ..NodeConfig::default()
    };
    let node = crate::start_local(
        Env::real(tokio::runtime::Handle::current()),
        data.path(),
        config,
    )
    .await
    .unwrap();
    (data, node)
}

fn begin(node: &Node, execution: char) -> pb::TurnBegin {
    pb::TurnBegin {
        execution_id: execution.to_string().repeat(32),
        actor: Some(pb::ActorRef {
            kind: "source".into(),
            key: "caller".into(),
        }),
        code_hash: vec![9; 32],
        engine_version: kronik_runtime::ENGINE_VERSION.into(),
        causal_key: Some(causal::root("source-root".into())),
        logical_time_ms: 29,
        random_seed: vec![6; 32],
        config_epoch: node.epoch(),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "GET".into(),
                path: "/source".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(Vec::new())),
                    })),
                }),
                ..Default::default()
            })),
        }),
    }
}

#[tokio::test]
async fn actual_turn_and_begin_sources_use_the_original_namespace_and_survive_execution_stop() {
    let (_data, node) = native_node("native-evidence").await;
    let authority = node.local_operator_authority().unwrap();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ))
    .unwrap();
    node.deploy(&wasm, pb::Audit::default(), false, authority.clone())
        .await
        .unwrap();
    let actor = ActorRef::parse("counter/source").unwrap();
    let expected_actor = actor.to_pb();
    let turn = node
        .send(
            actor,
            pb::Message {
                name: "increment".into(),
                ..Default::default()
            },
            pb::Audit::default(),
            false,
            authority.clone(),
        )
        .await
        .unwrap()
        .unwrap();
    let source = node.actor_source(turn.turn_id.lsn, |record| matches!(record,
        Record::TurnRecord(turn) if turn.actor.as_ref() == Some(&expected_actor)
            && matches!(turn.input.as_ref().and_then(|input| input.kind.as_ref()),
                Some(pb::input::Kind::Message(message)) if message.source == pb::MessageSource::Operator as i32
                    && message.msg.as_ref().is_some_and(|message| message.name == "increment"))
    )).await.unwrap();
    assert_eq!(
        source,
        pb::ActorSource {
            shard: None,
            lsn: turn.turn_id.lsn,
            branch: "native-evidence".into()
        }
    );
    assert!(
        node.actor_source(turn.turn_id.lsn, |record| matches!(
            record,
            Record::TurnBegin(_)
        ))
        .await
        .is_err()
    );

    let original = begin(&node, 'a');
    let lsn = node
        .commit_authorized(Record::TurnBegin(original.clone()), authority)
        .await
        .unwrap();
    let exact = |record: &Record| {
        matches!(record, Record::TurnBegin(actual)
        if actual.actor == original.actor && actual.execution_id == original.execution_id)
    };
    assert_eq!(
        node.actor_source(lsn, exact).await.unwrap().branch,
        "native-evidence"
    );
    assert!(
        node.actor_source(lsn, |record| matches!(record, Record::TurnBegin(actual)
        if actual.actor == original.actor && actual.execution_id != original.execution_id))
            .await
            .is_err()
    );
    node.stop_native_execution().unwrap();
    assert!(node.local_operator_authority().is_err());
    assert_eq!(
        node.actor_source(lsn, exact).await.unwrap().lsn,
        lsn,
        "historical source evidence is not current mutation authority"
    );
    {
        let _publication = lock(&node.publication);
        node.lifecycle.declare_member_under_publication();
    }
    assert!(
        node.actor_source(lsn, exact).await.is_err(),
        "unsupported member profile must not fall back to native"
    );
}

#[tokio::test]
async fn native_source_profile_cannot_rebind_to_another_real_node_or_log() {
    let (_first_data, first) = native_node("same-namespace").await;
    let (_second_data, second) = native_node("same-namespace").await;
    assert!(
        first
            .native_execution
            .native_source_start(&first, &first.log)
            .is_ok()
    );
    assert!(
        first
            .native_execution
            .native_source_start(&second, &first.log)
            .is_err()
    );
    assert!(
        first
            .native_execution
            .native_source_start(&first, &second.log)
            .is_err()
    );
}

#[tokio::test]
async fn current_native_profile_cannot_claim_a_source_after_an_unknown_crc_valid_frame() {
    for kind in (20_u8..=25).chain(std::iter::once(254)) {
        let (_data, node) = native_node("unknown-source").await;
        let lsn = node
            .commit_authorized(
                Record::TurnBegin(begin(&node, 'a')),
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap();
        node.stop_native_execution().unwrap();
        let start = *node.reader.starts().await.unwrap().last().unwrap();
        let path = node.reader.dir().join(kronik_log::segment_name(start));
        let mut suffix = Vec::new();
        kronik_log::encode_raw_entry(lsn + 1, kind, &[], &mut suffix);
        kronik_log::encode_entry(lsn + 2, &Record::TurnBegin(begin(&node, 'b')), &mut suffix);
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&suffix).unwrap();
        file.sync_all().unwrap();
        assert!(
            node.actor_source(lsn + 2, |record| matches!(record,
                Record::TurnBegin(actual) if actual.execution_id == "b".repeat(32)
            ))
            .await
            .is_err(),
            "kind {kind} must not produce a post-unknown native fact"
        );
    }
}

#[tokio::test]
async fn corrupt_or_torn_actual_source_frame_is_never_complete_evidence() {
    for torn in [false, true] {
        let (_data, node) = native_node("damaged-source").await;
        let lsn = node
            .commit_authorized(
                Record::TurnBegin(begin(&node, 'a')),
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap();
        node.stop_native_execution().unwrap();
        let mut position = None;
        node.reader
            .read(lsn, lsn, |record| {
                position = Some(record.pos);
                Ok(())
            })
            .await
            .unwrap();
        let position = position.unwrap();
        let path = node
            .reader
            .dir()
            .join(kronik_log::segment_name(position.segment));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        if torn {
            file.set_len(position.offset + 16).unwrap();
        } else {
            file.seek(SeekFrom::Start(position.offset + 4)).unwrap();
            let mut crc = [0_u8; 1];
            file.read_exact(&mut crc).unwrap();
            crc[0] ^= 1;
            file.seek(SeekFrom::Start(position.offset + 4)).unwrap();
            file.write_all(&crc).unwrap();
        }
        file.sync_all().unwrap();
        assert!(
            node.actor_source(lsn, |record| matches!(record, Record::TurnBegin(_)))
                .await
                .is_err()
        );
    }
}
