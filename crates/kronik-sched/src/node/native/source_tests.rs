use super::*;
use bytes::Bytes;
use kronik_core::env::{BoxFuture, File, Fs, OpenMode};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// Counts `read_at` on segment files while `armed` is set.
struct CountingFs {
    inner: std::sync::Arc<dyn Fs>,
    reads: std::sync::Arc<AtomicU64>,
    armed: std::sync::Arc<AtomicBool>,
}

struct CountingFile {
    inner: std::sync::Arc<dyn File>,
    segment: bool,
    reads: std::sync::Arc<AtomicU64>,
    armed: std::sync::Arc<AtomicBool>,
}

impl Fs for CountingFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: PathBuf,
        mode: OpenMode,
    ) -> BoxFuture<'static, std::io::Result<std::sync::Arc<dyn File>>> {
        let segment = path.extension().is_some_and(|ext| ext == "seg");
        let reads = self.reads.clone();
        let armed = self.armed.clone();
        let open = self.inner.open(path, mode);
        Box::pin(async move {
            let inner = open.await?;
            Ok(std::sync::Arc::new(CountingFile {
                inner,
                segment,
                reads,
                armed,
            }) as std::sync::Arc<dyn File>)
        })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_dir(dir)
    }
    fn available(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<u64>> {
        self.inner.available(path)
    }
    fn read_secure(
        &self,
        path: PathBuf,
        max_bytes: usize,
    ) -> BoxFuture<'static, std::io::Result<Vec<u8>>> {
        self.inner.read_secure(path, max_bytes)
    }
    fn write_secure(
        &self,
        path: PathBuf,
        bytes: Vec<u8>,
    ) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_secure(path, bytes)
    }
    fn write_secure_new(
        &self,
        path: PathBuf,
        bytes: Bytes,
    ) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_secure_new(path, bytes)
    }
}

impl File for CountingFile {
    fn len(&self) -> BoxFuture<'static, std::io::Result<u64>> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, std::io::Result<Vec<u8>>> {
        if self.segment && self.armed.load(Ordering::SeqCst) {
            self.reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.read_at(offset, len)
    }
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_data()
    }
}

fn begin_n(node: &Node, n: u32) -> pb::TurnBegin {
    let mut turn = begin(node, 'a');
    turn.execution_id = format!("{n:032x}");
    turn
}

#[tokio::test]
async fn indexed_actor_source_does_not_read_each_preceding_record() {
    const PREFIX: u32 = 24;
    let data = tempfile::tempdir().unwrap();
    let real = Env::real(tokio::runtime::Handle::current());
    let reads = std::sync::Arc::new(AtomicU64::new(0));
    let armed = std::sync::Arc::new(AtomicBool::new(false));
    let env = Env {
        fs: std::sync::Arc::new(CountingFs {
            inner: real.fs.clone(),
            reads: reads.clone(),
            armed: armed.clone(),
        }),
        ..real
    };
    let node = crate::start_local(
        env,
        data.path(),
        NodeConfig {
            branch: "source-reads".into(),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let authority = node.local_operator_authority().unwrap();
    let mut last = 0;
    for n in 1..=PREFIX {
        last = node
            .commit_authorized(Record::TurnBegin(begin_n(&node, n)), authority.clone())
            .await
            .unwrap();
    }
    let want = |record: &Record| matches!(record, Record::TurnBegin(turn) if turn.execution_id == format!("{PREFIX:032x}"));
    armed.store(true, Ordering::SeqCst);
    let source = node.actor_source(last, want).await.unwrap();
    let first = reads.swap(0, Ordering::SeqCst);
    let again = node.actor_source(last, want).await.unwrap();
    let second = reads.load(Ordering::SeqCst);
    assert_eq!(source.lsn, last);
    assert_eq!(again, source);
    // Header, envelope and payload. A prefix walk reads at least once per record.
    assert!(
        first < 8 && second < 8,
        "prefix of {PREFIX} records took {first} then {second} segment reads"
    );
}
#[tokio::test]
async fn a_call_succeeds_after_the_log_start_moves_past_one() {
    let data = tempfile::tempdir().unwrap();
    let node = crate::start_local(
        Env::real(tokio::runtime::Handle::current()),
        data.path(),
        NodeConfig {
            branch: "call-after-retention".into(),
            segment_max_bytes: Some(512),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let authority = node.local_operator_authority().unwrap();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ))
    .unwrap();
    node.deploy(&wasm, pb::Audit::default(), false, authority.clone())
        .await
        .unwrap();
    let mut rolls = 0;
    while node.reader.starts().await.unwrap().len() < 2 {
        rolls += 1;
        assert!(rolls < 20, "the log did not roll a second segment");
        node.send(
            ActorRef::parse(&format!("counter/roll{rolls}")).unwrap(),
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
    }
    let oldest = node.reader.starts().await.unwrap()[0];
    assert_eq!(oldest, 1, "a fresh log starts at 1");
    kronik_log::delete_segment(node.reader.dir(), oldest).unwrap();
    let retained = node.reader.starts().await.unwrap()[0];
    assert!(retained > 1, "log start {retained}");
    // The profile anchor stays at the opened start. The call must not walk from it.
    assert_eq!(
        node.native_execution
            .native_source_start(&node, &node.log)
            .unwrap(),
        1
    );
    let result = node
        .send(
            ActorRef::parse("counter/a").unwrap(),
            pb::Message {
                name: "call".into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(b"counter/b increment".to_vec())),
                }),
                ..Default::default()
            },
            pb::Audit::default(),
            false,
            authority,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(result.committed(), "{:?}", result.outcome);
    let committed = node.read_record(result.turn_id.lsn).await.unwrap().unwrap();
    let Record::TurnRecord(turn) = committed.record else {
        panic!("caller turn is not a record");
    };
    let source = turn
        .effects
        .iter()
        .find(|effect| effect.kind == "actor.call")
        .and_then(|effect| effect.callee_source.as_ref())
        .expect("the call records its callee source");
    assert_eq!(source.branch, "call-after-retention");
    assert!(
        source.lsn >= retained,
        "callee {} retained from {retained}",
        source.lsn
    );
}
