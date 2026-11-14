// Tests drive the log from several tokio tasks to mix records in batches.
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use kronik_core::env::{BoxFuture, Fs};
use kronik_proto::log::v1 as pb;

use super::*;
use super::{
    footer_payload, header_bytes, parse_entry, parse_header, parse_segment_name, turn_actor,
};

fn plain(b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

fn actor() -> Option<pb::ActorRef> {
    Some(pb::ActorRef {
        kind: "counter".into(),
        key: "a".into(),
    })
}

fn input() -> Option<pb::Input> {
    Some(pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
            from_schema_version: 0,
            to_schema_version: 1,
        })),
    })
}

fn causal() -> Option<pb::CausalKey> {
    Some(pb::CausalKey {
        root: "r".into(),
        path: vec![],
    })
}

fn effect() -> pb::EffectRecord {
    pb::EffectRecord {
        status: pb::EffectStatus::Ok as i32,
        grounding: pb::Grounding::Live as i32,
        request: plain(b"req"),
        response: plain(b"resp"),
        ..Default::default()
    }
}

/// One valid record of every kind, in kind order.
fn samples() -> Vec<Record> {
    let audit = Some(pb::Audit {
        token_id: "t".into(),
        reason: "r".into(),
        wall_time_ms: 1,
    });
    vec![
        Record::TurnBegin(pb::TurnBegin {
            execution_id: "e".into(),
            actor: actor(),
            causal_key: causal(),
            input: input(),
            ..Default::default()
        }),
        Record::EffectResult(pb::EffectResult {
            execution_id: "e".into(),
            effect: Some(effect()),
        }),
        Record::TurnRecord(pb::TurnRecord {
            execution_id: "e".into(),
            actor: actor(),
            causal_key: causal(),
            input: input(),
            effects: vec![effect()],
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            ..Default::default()
        }),
        Record::Deployment(pb::Deployment {
            epoch: 1,
            cause: pb::DeploymentCause::Deploy as i32,
            audit: audit.clone(),
            ..Default::default()
        }),
        Record::Grant(pb::Grant {
            epoch: 2,
            op: pb::GrantOp::Grant as i32,
            kind: "counter".into(),
            capability: "http:example.com".into(),
            ..Default::default()
        }),
        Record::Limits(pb::Limits {
            epoch: 3,
            kind: "counter".into(),
            fuel: Some(1),
            ..Default::default()
        }),
        Record::Policy(pb::Policy::default()),
        Record::Approval(pb::Approval::default()),
        Record::PrivacyMode(pb::PrivacyMode {
            epoch: 4,
            mode: pb::PrivacyState::On as i32,
            audit: audit.clone(),
            reseal_requested: false,
        }),
        Record::ForeignActor(pb::ForeignActor {
            op: pb::ForeignOp::Remove as i32,
            ..Default::default()
        }),
        Record::BranchCreated(pb::BranchCreated::default()),
        Record::Erasure(pb::Erasure::default()),
        Record::EngineUpgrade(pb::EngineUpgrade::default()),
        Record::SnapshotMarker(pb::SnapshotMarker::default()),
        Record::SimulatorConfig(pb::SimulatorConfig {
            epoch: 5,
            target: "http:payments.internal".into(),
            neighbor: true,
            ..Default::default()
        }),
        Record::StateRebase(pb::StateRebase {
            rebase_id: "r-1".into(),
            part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
                fork_lsn: 9,
                record: Some(pb::TurnRecord {
                    execution_id: "f".into(),
                    actor: actor(),
                    causal_key: causal(),
                    input: input(),
                    outcome: Some(pb::Outcome {
                        kind: pb::OutcomeKind::Committed as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            })),
        }),
        Record::GuardTriggered(pb::GuardTriggered {
            action: pb::GuardAction::Rollback as i32,
            outcome: pb::GuardOutcome::RolledBack as i32,
            ..Default::default()
        }),
        Record::AuditEvent(pb::AuditEvent {
            action: "secret.set".into(),
            audit: Some(pb::Audit::default()),
            ..Default::default()
        }),
        Record::SecretVersion(pb::SecretVersion {
            name: "key".into(),
            version: 1,
            version_hash: vec![0x55; 16],
            backend: "file".into(),
            source_version: "1".into(),
            r#ref: "key".into(),
            binding: "file".into(),
            canonical_ref: "key".into(),
            phase: pb::secret_version::Phase::Active as i32,
            hash_revision: 1,
            audit: audit.clone(),
            ..Default::default()
        }),
        Record::SecretLink(pb::SecretLink {
            name: "key".into(),
            backend: "vault".into(),
            r#ref: "kv/key".into(),
            binding: "trusted".into(),
            canonical_ref: "kv/data/key".into(),
            generation: 1,
            epoch: 7,
            audit: audit.clone(),
        }),
    ]
}

struct Harness {
    env: Env,
    _dir: tempfile::TempDir,
    cfg: LogConfig,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut cfg = LogConfig::new(dir.path().join("log"), "main");
    cfg.group_commit_window = Duration::ZERO;
    Harness {
        env,
        _dir: dir,
        cfg,
    }
}

impl Harness {
    async fn open(&self) -> Result<(Log, Opened, mpsc::UnboundedReceiver<Committed>), LogError> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (ftx, _frx) = oneshot::channel();
        let (log, opened) = Log::open(&self.env, self.cfg.clone(), tx, ftx).await?;
        Ok((log, opened, rx))
    }

    async fn read_all(&self) -> Result<Vec<Committed>, LogError> {
        let mut out = Vec::new();
        LogReader::new(self.env.clone(), self.cfg.dir.clone(), "main")
            .read(1, Lsn::MAX, |c| {
                out.push(c);
                Ok(())
            })
            .await?;
        Ok(out)
    }

    fn segment_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(&self.cfg.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        v.sort();
        v
    }
}

#[tokio::test]
async fn native_positional_read_binds_the_actual_header_and_record() {
    let mut h = harness();
    h.cfg.branch = "retained-native".into();
    let (log, _, mut committed) = h.open().await.unwrap();
    let expected = Record::Policy(pb::Policy::default());
    log.append(expected.clone()).await.unwrap();
    let committed = committed.recv().await.unwrap();
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), h.cfg.branch.clone());
    let (namespace, actual) = reader.read_at_with_namespace(committed.pos).await.unwrap();
    assert_eq!(namespace, "retained-native");
    assert_eq!(actual.lsn, committed.lsn);
    assert_eq!(actual.pos, committed.pos);
    assert_eq!(actual.record, expected);
    let unrelated = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "replaced-native");
    assert!(matches!(
        unrelated.read_at_with_namespace(committed.pos).await,
        Err(LogError::Corrupt(_))
    ));
}

struct ReadFs {
    inner: Arc<dyn Fs>,
    calls: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl Fs for ReadFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.create_dir_all(path)
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let opened = self.inner.open(path, mode);
        let calls = self.calls.clone();
        Box::pin(async move {
            Ok(Arc::new(ReadFile {
                inner: opened.await?,
                calls,
            }) as Arc<dyn File>)
        })
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.inner.exists(path)
    }

    fn read_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.inner.read_dir(path)
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.rename(from, to)
    }

    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.remove_file(path)
    }

    fn sync_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.sync_dir(path)
    }
}

struct ReadFile {
    inner: Arc<dyn File>,
    calls: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl File for ReadFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.len()
    }

    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        self.calls.lock().unwrap().push((offset, len));
        self.inner.read_at(offset, len)
    }

    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        self.inner.write_at(offset, data)
    }

    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        self.inner.sync_data()
    }
}

#[tokio::test]
async fn bounded_reads_stop_at_each_batch_and_resume_without_loss() {
    let mut h = harness();
    std::fs::create_dir_all(&h.cfg.dir).unwrap();
    let mut record = samples()[2].clone();
    if let Record::TurnRecord(turn) = &mut record {
        turn.effects[0].response = plain(&vec![b'x'; 16 << 10]);
    }
    let encoded = record.encode();
    let mut image = header_bytes("main", 1);
    let header_len = image.len();
    let frame_len = ENVELOPE_LEN + record.encoded_len();
    for lsn in 1..=257 {
        encode_entry(lsn, &record, &mut image);
    }
    std::fs::write(h.cfg.dir.join(segment_name(1)), &image).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    h.env.fs = Arc::new(ReadFs {
        inner: h.env.fs.clone(),
        calls: calls.clone(),
    });
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut consumed = Vec::new();
    while consumed.len() < 257 {
        calls.lock().unwrap().clear();
        let from = consumed.len() as u64 + 1;
        let mut batch = Vec::new();
        let mut callbacks = 0;
        reader
            .read_while(from, 257, |c| {
                callbacks += 1;
                if batch.len() == 17 {
                    return Ok(false);
                }
                assert_eq!(c.record.encode(), encoded);
                assert_eq!(
                    c.pos.offset as usize,
                    header_len + (c.lsn as usize - 1) * frame_len
                );
                batch.push(c.lsn);
                Ok(true)
            })
            .await
            .unwrap();
        assert_eq!(callbacks, (258 - from).min(18) as usize);
        let last_visited = from + callbacks as u64 - 1;
        let end = header_len + last_visited as usize * frame_len;
        let reads = calls.lock().unwrap();
        assert_eq!(reads.len(), 1 + last_visited as usize * 2);
        assert!(reads.iter().all(|&(_, len)| len <= frame_len));
        assert_eq!(
            reads.iter().map(|&(off, len)| off as usize + len).max(),
            Some(end)
        );
        assert_eq!(reads.iter().map(|&(_, len)| len).sum::<usize>(), end);
        consumed.extend(batch);
    }
    assert_eq!(consumed, (1..=257).collect::<Vec<_>>());
}

#[tokio::test]
async fn bounded_reads_decode_only_the_requested_and_visited_records() {
    let h = harness();
    std::fs::create_dir_all(&h.cfg.dir).unwrap();
    let mut image = header_bytes("main", 1);
    // A skipped, CRC-valid protobuf is not decoded, as with read().
    encode_raw_entry(1, kronik_proto::kind::TURN_RECORD, &[0xff], &mut image);
    encode_entry(2, &samples()[2], &mut image);
    encode_raw_entry(3, kronik_proto::kind::TURN_RECORD, &[0xff], &mut image);
    std::fs::write(h.cfg.dir.join(segment_name(1)), &image).unwrap();
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut seen = Vec::new();
    reader
        .read_while(2, 3, |c| {
            seen.push(c.lsn);
            Ok(false)
        })
        .await
        .unwrap();
    assert_eq!(seen, vec![2]);
    assert!(matches!(
        reader.read_while(3, 3, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
    assert!(matches!(
        reader.read_while(1, 3, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
    assert!(matches!(
        reader.read_while(2, 3, |_| Err(corrupt("callback"))).await,
        Err(LogError::Corrupt(message)) if message == "callback"
    ));
    let mut unknown = header_bytes("main", 1);
    encode_raw_entry(1, 0, &[], &mut unknown);
    encode_entry(2, &samples()[2], &mut unknown);
    std::fs::write(h.cfg.dir.join(segment_name(1)), &unknown).unwrap();
    assert!(matches!(
        reader.read_while(2, 2, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
}

#[tokio::test]
async fn bounded_reads_require_finite_endpoints_but_empty_ranges_do_no_io() {
    let h = harness();
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    // The directory does not exist: even listing it would fail.
    reader
        .read_while(2, 1, |_| panic!("empty range"))
        .await
        .unwrap();
    reader
        .read_while(0, 0, |_| panic!("zero endpoint"))
        .await
        .unwrap();
    std::fs::create_dir_all(&h.cfg.dir).unwrap();
    assert!(matches!(
        reader.read_while(1, 1, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
    reader
        .read_while(1, Lsn::MAX, |_| panic!("empty log"))
        .await
        .unwrap();
    let mut image = header_bytes("main", 10);
    encode_entry(10, &samples()[2], &mut image);
    std::fs::write(h.cfg.dir.join(segment_name(10)), &image).unwrap();
    assert!(matches!(
        reader.read_while(1, 5, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
}

#[tokio::test]
async fn bounded_reads_crc_check_large_skipped_payloads_in_small_chunks() {
    let mut h = harness();
    std::fs::create_dir_all(&h.cfg.dir).unwrap();
    let mut image = header_bytes("main", 1);
    let header_len = image.len();
    encode_raw_entry(
        1,
        kronik_proto::kind::TURN_RECORD,
        &vec![0xff; 256 << 10],
        &mut image,
    );
    encode_entry(2, &samples()[2], &mut image);
    let path = h.cfg.dir.join(segment_name(1));
    std::fs::write(&path, &image).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    h.env.fs = Arc::new(ReadFs {
        inner: h.env.fs.clone(),
        calls: calls.clone(),
    });
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut seen = Vec::new();
    reader
        .read_while(2, 2, |c| {
            seen.push(c.lsn);
            Ok(true)
        })
        .await
        .unwrap();
    assert_eq!(seen, vec![2]);
    {
        let reads = calls.lock().unwrap();
        assert!(reads.iter().all(|&(_, len)| len <= 64 << 10));
        assert_eq!(reads.iter().filter(|&&(_, len)| len == 64 << 10).count(), 4);
        assert_eq!(
            reads.iter().map(|&(_, len)| len).sum::<usize>(),
            image.len()
        );
    }
    image[header_len + ENVELOPE_LEN + (128 << 10)] ^= 1;
    std::fs::write(&path, &image).unwrap();
    assert!(matches!(
        reader
            .read_while(2, 2, |_| panic!("corrupt skipped prefix"))
            .await,
        Err(LogError::Corrupt(_))
    ));
}

#[tokio::test]
async fn bounded_reads_preserve_segment_boundaries_and_reject_damaged_frames() {
    let h = harness();
    std::fs::create_dir_all(&h.cfg.dir).unwrap();
    let record = &samples()[2];
    let mut first = header_bytes("main", 10);
    for lsn in 10..=12 {
        encode_entry(lsn, record, &mut first);
    }
    encode_raw_entry(
        0,
        FOOTER_KIND,
        &footer_payload(&FooterIndex::new()).unwrap(),
        &mut first,
    );
    let mut second = header_bytes("main", 13);
    for lsn in 13..=15 {
        encode_entry(lsn, record, &mut second);
    }
    let first_path = h.cfg.dir.join(segment_name(10));
    let second_path = h.cfg.dir.join(segment_name(13));
    std::fs::write(&first_path, &first).unwrap();
    std::fs::write(&second_path, &second).unwrap();
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut seen = Vec::new();
    reader
        .read_while(11, 14, |c| {
            seen.push((c.lsn, c.pos.segment));
            Ok(true)
        })
        .await
        .unwrap();
    assert_eq!(seen, vec![(11, 10), (12, 10), (13, 13), (14, 13)]);

    for damaged in [
        first[..first.len() - 1].to_vec(),
        {
            let mut bad = first.clone();
            let crc = parse_header(&bad).unwrap().len + 4;
            bad[crc] ^= 1;
            bad
        },
        {
            let mut bad = header_bytes("main", 10);
            encode_entry(10, record, &mut bad);
            encode_entry(12, record, &mut bad);
            bad
        },
        {
            let mut bad = header_bytes("main", 10);
            encode_entry(10, record, &mut bad);
            encode_entry(11, record, &mut bad);
            bad
        },
        {
            let mut bad = header_bytes("main", 10);
            bad.extend_from_slice(&(MAX_RECORD + 1).to_le_bytes());
            bad.extend_from_slice(&[0; ENVELOPE_LEN - 4]);
            bad
        },
    ] {
        std::fs::write(&first_path, &damaged).unwrap();
        assert!(matches!(
            reader.read(10, 15, |_| Ok(())).await,
            Err(LogError::Corrupt(_))
        ));
        assert!(matches!(
            reader.read_while(10, 15, |_| Ok(true)).await,
            Err(LogError::Corrupt(_))
        ));
    }
    std::fs::write(&first_path, &first).unwrap();
    for damaged in [
        second[..second.len() - 1].to_vec(),
        second[..parse_header(&second).unwrap().len].to_vec(),
        {
            let mut bad = second.clone();
            let crc = parse_header(&bad).unwrap().len + 4;
            bad[crc] ^= 1;
            bad
        },
    ] {
        std::fs::write(&second_path, &damaged).unwrap();
        assert!(matches!(
            reader.read_while(13, 15, |_| Ok(true)).await,
            Err(LogError::Corrupt(_))
        ));
        reader.read_while(13, Lsn::MAX, |_| Ok(true)).await.unwrap();
    }
    std::fs::write(&second_path, header_bytes("other", 13)).unwrap();
    assert!(matches!(
        reader.read_while(13, 15, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
    let mut mismatch = header_bytes("main", 14);
    encode_entry(14, record, &mut mismatch);
    std::fs::write(&second_path, &mismatch).unwrap();
    assert!(matches!(
        reader.read_while(13, 15, |_| Ok(true)).await,
        Err(LogError::Corrupt(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn lsn_strictly_increases_across_all_record_kinds() {
    let h = harness();
    let (log, opened, mut rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 1);
    let mut lsns = Vec::new();
    // Two rounds over every kind, concurrently, to mix them in batches.
    let log = Arc::new(log);
    let mut tasks = Vec::new();
    for r in samples().into_iter().chain(samples()) {
        let log = log.clone();
        tasks.push(tokio::spawn(async move { log.append(r).await.unwrap() }));
    }
    for t in tasks {
        lsns.push(t.await.unwrap());
    }
    lsns.sort_unstable();
    assert_eq!(lsns, (1..=2 * samples().len() as u64).collect::<Vec<_>>());
    // The applier stream is in LSN order.
    let mut streamed = Vec::new();
    for _ in 0..2 * samples().len() {
        streamed.push(rx.recv().await.unwrap().lsn);
    }
    assert_eq!(
        streamed,
        (1..=2 * samples().len() as u64).collect::<Vec<_>>()
    );
    drop(log);

    let all = h.read_all().await.unwrap();
    let mut prev = 0;
    let mut kinds = std::collections::BTreeSet::new();
    for c in &all {
        assert!(c.lsn > prev, "lsn {} after {prev}", c.lsn);
        prev = c.lsn;
        kinds.insert(c.record.kind());
        let again = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main")
            .read_at(c.pos)
            .await
            .unwrap();
        assert_eq!(again.lsn, c.lsn);
        assert_eq!(again.record, c.record);
    }
    assert_eq!(all.len(), 2 * samples().len());
    assert_eq!(
        kinds.into_iter().collect::<Vec<_>>(),
        kronik_proto::kind::ALL
    );
    let (_log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 2 * samples().len() as u64 + 1);
}

/// A nonzero group-commit window — the production default, while every
/// other test pins it to zero: the writer sleeps the window, then drains
/// what queued into one batch. A lone append cannot resolve before the
/// window has passed, and concurrent appends that queue while the writer
/// sleeps all resolve with unique, contiguous LSNs, keep the applier
/// stream in order and read back unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_nonzero_group_commit_window_batches_concurrent_appends_correctly() {
    let mut h = harness();
    h.cfg.group_commit_window = Duration::from_millis(20);
    let (log, opened, mut rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 1);
    let log = Arc::new(log);

    // One append on its own: the writer holds every batch for the window.
    let started = h.env.clock.monotonic();
    assert_eq!(
        log.append(Record::Policy(pb::Policy::default()))
            .await
            .unwrap(),
        1
    );
    assert!(
        h.env.clock.monotonic() - started >= h.cfg.group_commit_window,
        "an append resolved before the window passed"
    );

    // Everything sent while the writer sleeps the next window queues
    // behind it and shares its batch.
    let mut tasks = Vec::new();
    for r in samples().into_iter().chain(samples()) {
        let log = log.clone();
        tasks.push(tokio::spawn(async move { log.append(r).await.unwrap() }));
    }
    let mut lsns = Vec::with_capacity(tasks.len());
    for t in tasks {
        lsns.push(t.await.unwrap());
    }
    lsns.sort_unstable();
    assert_eq!(
        lsns,
        (2..=1 + samples().len() as u64 * 2).collect::<Vec<Lsn>>()
    );

    let total = 1 + samples().len() * 2;
    let mut streamed = Vec::new();
    for _ in 0..total {
        streamed.push(rx.recv().await.unwrap().lsn);
    }
    assert_eq!(streamed, (1..=total as Lsn).collect::<Vec<_>>());
    drop(log);

    let all = h.read_all().await.unwrap();
    assert_eq!(all.len(), total);
    let mut prev = 0;
    for c in &all {
        assert!(c.lsn > prev);
        prev = c.lsn;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn torn_tail_is_truncated_and_appends_continue() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    for r in samples().into_iter().take(3) {
        log.append(r).await.unwrap();
    }
    drop(log);
    let seg = h.segment_files().pop().unwrap();
    let full = std::fs::read(&seg).unwrap();
    // Tear the last record in half.
    let mut buf = Vec::new();
    encode_entry(4, &samples()[3], &mut buf);
    let mut torn = full.clone();
    torn.extend_from_slice(&buf[..buf.len() / 2]);
    std::fs::write(&seg, &torn).unwrap();

    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 4);
    assert_eq!(opened.truncated_bytes, (buf.len() / 2) as u64);
    assert_eq!(std::fs::read(&seg).unwrap(), full);
    assert_eq!(log.append(samples()[3].clone()).await.unwrap(), 4);
    drop(log);
    assert_eq!(h.read_all().await.unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn segments_roll_and_closed_segment_damage_is_corrupt() {
    let mut h = harness();
    h.cfg.segment_max_bytes = 100;
    let (log, _, _rx) = h.open().await.unwrap();
    for r in samples() {
        log.append(r).await.unwrap();
    }
    drop(log);
    let files = h.segment_files();
    assert!(files.len() > 2, "expected several segments, got {files:?}");
    let all = h.read_all().await.unwrap();
    assert_eq!(
        all.iter().map(|c| c.lsn).collect::<Vec<_>>(),
        (1..=samples().len() as u64).collect::<Vec<_>>()
    );
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut from_ten = Vec::new();
    reader
        .read(10, 12, |c| {
            from_ten.push(c.lsn);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(from_ten, vec![10, 11, 12]);

    // Flip a byte in the first (closed) segment's last entry.
    let mut img = std::fs::read(&files[0]).unwrap();
    let n = img.len();
    img[n - 1] ^= 0xff;
    std::fs::write(&files[0], &img).unwrap();
    assert!(matches!(h.read_all().await, Err(LogError::Corrupt(_))));
    // Opening still works: only the active segment is scanned at open.
    assert!(h.open().await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_record_with_valid_crc_is_storage_corrupt() {
    for (kind, payload) in [
        // TurnRecord with an outcome kind of 0 (UNSPECIFIED).
        (
            kronik_proto::kind::TURN_RECORD,
            Record::TurnRecord(pb::TurnRecord {
                execution_id: "e".into(),
                actor: actor(),
                causal_key: causal(),
                input: input(),
                outcome: Some(pb::Outcome::default()),
                ..Default::default()
            })
            .encode(),
        ),
        // An unknown enum value.
        (
            kronik_proto::kind::PRIVACY_MODE,
            Record::PrivacyMode(pb::PrivacyMode {
                epoch: 1,
                mode: 77,
                audit: None,
                reseal_requested: false,
            })
            .encode(),
        ),
        // Unknown and zero record kinds.
        (99, vec![]),
        (0, vec![]),
    ] {
        let h = harness();
        let (log, _, _rx) = h.open().await.unwrap();
        log.append(samples()[3].clone()).await.unwrap();
        drop(log);
        let seg = h.segment_files().pop().unwrap();
        let mut img = std::fs::read(&seg).unwrap();
        encode_raw_entry(2, kind, &payload, &mut img);
        std::fs::write(&seg, &img).unwrap();
        let res = h.read_all().await;
        assert!(
            matches!(res, Err(LogError::Corrupt(_))),
            "kind {kind}: {res:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn torn_header_of_new_segment_is_recreated() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    log.append(samples()[3].clone()).await.unwrap();
    drop(log);
    // A crash while rolling left a partial header for lsn 2.
    std::fs::write(h.cfg.dir.join(segment_name(2)), b"KRN").unwrap();
    let (log, opened, _rx) = h.open().await.unwrap();
    assert!(opened.recreated_active);
    assert_eq!(opened.next_lsn, 2);
    assert_eq!(log.append(samples()[4].clone()).await.unwrap(), 2);
    drop(log);
    assert_eq!(h.read_all().await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_log_can_start_after_lsn_one_and_append_in_one_batch() {
    let mut h = harness();
    h.cfg.first_lsn = 101;
    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 101);
    let last = log
        .append_all(samples().into_iter().take(5).collect())
        .await
        .unwrap();
    assert_eq!(last, Some(105));
    assert_eq!(log.append_all(Vec::new()).await.unwrap(), None);
    drop(log);
    let all = h.read_all().await.unwrap();
    assert_eq!(
        all.iter().map(|c| c.lsn).collect::<Vec<_>>(),
        (101..=105).collect::<Vec<_>>()
    );
    let (_log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 106);
}

fn begin(key: &str) -> Record {
    Record::TurnBegin(pb::TurnBegin {
        execution_id: "e".into(),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: key.into(),
        }),
        causal_key: causal(),
        input: input(),
        ..Default::default()
    })
}

fn finished(key: &str) -> Record {
    Record::TurnRecord(pb::TurnRecord {
        execution_id: "e".into(),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: key.into(),
        }),
        causal_key: causal(),
        input: input(),
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn last_kind(image: &[u8]) -> Option<u8> {
    let header = parse_header(image)?;
    let mut off = header.len;
    let mut kind = None;
    while let Some(e) = parse_entry(image, off) {
        kind = Some(e.kind);
        off = e.end;
    }
    kind
}

fn turn_offsets(image: &[u8]) -> FooterIndex {
    let header = parse_header(image).unwrap();
    let mut off = header.len;
    let mut index = FooterIndex::new();
    while let Some(e) = parse_entry(image, off) {
        if e.kind == FOOTER_KIND {
            break;
        }
        if e.kind == kronik_proto::kind::TURN_BEGIN || e.kind == kronik_proto::kind::TURN_RECORD {
            let record = Record::decode(e.kind, e.payload).unwrap();
            let (kind, key) = turn_actor(&record).unwrap();
            index
                .entry((kind.to_owned(), key.to_owned()))
                .or_default()
                .push(off as u64);
        }
        off = e.end;
    }
    index
}

#[tokio::test(flavor = "multi_thread")]
async fn rolled_segment_ends_with_a_footer_index() {
    let mut h = harness();
    h.cfg.segment_max_bytes = 64;
    let (log, _, _rx) = h.open().await.unwrap();
    for r in samples() {
        log.append(r).await.unwrap();
    }
    drop(log);
    let files = h.segment_files();
    assert!(files.len() > 2, "expected several segments, got {files:?}");
    for path in &files[..files.len() - 1] {
        let image = std::fs::read(path).unwrap();
        assert_eq!(last_kind(&image), Some(FOOTER_KIND), "{}", path.display());
        assert_eq!(footer_index(path).unwrap().unwrap(), turn_offsets(&image));
    }
    assert_eq!(footer_index(files.last().unwrap()).unwrap(), None);
    let all = h.read_all().await.unwrap();
    assert_eq!(
        all.iter().map(|c| c.lsn).collect::<Vec<_>>(),
        (1..=samples().len() as u64).collect::<Vec<_>>()
    );
    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, samples().len() as u64 + 1);
    drop(log);

    // A crash after the footer, before the next segment existed: do not
    // append after the footer.
    let closed = files[files.len() - 2].clone();
    let closed_bytes = std::fs::read(&closed).unwrap();
    let active = files.last().unwrap();
    let start = parse_segment_name(&active.file_name().unwrap().to_string_lossy()).unwrap();
    std::fs::remove_file(active).unwrap();
    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(std::fs::read(&closed).unwrap(), closed_bytes);
    assert_eq!(opened.next_lsn, start);
    assert!(h.cfg.dir.join(segment_name(start)).is_file());
    assert_eq!(log.append(samples()[0].clone()).await.unwrap(), start);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_footer_does_not_change_records_or_the_next_lsn() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    for record in [begin("a"), finished("a"), begin("b"), finished("b")] {
        log.append(record).await.unwrap();
    }
    drop(log);
    let path = h.segment_files().pop().unwrap();
    let bare_image = std::fs::read(&path).unwrap();
    assert_eq!(footer_index(&path).unwrap(), None);
    let header = parse_header(&bare_image).unwrap();
    let payload = footer_payload(&turn_offsets(&bare_image)).unwrap();
    let mut image = bare_image.clone();
    encode_raw_entry(0, FOOTER_KIND, &payload, &mut image);
    std::fs::write(&path, &image).unwrap();
    let with = decode_segment_image(&image, "main", header.start_lsn, 1, Lsn::MAX, false).unwrap();
    let bare =
        decode_segment_image(&bare_image, "main", header.start_lsn, 1, Lsn::MAX, false).unwrap();
    assert_eq!(with.next_lsn, bare.next_lsn);
    assert_eq!(with.records.len(), bare.records.len());
    for (left, right) in with.records.iter().zip(&bare.records) {
        assert_eq!(left.lsn, right.lsn);
        assert_eq!(left.pos, right.pos);
        assert_eq!(left.record, right.record);
    }
    let index = footer_index(&path).unwrap().unwrap();
    assert_eq!(index, turn_offsets(&image));
    let a = &index[&("counter".into(), "a".into())];
    let b = &index[&("counter".into(), "b".into())];
    assert_eq!(a.len(), 2);
    assert_eq!(b.len(), 2);
    assert!(a[0] < a[1] && a[1] < b[0] && b[0] < b[1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_torn_footer_is_truncated() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    log.append(begin("a")).await.unwrap();
    drop(log);
    let seg = h.segment_files().pop().unwrap();
    let full = std::fs::read(&seg).unwrap();
    assert_eq!(footer_index(&seg).unwrap(), None);
    let mut footer = Vec::new();
    encode_raw_entry(0, FOOTER_KIND, b"FIDX", &mut footer);
    let mut torn = full.clone();
    torn.extend_from_slice(&footer[..footer.len() / 2]);
    std::fs::write(&seg, &torn).unwrap();
    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 2);
    assert_eq!(opened.truncated_bytes, (footer.len() / 2) as u64);
    assert_eq!(std::fs::read(&seg).unwrap(), full);
    assert_eq!(log.append(finished("a")).await.unwrap(), 2);
    drop(log);
    assert_eq!(h.read_all().await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn rewrite_rebuilds_offsets_and_a_noop_leaves_a_missing_footer() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    log.append_all(vec![begin("a"), finished("a")])
        .await
        .unwrap();
    drop(log);
    let path = h.segment_files().pop().unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(footer_index(&path).unwrap().is_none());
    let untouched = rewrite_segment(&path, |_lsn, _record| Ok(false)).unwrap();
    assert!(!untouched.changed);
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let rewritten = rewrite_segment(&path, |_lsn, record| {
        if let Record::TurnBegin(turn) = record {
            turn.execution_id = "execution-id-long-enough-to-shift-later-offsets".into();
            return Ok(true);
        }
        Ok(false)
    })
    .unwrap();
    assert!(rewritten.changed);
    let image = std::fs::read(&path).unwrap();
    assert_eq!(last_kind(&image), Some(FOOTER_KIND));
    assert_ne!(image, before);
    assert_eq!(footer_index(&path).unwrap().unwrap(), turn_offsets(&image));
    let again = rewrite_segment(&path, |_lsn, _record| Ok(false)).unwrap();
    assert!(!again.changed);
    assert_eq!(std::fs::read(&path).unwrap(), image);

    decode_segment_image(
        &image,
        "main",
        parse_header(&image).unwrap().start_lsn,
        1,
        Lsn::MAX,
        false,
    )
    .unwrap();
}

#[test]
fn footer_index_rejects_a_footer_that_does_not_parse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(segment_name(1));
    let mut image = header_bytes("main", 1);
    encode_entry(1, &begin("a"), &mut image);
    encode_raw_entry(0, FOOTER_KIND, b"NOPE", &mut image);
    std::fs::write(&path, &image).unwrap();
    assert!(footer_index(&path).is_err());

    let mut image = header_bytes("main", 1);
    encode_entry(1, &begin("a"), &mut image);
    let mut payload = Vec::new();
    payload.extend_from_slice(b"FIDX");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"k");
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(b"a");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&u64::MAX.to_le_bytes());
    encode_raw_entry(0, FOOTER_KIND, &payload, &mut image);
    std::fs::write(&path, &image).unwrap();
    let err = footer_index(&path).unwrap_err();
    assert!(err.to_string().contains("outside the segment"), "{err}");
}

/// An `EffectResult` whose body is `body` bytes of response plus a few
/// bytes of envelope fields.
fn effect_result_with(body: Vec<u8>) -> Record {
    Record::EffectResult(pb::EffectResult {
        execution_id: "e".into(),
        effect: Some(pb::EffectRecord {
            response: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(body)),
            }),
            ..effect()
        }),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn an_append_over_the_limit_is_refused_and_writes_nothing() {
    let mut h = harness();
    h.cfg.max_record_bytes = 4096;
    let (log, _, _rx) = h.open().await.unwrap();
    assert_eq!(log.record_limit(), 4096);
    log.append(samples()[3].clone()).await.unwrap();
    let seg = h.segment_files().pop().unwrap();
    let before = std::fs::read(&seg).unwrap();

    let big = effect_result_with(vec![7; 4096]);
    let bytes = big.encoded_len();
    let err = log.append(big.clone()).await.unwrap_err();
    assert!(
        matches!(err, LogError::TooLarge { kind, bytes: b, limit: 4096 }
            if kind == kronik_proto::kind::EFFECT_RESULT && b == bytes),
        "{err:?}"
    );
    assert!(err.is_refusal(), "{err}");
    // A batch with one record over the limit writes none of them.
    let err = log
        .append_all(vec![samples()[4].clone(), big])
        .await
        .unwrap_err();
    assert!(err.is_refusal(), "{err}");
    assert_eq!(
        std::fs::read(&seg).unwrap(),
        before,
        "a refused body was written"
    );

    // No LSN was used and the writer goes on; a body at the limit fits.
    assert_eq!(log.append(samples()[4].clone()).await.unwrap(), 2);
    // Between 128 and 16 383 body bytes every length prefix keeps its size.
    let overhead = effect_result_with(vec![1; 4000]).encoded_len() - 4000;
    let at_limit = effect_result_with(vec![1; 4096 - overhead]);
    assert_eq!(at_limit.encoded_len(), 4096);
    assert_eq!(log.append(at_limit).await.unwrap(), 3);
    drop(log);
    assert_eq!(h.read_all().await.unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_default_limit_is_max_record() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    assert_eq!(log.record_limit(), MAX_RECORD as usize);
    // `vec![0; n]` maps zero pages lazily and `encoded_len` never touches
    // them: this costs no 128 MiB of memory.
    let err = log
        .append(effect_result_with(vec![0; MAX_RECORD as usize]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LogError::TooLarge { limit, bytes, .. }
            if limit == MAX_RECORD as usize && bytes > limit),
        "{err:?}"
    );
    // A test hook above the format's limit does not raise it.
    let mut cfg = h.cfg.clone();
    cfg.max_record_bytes = u32::MAX;
    assert_eq!(cfg.record_limit(), MAX_RECORD as usize);
}

/// Writes one complete, CRC-valid entry for `record` at the end of the
/// segment file `path` without copying its body a second time.
fn append_raw_entry(path: &Path, lsn: Lsn, record: &Record) {
    use std::io::Write as _;
    let payload = record.encode();
    let mut crc = crc32c::crc32c(&lsn.to_le_bytes());
    crc = crc32c::crc32c_append(crc, &[record.kind()]);
    crc = crc32c::crc32c_append(crc, &payload);
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&(payload.len() as u32).to_le_bytes())
        .unwrap();
    file.write_all(&crc.to_le_bytes()).unwrap();
    file.write_all(&lsn.to_le_bytes()).unwrap();
    file.write_all(&[record.kind()]).unwrap();
    file.write_all(&payload).unwrap();
    file.sync_all().unwrap();
}

/// A release before 0.5 could append a record over `MAX_RECORD`, and its
/// own start then cut that acknowledged record off as a "torn tail". The
/// record is complete and its CRC holds: it is read, never truncated.
#[tokio::test(flavor = "multi_thread")]
async fn a_complete_record_over_the_limit_is_read_and_never_truncated() {
    let h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    log.append(samples()[3].clone()).await.unwrap();
    drop(log);
    let seg = h.segment_files().pop().unwrap();
    let body = MAX_RECORD as usize + 4096;
    append_raw_entry(&seg, 2, &effect_result_with(vec![0x5a; body]));
    let len = std::fs::metadata(&seg).unwrap().len();
    assert!(len > u64::from(MAX_RECORD));

    let (log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(
        opened.truncated_bytes, 0,
        "an acknowledged record was cut off"
    );
    assert_eq!(opened.next_lsn, 3);
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), len);
    assert_eq!(log.append(samples()[4].clone()).await.unwrap(), 3);
    drop(log);

    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let mut seen = Vec::new();
    reader
        .read(2, 3, |c| {
            seen.push((c.lsn, c.record.encoded_len(), c.pos));
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, 2);
    assert!(seen[0].1 > MAX_RECORD as usize);
    // The positional read (history) and the bounded reader agree.
    let at = reader.read_at(seen[0].2).await.unwrap();
    assert_eq!((at.lsn, at.record.encoded_len()), (2, seen[0].1));
    let mut bounded = Vec::new();
    reader
        .read_while(2, 3, |c| {
            bounded.push(c.lsn);
            Ok(true)
        })
        .await
        .unwrap();
    assert_eq!(bounded, vec![2, 3]);
}

/// An incomplete entry, whatever its length says, is still a torn tail;
/// a length that runs past the file sizes no read.
#[tokio::test(flavor = "multi_thread")]
async fn an_incomplete_entry_is_torn_and_its_length_sizes_no_read() {
    let mut h = harness();
    let (log, _, mut rx) = h.open().await.unwrap();
    log.append(samples()[3].clone()).await.unwrap();
    let first = rx.recv().await.unwrap();
    drop(log);
    let seg = h.segment_files().pop().unwrap();
    let full = std::fs::read(&seg).unwrap();
    // The envelope of an entry that claims nearly 4 GiB, then 100 bytes.
    let mut torn = full.clone();
    torn.extend_from_slice(&(u32::MAX - 16).to_le_bytes());
    torn.extend_from_slice(&[0xab; 4 + 8 + 1 + 100]);
    std::fs::write(&seg, &torn).unwrap();

    // A positional read of it is corrupt, and no read asks for more bytes
    // than the file has.
    let calls = Arc::new(Mutex::new(Vec::new()));
    let plain_env = h.env.clone();
    h.env.fs = Arc::new(ReadFs {
        inner: plain_env.fs.clone(),
        calls: calls.clone(),
    });
    let reader = LogReader::new(h.env.clone(), h.cfg.dir.clone(), "main");
    let pos = Position {
        segment: first.pos.segment,
        offset: full.len() as u64,
    };
    assert!(matches!(
        reader.read_at(pos).await,
        Err(LogError::Corrupt(_))
    ));
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .all(|&(_, len)| len <= torn.len()),
        "{:?}",
        calls.lock().unwrap()
    );
    // The bounded reader treats it as the unacknowledged tail it is.
    reader.read_while(1, Lsn::MAX, |_| Ok(true)).await.unwrap();
    h.env = plain_env;

    let (_log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 2);
    assert_eq!(opened.truncated_bytes, (torn.len() - full.len()) as u64);
    assert_eq!(std::fs::read(&seg).unwrap(), full);
}

/// The state database applied records through `acknowledged_through`, so
/// they were fsynced and acknowledged: a damaged one is corruption, never a
/// torn tail. Past that LSN the torn-tail rule is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledged_record_is_never_truncated() {
    let mut h = harness();
    let (log, _, _rx) = h.open().await.unwrap();
    for r in samples().into_iter().skip(3).take(3) {
        log.append(r).await.unwrap();
    }
    drop(log);
    let seg = h.segment_files().pop().unwrap();
    let mut damaged = std::fs::read(&seg).unwrap();
    // Flip a byte of the last record's body: its CRC fails.
    let n = damaged.len();
    damaged[n - 1] ^= 0xff;
    std::fs::write(&seg, &damaged).unwrap();

    h.cfg.acknowledged_through = 3;
    let err = h
        .open()
        .await
        .err()
        .expect("an acknowledged record was damaged");
    assert!(matches!(err, LogError::Corrupt(_)), "{err}");
    let text = err.to_string();
    assert!(
        text.contains("lsn 3") && text.contains("nothing was truncated"),
        "{text}"
    );
    assert_eq!(std::fs::read(&seg).unwrap(), damaged, "the file changed");

    // Applied through 2 only: lsn 3 may be the torn last batch.
    h.cfg.acknowledged_through = 2;
    let (_log, opened, _rx) = h.open().await.unwrap();
    assert_eq!(opened.next_lsn, 3);
    assert!(opened.truncated_bytes > 0);

    // A segment whose header is damaged after it held an applied record
    // is not recreated as an empty one.
    let h2 = harness();
    let (log, _, _rx) = h2.open().await.unwrap();
    log.append(samples()[3].clone()).await.unwrap();
    drop(log);
    let seg = h2.segment_files().pop().unwrap();
    let mut header_damaged = std::fs::read(&seg).unwrap();
    header_damaged[0] ^= 0xff;
    std::fs::write(&seg, &header_damaged).unwrap();
    let mut cfg = h2.cfg.clone();
    cfg.acknowledged_through = 1;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (ftx, _frx) = oneshot::channel();
    let err = Log::open(&h2.env, cfg, tx, ftx)
        .await
        .err()
        .expect("refused");
    assert!(matches!(err, LogError::Corrupt(_)), "{err}");
    assert_eq!(std::fs::read(&seg).unwrap(), header_damaged);
}

#[tokio::test]
async fn canceling_an_unpolled_real_writer_publishes_native_closure_synchronously() {
    struct HeldWriter {
        actual: Arc<dyn kronik_core::env::Spawner>,
        writer: Mutex<Option<BoxFuture<'static, ()>>>,
    }
    impl kronik_core::env::Spawner for HeldWriter {
        fn spawn(&self, name: &'static str, future: BoxFuture<'static, ()>) {
            if name == "log-writer" {
                *self.writer.lock().unwrap() = Some(future);
            } else {
                self.actual.spawn(name, future);
            }
        }
        fn spawn_blocking(&self, name: &'static str, work: Box<dyn FnOnce() + Send + 'static>) {
            self.actual.spawn_blocking(name, work);
        }
    }
    let mut h = harness();
    let held = Arc::new(HeldWriter {
        actual: h.env.spawner.clone(),
        writer: Mutex::new(None),
    });
    h.env.spawner = held.clone();
    let (log, _, _records) = h.open().await.unwrap();
    let publication = Arc::new(Mutex::new(()));
    let writer = log
        .bind_native_execution(publication.clone(), None)
        .unwrap();
    assert!(writer.is_open());
    assert!(
        log.bind_native_execution(Arc::new(Mutex::new(())), None)
            .is_err()
    );
    let unpolled = held.writer.lock().unwrap().take().unwrap();
    drop(unpolled);
    assert!(
        !writer.is_open(),
        "receiver cancellation publishes before Drop returns"
    );
    tokio::time::timeout(Duration::from_secs(2), writer.closed())
        .await
        .unwrap();
    assert!(log.bind_native_execution(publication, None).is_err());
    assert!(matches!(
        log.append(begin("canceled-writer")).await,
        Err(LogError::Stopped(_))
    ));
    assert!(h.read_all().await.unwrap().is_empty());
}

/// A file system that records the syncs: `("dir", path)` and
/// `("data", path)`.
struct SyncFs {
    inner: Arc<dyn Fs>,
    syncs: Arc<Mutex<Vec<(&'static str, PathBuf)>>>,
}

impl Fs for SyncFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.create_dir_all(path)
    }

    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let opened = self.inner.open(path.clone(), mode);
        let syncs = self.syncs.clone();
        Box::pin(async move {
            Ok(Arc::new(SyncFile {
                inner: opened.await?,
                path,
                syncs,
            }) as Arc<dyn File>)
        })
    }

    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.inner.exists(path)
    }

    fn read_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.inner.read_dir(path)
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.rename(from, to)
    }

    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.remove_file(path)
    }

    fn sync_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.syncs.lock().unwrap().push(("dir", path.clone()));
        self.inner.sync_dir(path)
    }
}

struct SyncFile {
    inner: Arc<dyn File>,
    path: PathBuf,
    syncs: Arc<Mutex<Vec<(&'static str, PathBuf)>>>,
}

impl File for SyncFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.len()
    }

    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        self.inner.read_at(offset, len)
    }

    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        self.inner.write_at(offset, data)
    }

    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        self.syncs.lock().unwrap().push(("data", self.path.clone()));
        self.inner.sync_data()
    }
}

/// A process killed without a power loss leaves its last segment's tail,
/// and the name of a segment it created before syncing the directory, in
/// the page cache only. The next open makes both durable before it builds
/// on them: it fsyncs the last segment, active or closed, and the
/// directory, whichever way the segment ended.
#[tokio::test]
async fn open_makes_what_the_last_process_left_durable() {
    for closed in [false, true] {
        let mut h = harness();
        if closed {
            // Every append rolls: the last segment the next open finds is
            // closed by a footer, and that open creates the next one.
            h.cfg.segment_max_bytes = 1;
        }
        {
            let (log, _, _rx) = h.open().await.unwrap();
            for r in samples().into_iter().take(3) {
                log.append(r).await.unwrap();
            }
        }
        let segments = h.segment_files();
        let last = segments.last().unwrap().clone();
        let syncs = Arc::new(Mutex::new(Vec::new()));
        let mut env = h.env.clone();
        env.fs = Arc::new(SyncFs {
            inner: h.env.fs.clone(),
            syncs: syncs.clone(),
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let (ftx, _frx) = oneshot::channel();
        let (_log, opened) = Log::open(&env, h.cfg.clone(), tx, ftx).await.unwrap();
        assert_eq!(opened.next_lsn, 4, "closed {closed}");
        let syncs = syncs.lock().unwrap().clone();
        assert!(
            syncs.contains(&("data", last.clone())),
            "closed {closed}: the last segment {last:?} was not fsynced: {syncs:?}"
        );
        assert!(
            syncs.contains(&("dir", h.cfg.dir.clone())),
            "closed {closed}: the log directory was not synced: {syncs:?}"
        );
    }
}
