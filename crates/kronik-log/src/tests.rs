// Tests drive the log from several tokio tasks to mix records in batches.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

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
            audit,
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
