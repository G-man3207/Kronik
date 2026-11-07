//! What certifying the secret inventory costs, and what it leaves on disk.
//!
//! A start reads the log in whole segment images however long the log is,
//! never replaces the last valid coverage watermark with anything else, and
//! hands the node a certificate that the node's own first cycle does not
//! retire again. The file system under each node is wrapped to count and
//! order what the node asks of it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use super::*;
use bytes::Bytes;
use kronik_core::causal;
use kronik_core::env::{BoxFuture, File, Fs, OpenMode};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;

const MANIFEST: &str = "secret-coverage.json";
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const TEMPORARY: &str = "secret-coverage.json.tmp";

/// What the file system under a node was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Read(PathBuf),
    Write(PathBuf),
    SyncData(PathBuf),
    Rename {
        from: PathBuf,
        to: PathBuf,
        ok: bool,
    },
    SyncDir(PathBuf),
}

#[derive(Default)]
struct Recording {
    ops: Mutex<Vec<Op>>,
    /// The text of every watermark renamed into place.
    manifests: Mutex<Vec<String>>,
    /// While set, a read of a log segment waits here for a permit.
    gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
}

impl Recording {
    /// Reads of log segments: one per segment image, or one per record.
    fn segment_reads(&self) -> usize {
        lock(&self.ops)
            .iter()
            .filter(
                |op| matches!(op, Op::Read(path) if path.extension().is_some_and(|e| e == "seg")),
            )
            .count()
    }
}

/// The real file system, recorded; reads of a log segment and writes to the
/// watermark's temporary file can be slowed so that a rebuild that reads
/// record by record, or two writers that overlap, cannot hide in a fast test.
struct RecordingFs {
    inner: Arc<dyn Fs>,
    rec: Arc<Recording>,
    read_delay: Duration,
    write_delay: Duration,
}

struct RecordingFile {
    inner: Arc<dyn File>,
    path: PathBuf,
    rec: Arc<Recording>,
    read_delay: Duration,
    write_delay: Duration,
}

impl Fs for RecordingFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let opened = self.inner.open(path.clone(), mode);
        let (rec, read_delay, write_delay) = (self.rec.clone(), self.read_delay, self.write_delay);
        Box::pin(async move {
            let inner = opened.await?;
            Ok(Arc::new(RecordingFile {
                inner,
                path,
                rec,
                read_delay,
                write_delay,
            }) as Arc<dyn File>)
        })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        if to.file_name().is_some_and(|name| name == MANIFEST) {
            // The renamed file's text, before the rename moves it.
            lock(&self.rec.manifests).push(std::fs::read_to_string(&from).unwrap_or_default());
        }
        let rec = self.rec.clone();
        let renamed = self.inner.rename(from.clone(), to.clone());
        Box::pin(async move {
            let result = renamed.await;
            lock(&rec.ops).push(Op::Rename {
                from,
                to,
                ok: result.is_ok(),
            });
            result
        })
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        lock(&self.rec.ops).push(Op::SyncDir(dir.clone()));
        self.inner.sync_dir(dir)
    }
    fn available(&self, path: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.available(path)
    }
    fn read_secure(
        &self,
        path: PathBuf,
        max_bytes: usize,
    ) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        self.inner.read_secure(path, max_bytes)
    }
    fn write_secure(&self, path: PathBuf, bytes: Vec<u8>) -> BoxFuture<'static, io::Result<()>> {
        self.inner.write_secure(path, bytes)
    }
    fn write_secure_new(&self, path: PathBuf, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
        self.inner.write_secure_new(path, bytes)
    }
}

impl File for RecordingFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        lock(&self.rec.ops).push(Op::Read(self.path.clone()));
        let (inner, delay, rec) = (self.inner.clone(), self.read_delay, self.rec.clone());
        let segment = self.path.extension().is_some_and(|e| e == "seg");
        Box::pin(async move {
            if segment {
                let gate = lock(&rec.gate).clone();
                if let Some(gate) = gate {
                    gate.acquire().await.unwrap().forget();
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            inner.read_at(offset, len).await
        })
    }
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        lock(&self.rec.ops).push(Op::Write(self.path.clone()));
        let (inner, delay) = (self.inner.clone(), self.write_delay);
        let temporary = self.path.file_name().is_some_and(|name| name == TEMPORARY);
        Box::pin(async move {
            if temporary && !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            inner.write_at(offset, data).await
        })
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        lock(&self.rec.ops).push(Op::SyncData(self.path.clone()));
        self.inner.sync_data()
    }
}

fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}

fn recording(read_delay: Duration, write_delay: Duration) -> (Env, Arc<Recording>) {
    let rec = Arc::new(Recording::default());
    let mut environment = env();
    environment.fs = Arc::new(RecordingFs {
        inner: environment.fs.clone(),
        rec: rec.clone(),
        read_delay,
        write_delay,
    });
    (environment, rec)
}

fn config() -> crate::NodeConfig {
    crate::NodeConfig {
        concurrency: 1,
        group_commit_window: Some(Duration::ZERO),
        ..Default::default()
    }
}

fn audit() -> pb::Audit {
    system_audit(&env(), "certification fixture")
}

/// Runs `future` on a runtime of its own, then drops the runtime with
/// everything the node spawned on it: the node is gone as a `kill -9` leaves it.
fn run<T>(future: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let output = runtime.block_on(future);
    drop(runtime);
    output
}

async fn start(data: &Path, environment: Env) -> Arc<Node> {
    crate::start_local(environment, data, config())
        .await
        .unwrap()
}

/// Waits until the node's own cycle has made its first pass: the fixtures
/// below write the ledger directly, which that pass would race.
async fn settle(node: &Node) {
    let runtime = node.runtime().unwrap();
    for _ in 0..400 {
        if runtime.certified.borrow().1 {
            return;
        }
        node.env.clock.sleep(Duration::from_millis(5)).await;
    }
    panic!("the node's first cycle never finished");
}

/// Waits until the node's own cycle has certified every change made so far
/// and is idle again, so that it cannot rebuild between two steps of a test.
async fn quiesce(node: &Node) {
    let runtime = node.runtime().unwrap();
    let (mut builds, mut idle) = (u64::MAX, 0);
    for _ in 0..600 {
        let now = runtime.stats.builds.load(Relaxed);
        if now == builds && runtime.cache.complete(node.epoch()) {
            idle += 1;
            if idle == 20 {
                return;
            }
        } else {
            idle = 0;
        }
        builds = now;
        node.env.clock.sleep(Duration::from_millis(5)).await;
    }
    panic!("the node's cycle never went idle");
}

/// An explicit certification, repeated while a change of the inventory
/// that races it makes it give way (the documented fail-closed window).
async fn certify(node: &Node) {
    let original = node.local_operator_authority().unwrap();
    for _ in 0..200 {
        match node.refresh_secret_inventory(original.clone()).await {
            Ok(()) => return,
            Err(error) if error.code == ErrorCode::SecretUnavailable => {
                node.env.clock.sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("{error}"),
        }
    }
    panic!("the inventory never certified");
}

/// `count` records that mean nothing to the inventory, committed by sixteen
/// writers so that the log writer groups their fsyncs.
async fn append_noise(node: &Arc<Node>, count: usize) {
    let mut writers = Vec::new();
    for writer in 0..16 {
        let node = node.clone();
        let share = count / 16 + usize::from(writer < count % 16);
        writers.push(tokio::spawn(async move {
            for index in 0..share {
                node.commit(Record::AuditEvent(pb::AuditEvent {
                    action: "test.noise".into(),
                    target: format!("{writer}-{index}"),
                    details: Default::default(),
                    audit: Some(audit()),
                    operation: None,
                }))
                .await
                .unwrap();
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
}

/// A node that lived over `data`: certified at its start, `covered` records
/// more and one explicit certification (the watermark), `after` records
/// more; then killed. Returns the last applied LSN.
fn grow(data: &Path, covered: usize, after: usize) -> u64 {
    run(async {
        let node = start(data, env()).await;
        settle(&node).await;
        append_noise(&node, covered).await;
        certify(&node).await;
        append_noise(&node, after).await;
        node.applied_lsn()
    })
}

fn manifest(data: &Path) -> coverage::CoverageWatermark {
    serde_json::from_slice(&std::fs::read(data.join(MANIFEST)).unwrap()).unwrap()
}

#[test]
fn a_start_reads_the_log_by_segment_whatever_its_length() {
    let mut reads = Vec::new();
    for covered in [300, 1_200] {
        let data = tempfile::tempdir().unwrap();
        grow(data.path(), covered, 30);
        reads.push(run(async {
            let (environment, rec) = recording(Duration::ZERO, Duration::ZERO);
            let node = start(data.path(), environment).await;
            assert!(node.secret_values().is_ok());
            rec.segment_reads()
        }));
    }
    assert!(
        reads[1] <= 24 && reads[1] <= reads[0] + 2,
        "a start of a log of 300 records read segments {} times, of 1,200 records {} times",
        reads[0],
        reads[1]
    );
}

#[test]
fn a_start_leaves_only_valid_watermarks_on_disk() {
    let data = tempfile::tempdir().unwrap();
    grow(data.path(), 600, 30);
    let before = manifest(data.path());
    assert!(before.certified_through_lsn > 0);
    let written = run(async {
        let (environment, rec) = recording(Duration::ZERO, Duration::ZERO);
        let node = start(data.path(), environment).await;
        node.env.clock.sleep(Duration::from_millis(200)).await;
        lock(&rec.manifests).clone()
    });
    assert!(!written.is_empty(), "the start wrote no watermark");
    for text in &written {
        let watermark: coverage::CoverageWatermark = serde_json::from_str(text).unwrap();
        assert!(
            watermark.certified_through_lsn >= before.certified_through_lsn,
            "a watermark the last valid one was replaced with: {text}"
        );
    }
    assert!(manifest(data.path()).certified_through_lsn >= before.certified_through_lsn);
}

#[test]
fn a_watermark_ahead_of_the_log_is_ignored_and_replaced() {
    let data = tempfile::tempdir().unwrap();
    let applied = grow(data.path(), 200, 0);
    let mut ahead = manifest(data.path());
    ahead.certified_through_lsn = applied + 5_000;
    std::fs::write(
        data.path().join(MANIFEST),
        serde_json::to_vec(&ahead).unwrap(),
    )
    .unwrap();
    run(async {
        let node = start(data.path(), env()).await;
        let at_start = node.applied_lsn();
        // The whole log was read: the watermark certified nothing.
        assert!(node.runtime().unwrap().stats.records.load(Relaxed) >= at_start);
        assert!(node.secret_values().is_ok());
        assert_eq!(manifest(data.path()).certified_through_lsn, at_start);
    });
}

#[test]
fn a_certificate_built_from_the_watermark_is_the_one_a_full_scan_builds() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = start(data.path(), env()).await;
        settle(&node).await;
        let metadata = install_file(&node, b"fingerprinted-value").await;
        let begin = begin(&node);
        let cited = persist(&node, &begin, &[reveal(metadata, 0)]).await;
        quiesce(&node).await;
        // The watermark stops just before the record that cites the secret:
        // this certification reads the citation.
        let mut watermark = manifest(data.path());
        watermark.certified_through_lsn = cited - 1;
        std::fs::write(
            data.path().join(MANIFEST),
            serde_json::to_vec(&watermark).unwrap(),
        )
        .unwrap();
        certify(&node).await;
        let after_delta = node.native_secret_snapshot().unwrap();
        // A full scan reads it too.
        std::fs::remove_file(data.path().join(MANIFEST)).unwrap();
        certify(&node).await;
        let full = node.native_secret_snapshot().unwrap();
        // Now the watermark covers the citation: the scan meets none.
        certify(&node).await;
        let after_nothing = node.native_secret_snapshot().unwrap();
        let values = |snapshot: &CertifiedSecretSnapshot| -> Vec<(String, Vec<u8>)> {
            snapshot
                .values
                .iter()
                .map(|(name, value)| (name.clone(), value.to_vec()))
                .collect()
        };
        assert_eq!(after_delta.fingerprint, full.fingerprint);
        assert_eq!(full.fingerprint, after_nothing.fingerprint);
        assert_eq!(values(&after_delta), values(&full));
        assert_eq!(values(&full), values(&after_nothing));
        assert_eq!(full.references, after_nothing.references);
    });
}

#[test]
fn a_v0_4_0_manifest_is_never_a_watermark() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join(MANIFEST);
        let manifest = |schema: &str, through: u64| {
            format!(
                r#"{{"schema":"kronik.secret-coverage/{schema}","branch":"main","certified_through_lsn":{through},"coverage_epoch":4,"coverage_fingerprint":"","store_generation":"00","scan_frontier":{{"base":1,"through":8191,"head":0,"store_generation":"00","branch":"main","references_empty":true}}}}"#
            )
        };
        // What v0.4.0 left after every start: a scan under way.
        std::fs::write(&path, manifest("v1", 0)).unwrap();
        assert!(coverage::load(&env(), data.path(), "main").await.is_none());
        // One that only looks valid: v0.4.0 stored the applied LSN of the
        // moment it wrote the file, which can be ahead of the last record
        // its scan read, so a restart must not skip up to it.
        std::fs::write(&path, manifest("v1", 77)).unwrap();
        assert!(coverage::load(&env(), data.path(), "main").await.is_none());
        std::fs::write(&path, manifest("v2", 78)).unwrap();
        let loaded = coverage::load(&env(), data.path(), "main").await.unwrap();
        assert_eq!(loaded.certified_through_lsn, 78);
        // A schema this build does not know says nothing it can trust.
        std::fs::write(&path, manifest("v3", 79)).unwrap();
        assert!(coverage::load(&env(), data.path(), "main").await.is_none());
    });
}

/// The watermark the v0.4.0 release wrote into its compatibility corpus.
const V0_4_0_WATERMARK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/compatibility/v0.4.0/data/secret-coverage.json"
));

#[test]
fn the_watermark_the_v0_4_0_release_wrote_is_not_trusted() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        std::fs::write(data.path().join(MANIFEST), V0_4_0_WATERMARK).unwrap();
        // The real file: schema v1, LSN 7, a valid store generation.
        let text = std::fs::read_to_string(data.path().join(MANIFEST)).unwrap();
        assert!(text.contains(r#""schema":"kronik.secret-coverage/v1""#));
        assert!(text.contains(r#""certified_through_lsn":7"#));
        assert!(coverage::load(&env(), data.path(), "main").await.is_none());
    });
}

#[test]
fn a_start_after_a_v0_4_0_manifest_reads_the_whole_log_and_writes_v2() {
    let data = tempfile::tempdir().unwrap();
    let applied = grow(data.path(), 600, 40);
    let mut written = manifest(data.path());
    assert_eq!(written.schema, coverage::SCHEMA);
    assert!(
        0 < written.certified_through_lsn && written.certified_through_lsn < applied,
        "a watermark that a start would trust"
    );
    // What v0.4.0 would have left: its schema, a valid-looking LSN and a
    // fingerprint of its own.
    written.schema = "kronik.secret-coverage/v1".into();
    written.coverage_fingerprint =
        "82c0696d3c20ca2fc50c024e80d020ac5d672b77ed8a2d0a7ea1de812c9311a4".into();
    std::fs::write(
        data.path().join(MANIFEST),
        serde_json::to_vec(&written).unwrap(),
    )
    .unwrap();
    run(async {
        let node = start(data.path(), env()).await;
        settle(&node).await;
        quiesce(&node).await;
        // Nothing of the old file is trusted: the whole retained log is read,
        // from its first record.
        let read = node.runtime().unwrap().stats.records.load(Relaxed);
        assert_eq!(read, node.applied_lsn(), "records read at the start");
        assert!(read >= applied);
        assert!(node.secret_values().is_ok());
        // And the file is v2 now, with the exact LSN the scan reached.
        let rewritten = manifest(data.path());
        assert_eq!(rewritten.schema, coverage::SCHEMA);
        assert_eq!(rewritten.certified_through_lsn, read);
        assert_ne!(rewritten.coverage_fingerprint, written.coverage_fingerprint);
    });
}

async fn node() -> (tempfile::TempDir, Arc<Node>) {
    let data = tempfile::tempdir().unwrap();
    let node = start(data.path(), env()).await;
    settle(&node).await;
    (data, node)
}

#[tokio::test]
async fn a_scan_agrees_with_the_record_reader_over_many_segments() {
    let data = tempfile::tempdir().unwrap();
    let node = crate::start_local(
        env(),
        data.path(),
        crate::NodeConfig {
            segment_max_bytes: Some(1_024),
            ..config()
        },
    )
    .await
    .unwrap();
    settle(&node).await;
    let metadata = install_file(&node, b"scanned-value").await;
    for turn in 0..6u32 {
        let mut begin = begin(&node);
        begin.execution_id = format!("{turn:032x}");
        persist(&node, &begin, &[reveal(metadata.clone(), 0)]).await;
        append_noise(&node, 24).await;
    }
    let applied = node.applied_lsn();
    let segments = node.reader().starts().await.unwrap();
    assert!(segments.len() > scan::SCAN_WIDTH + 2, "{segments:?}");

    // The record reader, one record at a time, is the reference.
    let reference = |from: u64, upto: u64| {
        let node = node.clone();
        async move {
            let mut expected = scan::LogScan::default();
            node.reader()
                .read_while(from, upto, |committed| {
                    expected.visit(&committed.record, &node.sealer).unwrap();
                    Ok(true)
                })
                .await
                .unwrap();
            expected
        }
    };
    for (from, upto) in [
        (1, applied),
        (applied / 2, applied),
        (1, applied / 2),
        (applied - 1, applied),
        (3, 3),
    ] {
        let expected = reference(from, upto).await;
        let found = node.scan_secret_use(from, upto).await.unwrap();
        assert_eq!(found.records, upto - from + 1, "{from}..={upto}");
        assert_eq!(found.records, expected.records, "{from}..={upto}");
        assert_eq!(found.references, expected.references, "{from}..={upto}");
        assert_eq!(found.touched, expected.touched, "{from}..={upto}");
    }
    let everything = node.scan_secret_use(1, applied).await.unwrap();
    assert_eq!(everything.references.len(), 1);
    assert!(everything.touched.contains("token"));
    assert_eq!(node.scan_secret_use(5, 4).await.unwrap().records, 0);

    // What the log does not hold is an error, not an empty answer.
    let past = node.scan_secret_use(1, applied + 3).await.unwrap_err();
    assert_eq!(past.code, ErrorCode::SecretUnavailable);
    let lost = data
        .path()
        .join("branches/main/log")
        .join(kronik_log::segment_name(segments[segments.len() / 2]));
    std::fs::remove_file(lost).unwrap();
    let gap = node.scan_secret_use(1, applied).await.unwrap_err();
    assert_eq!(gap.code, ErrorCode::SecretUnavailable);
}

#[tokio::test]
async fn a_certification_reads_only_the_records_the_watermark_does_not_cover() {
    let (_data, node) = node().await;
    append_noise(&node, 600).await;
    certify(&node).await;
    let stats = &node.runtime().unwrap().stats;
    let (builds, records) = (stats.builds.load(Relaxed), stats.records.load(Relaxed));
    append_noise(&node, 48).await;
    certify(&node).await;
    assert_eq!(stats.builds.load(Relaxed), builds + 1);
    let read = stats.records.load(Relaxed) - records;
    assert!(
        (48..=52).contains(&read),
        "a log of 650 records, 48 of them after the watermark: {read} records read"
    );
}

#[test]
fn a_restart_certifies_only_the_records_after_its_watermark() {
    let data = tempfile::tempdir().unwrap();
    let applied = grow(data.path(), 600, 40);
    run(async {
        let node = start(data.path(), env()).await;
        let stats = &node.runtime().unwrap().stats;
        assert_eq!(stats.builds.load(Relaxed), 1);
        let read = stats.records.load(Relaxed);
        assert!(
            (40..applied / 4).contains(&read),
            "{read} records read at a start after a watermark at {} of {applied}",
            applied - 40
        );
    });
}

// The fixtures below are those of `recovery/tests.rs`: a secret in the
// ledger and a turn whose record cites it.

fn plain(bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn begin(node: &Node) -> pb::TurnBegin {
    pb::TurnBegin {
        execution_id: "0123456789abcdef0123456789abcdef".into(),
        actor: Some(pb::ActorRef {
            kind: "recover".into(),
            key: "blocked".into(),
        }),
        code_hash: vec![9; 32],
        engine_version: kronik_runtime::ENGINE_VERSION.into(),
        causal_key: Some(causal::root("recorded-root".into())),
        logical_time_ms: 29,
        random_seed: vec![6; 32],
        config_epoch: node.epoch(),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "GET".into(),
                path: "/original-input".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(plain(Vec::new()).unwrap())),
                }),
                ..Default::default()
            })),
        }),
    }
}

fn reveal(metadata: SecretMeta, ordinal: u32) -> pb::EffectRecord {
    let mut reference = pb::SecretRef {
        name: metadata.name.clone(),
        version_hash: metadata.version_hash,
        ..Default::default()
    };
    reference.set_resolved_version(metadata.version).unwrap();
    pb::EffectRecord {
        ordinal,
        kind: "secret.reveal".into(),
        status: pb::EffectStatus::Ok as i32,
        target: format!("secret-reveal:{}", metadata.name),
        fingerprint: vec![3; 32],
        grounding: pb::Grounding::Live as i32,
        request: plain(
            pb::RevealEffectRequest {
                secret: Some(reference),
            }
            .encode_to_vec(),
        ),
        ..Default::default()
    }
}

async fn install_file(node: &Node, value: &[u8]) -> SecretMeta {
    let runtime = node.runtime().unwrap();
    let version = node.next_secret_version("token").await.unwrap();
    let hash = runtime.file.version_hash("token", version, value).unwrap();
    let mut row = node.secret_record(
        &Scope::file("token", 0),
        version,
        version.to_string(),
        hash,
        false,
        audit(),
    );
    node.secret_publish(row.clone()).await.unwrap();
    let metadata = runtime
        .file
        .set_at("token", version, value, [5; 24], 29, "system", "fixture")
        .unwrap();
    row.phase = Phase::Active as i32;
    node.secret_publish(row).await.unwrap();
    metadata
}

/// Commits the turn's records; returns the LSN of its `TurnBegin`.
async fn persist(node: &Node, begin: &pb::TurnBegin, effects: &[pb::EffectRecord]) -> u64 {
    let first = node.commit(Record::TurnBegin(begin.clone())).await.unwrap();
    for effect in effects {
        node.commit(Record::EffectResult(pb::EffectResult {
            execution_id: begin.execution_id.clone(),
            effect: Some(effect.clone()),
        }))
        .await
        .unwrap();
    }
    first
}
