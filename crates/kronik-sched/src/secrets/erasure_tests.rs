//! Sealed requests of erased subjects and the reference scan.
//!
//! The scan opens every sealed request of a secret-using effect, because only
//! the plaintext tells whether it cites a secret version. Erasing a subject
//! destroys its key on purpose, so its requests can never be opened again; the
//! scan must read that as "nothing to cite", not as a loss of coverage. A
//! request whose key is merely unavailable is not erased: coverage stays
//! refused (the sealer's `Erased` and `Unreadable` are the line between them).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use super::certification_tests::{
    MANIFEST, append_noise, audit, begin, certify, config, env, install_file, manifest, quiesce,
    recording, run, settle, start,
};
use super::*;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

const TOKEN: &[u8] = b"value-of-a-secret-an-erased-request-cited";

fn authority(node: &Node) -> AuthLease {
    node.local_operator_authority().unwrap()
}

async fn privacy(node: &Node, mode: pb::PrivacyState) {
    node.set_privacy_mode(mode, audit(), false, authority(node))
        .await
        .unwrap();
}

async fn erase(node: &Node, subject: &str) {
    node.erase_subject(subject, audit(), false, authority(node))
        .await
        .unwrap();
}

/// The effect of a turn with `request` as recorded: tagged with `subject`, and
/// plain, until a node whose privacy mode is on commits it.
fn effect(subject: Option<&str>, request: Vec<u8>) -> pb::EffectRecord {
    pb::EffectRecord {
        ordinal: 0,
        kind: "http.fetch".into(),
        status: pb::EffectStatus::Ok as i32,
        target: "http:127.0.0.1".into(),
        fingerprint: vec![3; 32],
        grounding: pb::Grounding::Live as i32,
        request: Some(pb::Sealable {
            subject: subject.map(str::to_owned),
            value: Some(pb::sealable::Value::Plain(request)),
        }),
        ..Default::default()
    }
}

/// A POST that cites the secret version `cites`, if any, in a header.
fn fetch(subject: Option<&str>, cites: Option<(&str, u64, &[u8])>) -> pb::EffectRecord {
    let headers = cites
        .map(|(name, version, hash)| {
            let mut reference = pb::SecretRef {
                name: name.into(),
                version_hash: hash.to_vec(),
                ..Default::default()
            };
            reference.set_resolved_version(version).unwrap();
            vec![pb::HttpEffectHeader {
                name: "authorization".into(),
                value: Some(pb::http_effect_header::Value::Secret(reference)),
            }]
        })
        .unwrap_or_default();
    effect(
        subject,
        pb::HttpEffectRequest {
            method: "POST".into(),
            url: "http://127.0.0.1:9/hook".into(),
            headers,
            body: b"the body of the request".to_vec(),
            fingerprint_version: 2,
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn cites(meta: &SecretMeta) -> Option<(&str, u64, &[u8])> {
    Some((&meta.name, meta.version, &meta.version_hash))
}

/// Sets `sealed` as the request of `effect`, as the sealing step would have
/// left it: sealed already, so the node commits it as it is.
fn with_sealed(mut effect: pb::EffectRecord, sealed: pb::Sealed) -> pb::EffectRecord {
    if let Some(request) = effect.request.as_mut() {
        request.value = Some(pb::sealable::Value::Sealed(sealed));
    }
    effect
}

/// A finished turn of one effect; returns the LSN of its record. The turns
/// are told apart by `id`.
async fn finished(node: &Node, id: u32, effect: pb::EffectRecord) -> u64 {
    let mut begin = begin(node);
    begin.execution_id = format!("{id:032x}");
    node.commit(Record::TurnBegin(begin.clone())).await.unwrap();
    node.commit(Record::TurnRecord(pb::TurnRecord {
        execution_id: begin.execution_id,
        actor: begin.actor,
        code_hash: begin.code_hash,
        engine_version: begin.engine_version,
        causal_key: begin.causal_key,
        logical_time_ms: begin.logical_time_ms,
        random_seed: begin.random_seed,
        input: begin.input,
        effects: vec![effect],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        config_epoch: begin.config_epoch,
        ..Default::default()
    }))
    .await
    .unwrap()
}

/// A node with the privacy mode on, certified.
async fn private_node(data: &Path, environment: Env) -> Arc<Node> {
    let node = start(data, environment).await;
    settle(&node).await;
    privacy(&node, pb::PrivacyState::On).await;
    quiesce(&node).await;
    node
}

fn stats(node: &Node) -> (u64, u64) {
    let stats = &node.runtime().unwrap().stats;
    (stats.records.load(Relaxed), stats.erased.load(Relaxed))
}

fn values(snapshot: &CertifiedSecretSnapshot) -> Vec<(String, Vec<u8>)> {
    snapshot
        .values
        .iter()
        .map(|(name, value)| (name.clone(), value.to_vec()))
        .collect()
}

#[test]
fn the_sealed_request_of_an_erased_subject_cites_nothing_and_blocks_nothing() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        let token = install_file(&node, TOKEN).await;
        finished(&node, 1, fetch(Some("user:1"), cites(&token))).await;
        finished(&node, 2, fetch(Some("user:2"), cites(&token))).await;
        finished(&node, 3, fetch(Some("user:3"), None)).await;
        let applied = node.applied_lsn();

        // Sealed, both are read: each cites the version.
        let before = node.scan_secret_use(1, applied).await.unwrap();
        assert_eq!(before.erased, 0);
        assert_eq!(before.references.len(), 1, "{:?}", before.references);

        // One of the two subjects is erased. The other's request still cites
        // the version, and the erased one is skipped, not an error.
        erase(&node, "user:1").await;
        let applied = node.applied_lsn();
        let one = node.scan_secret_use(1, applied).await.unwrap();
        assert_eq!(one.erased, 1);
        assert_eq!(one.references, before.references);
        assert_eq!(one.records, applied);

        // Both are erased: no reference is left, and the node certifies.
        erase(&node, "user:2").await;
        let applied = node.applied_lsn();
        let both = node.scan_secret_use(1, applied).await.unwrap();
        assert_eq!(both.erased, 2);
        assert!(both.references.is_empty(), "{:?}", both.references);
        certify(&node).await;
        // The erasure woke the node's own certification too: it clears the
        // certificate for as long as it runs.
        quiesce(&node).await;
        assert!(node.secret_values().is_ok());
    });
}

#[test]
fn a_subject_that_comes_back_after_its_erasure_has_its_new_requests_read() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        let token = install_file(&node, TOKEN).await;
        finished(&node, 1, fetch(Some("user:1"), cites(&token))).await;
        erase(&node, "user:1").await;
        // The key is new, numbered after the erased one: what the subject
        // does from now on is readable, and what it did before is not.
        finished(&node, 2, fetch(Some("user:1"), None)).await;
        let found = node.scan_secret_use(1, node.applied_lsn()).await.unwrap();
        assert_eq!(found.erased, 1);
        assert!(found.references.is_empty(), "{:?}", found.references);
        finished(&node, 3, fetch(Some("user:1"), cites(&token))).await;
        let found = node.scan_secret_use(1, node.applied_lsn()).await.unwrap();
        assert_eq!(found.erased, 1);
        assert_eq!(found.references.len(), 1, "{:?}", found.references);
    });
}

#[test]
fn a_secret_only_erased_requests_cited_stays_a_scrub_value() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        let token = install_file(&node, TOKEN).await;
        finished(&node, 1, fetch(Some("user:1"), cites(&token))).await;
        certify(&node).await;
        quiesce(&node).await;
        let retained = |snapshot: &CertifiedSecretSnapshot| {
            values(snapshot)
                .iter()
                .any(|(name, value)| name == "token" && value.as_slice() == TOKEN)
        };
        assert!(retained(&node.native_secret_snapshot().unwrap()));

        // The only request that cites the version is erased, and the
        // certification starts at the first record: it reads the erased
        // request and finds no citation. The value is still a scrub value.
        erase(&node, "user:1").await;
        // The node's own certification after the erasure is done, so that it
        // cannot write a manifest again behind the one removed here.
        quiesce(&node).await;
        std::fs::remove_file(data.path().join(MANIFEST)).unwrap();
        let (records_before, _) = stats(&node);
        certify(&node).await;
        let (records_after, erased) = stats(&node);
        // It failed once under heavy load, not since in 50 runs: what the
        // builds read says whether the certification started at the first
        // record or at a watermark that came back.
        assert!(
            erased >= 1,
            "the erased request was read: builds since the removal read {} records, \
             the log is applied through {}, a watermark is {}",
            records_after - records_before,
            node.applied_lsn(),
            if data.path().join(MANIFEST).exists() {
                "there now"
            } else {
                "absent"
            }
        );
        let cold = node.native_secret_snapshot().unwrap();
        assert!(retained(&cold), "{:?}", values(&cold));
        assert!(cold.references.is_some());
    });
}

#[test]
fn a_certification_after_an_erasure_is_not_refused() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        // The request lies after the watermark the node has written.
        finished(&node, 1, fetch(Some("user:1"), None)).await;
        finished(&node, 2, fetch(Some("user:2"), None)).await;
        erase(&node, "user:1").await;
        certify(&node).await;
        quiesce(&node).await;
        assert!(node.secret_values().is_ok());
        assert!(stats(&node).1 >= 1);
    });
}

#[test]
fn an_erasure_while_a_certification_reads_the_log_does_not_refuse_it() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let (environment, rec) = recording(Duration::ZERO, Duration::ZERO);
        let node = private_node(data.path(), environment).await;
        finished(&node, 1, fetch(Some("user:1"), None)).await;

        // The certification below reads the request. It waits for its read of
        // the log segment; the subject's key is destroyed meanwhile, the first
        // step of an erasure, so the request is opened after that.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *lock(&rec.gate) = Some(gate.clone());
        let reads = rec.segment_reads();
        let refresh = tokio::spawn({
            let node = node.clone();
            async move { certify(&node).await }
        });
        let waiting = tokio::time::Instant::now();
        while rec.segment_reads() == reads {
            assert!(
                waiting.elapsed() < Duration::from_secs(30),
                "the certification read no segment"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        node.sealer()
            .erase("user:1", node.env.clock.wall_ms())
            .unwrap();
        gate.add_permits(1_000);
        refresh.await.unwrap();

        // The erasure is completed as `recover_erasures` or the API would.
        erase(&node, "user:1").await;
        quiesce(&node).await;
        assert!(node.secret_values().is_ok());
        assert!(stats(&node).1 >= 1);
    });
}

#[test]
fn a_restart_after_an_erasure_certifies_alike_from_a_watermark_and_from_the_first_record() {
    let data = tempfile::tempdir().unwrap();
    let (applied, before_requests) = run(async {
        let node = private_node(data.path(), env()).await;
        let token = install_file(&node, TOKEN).await;
        let before_requests = node.applied_lsn();
        finished(&node, 1, fetch(Some("user:1"), cites(&token))).await;
        finished(&node, 2, fetch(Some("user:2"), cites(&token))).await;
        finished(&node, 3, fetch(Some("user:3"), None)).await;
        erase(&node, "user:1").await;
        erase(&node, "user:3").await;
        certify(&node).await;
        quiesce(&node).await;
        (node.applied_lsn(), before_requests)
    });
    let watermark = manifest(data.path());
    assert!(watermark.certified_through_lsn >= applied - 1);

    // Each start below is a restart of the same data: from the watermark the
    // last certification left, from one that stops before the requests, and
    // from the first record.
    let mut found = Vec::new();
    for (label, from) in [
        ("watermark", Some(watermark.certified_through_lsn)),
        ("before the requests", Some(before_requests)),
        ("first record", None),
    ] {
        match from {
            Some(through) => {
                let mut stale = watermark.clone();
                stale.certified_through_lsn = through;
                std::fs::write(
                    data.path().join(MANIFEST),
                    serde_json::to_vec(&stale).unwrap(),
                )
                .unwrap();
            }
            None => std::fs::remove_file(data.path().join(MANIFEST)).unwrap(),
        }
        let (read, erased, snapshot) = run(async {
            let node = start(data.path(), env()).await;
            assert!(
                node.secret_values().is_ok(),
                "the start from the {label} did not certify"
            );
            let (read, erased) = stats(&node);
            (read, erased, node.native_secret_snapshot().unwrap())
        });
        found.push((label, read, erased, snapshot));
    }
    let (_, warm_read, warm_erased, warm) = &found[0];
    let (_, middle_read, middle_erased, middle) = &found[1];
    let (_, cold_read, cold_erased, cold) = &found[2];
    assert!(
        *warm_read < 8 && *warm_erased == 0,
        "{warm_read} {warm_erased}"
    );
    assert!(
        *middle_read >= 6 && *middle_erased == 2,
        "{middle_read} {middle_erased}"
    );
    assert!(
        *cold_read >= applied && *cold_erased == 2,
        "{cold_read} {cold_erased}"
    );
    // The certificate does not depend on where the scan started.
    assert_eq!(warm.fingerprint, middle.fingerprint);
    assert_eq!(middle.fingerprint, cold.fingerprint);
    assert_eq!(values(warm), values(cold));
    assert_eq!(warm.references, cold.references);
    assert!(
        values(cold)
            .iter()
            .any(|(name, value)| name == "token" && value.as_slice() == TOKEN)
    );
}

#[test]
fn a_start_from_a_v0_4_0_manifest_certifies_over_a_request_erased_before_the_upgrade() {
    let data = tempfile::tempdir().unwrap();
    // What a v0.4.0 node leaves behind: a sealed request, its subject erased,
    // and a manifest in the schema of that release whose LSN is past the
    // request.
    let applied = run(async {
        let node = private_node(data.path(), env()).await;
        let token = install_file(&node, TOKEN).await;
        finished(&node, 1, fetch(Some("user:1"), cites(&token))).await;
        finished(&node, 2, fetch(Some("user:2"), cites(&token))).await;
        erase(&node, "user:1").await;
        certify(&node).await;
        quiesce(&node).await;
        node.applied_lsn()
    });
    let mut written = manifest(data.path());
    assert!(written.certified_through_lsn >= applied - 1);
    written.schema = "kronik.secret-coverage/v1".into();
    std::fs::write(
        data.path().join(MANIFEST),
        serde_json::to_vec(&written).unwrap(),
    )
    .unwrap();

    // The first start after the upgrade trusts none of it: it reads the whole
    // log, the erased request among it, and certifies.
    run(async {
        let node = start(data.path(), env()).await;
        assert!(
            node.secret_values().is_ok(),
            "the start did not certify over the erased request"
        );
        let (read, erased) = stats(&node);
        assert!(read >= applied, "{read} records read of {applied}");
        assert_eq!(erased, 1);
        let token_value = |snapshot: &CertifiedSecretSnapshot| {
            values(snapshot)
                .iter()
                .any(|(name, value)| name == "token" && value.as_slice() == TOKEN)
        };
        assert!(token_value(&node.native_secret_snapshot().unwrap()));
    });
    // And it leaves a manifest of this release's schema, so that the next
    // start reads only what came after.
    assert_eq!(manifest(data.path()).schema, coverage::SCHEMA);
    run(async {
        let node = start(data.path(), env()).await;
        assert!(node.secret_values().is_ok());
        let (read, erased) = stats(&node);
        assert!(read < 8 && erased == 0, "{read} records, {erased} erased");
    });
}

#[test]
fn a_reseal_leaves_tombstones_that_a_full_scan_reads_as_erased() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = crate::start_local(
            env(),
            data.path(),
            crate::NodeConfig {
                segment_max_bytes: Some(2_048),
                ..config()
            },
        )
        .await
        .unwrap();
        settle(&node).await;
        privacy(&node, pb::PrivacyState::On).await;
        quiesce(&node).await;
        finished(&node, 1, fetch(Some("user:1"), None)).await;
        finished(&node, 2, fetch(Some("user:2"), None)).await;
        // Enough records after the requests to close their segment.
        append_noise(&node, 80).await;
        erase(&node, "user:1").await;
        let done = node.reseal(audit(), false, authority(&node)).await.unwrap();
        assert!(done.tombstones >= 1, "{done:?}");
        quiesce(&node).await;

        // The request of the erased subject is a tombstone now; a scan from
        // the first record opens it, and the other subject's request.
        std::fs::remove_file(data.path().join(MANIFEST)).unwrap();
        certify(&node).await;
        quiesce(&node).await;
        assert!(node.secret_values().is_ok());
        assert!(stats(&node).1 >= 1);
    });
}

/// Scans a log of one effect on a node with the privacy mode on.
async fn scan_of(effect: pb::EffectRecord) -> Result<scan::LogScan, ApiError> {
    let data = tempfile::tempdir().unwrap();
    let node = private_node(data.path(), env()).await;
    finished(&node, 1, effect).await;
    node.scan_secret_use(1, node.applied_lsn()).await
}

#[test]
fn a_sealed_request_the_node_cannot_open_and_did_not_erase_fails_closed() {
    run(async {
        // Sealed under a key version this keystore does not hold: a restored
        // or replaced keystore may have it.
        let lost = with_sealed(
            fetch(Some("user:7"), None),
            pb::Sealed {
                key_version: 7,
                nonce: vec![1; 24],
                ciphertext: vec![2; 48],
            },
        );
        let error = scan_of(lost).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);

        // A tombstone of a subject this keystore never erased says nothing it
        // can vouch for: it is not "erased".
        let forged = with_sealed(
            fetch(Some("user:8"), None),
            pb::Sealed {
                key_version: 1,
                nonce: vec![0; 24],
                ciphertext: Vec::new(),
            },
        );
        let error = scan_of(forged).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);

        // A value of a subject whose key is here, damaged.
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        let mut request = fetch(Some("user:9"), None).request.unwrap();
        let entropy = node.env.entropy.clone();
        node.sealer()
            .seal_value(&mut request, &|b: &mut [u8]| entropy.fill(b), 29)
            .unwrap();
        let Some(pb::sealable::Value::Sealed(mut sealed)) = request.value else {
            panic!("the request was not sealed");
        };
        sealed.ciphertext[0] ^= 1;
        finished(&node, 1, with_sealed(fetch(Some("user:9"), None), sealed)).await;
        let error = node
            .scan_secret_use(1, node.applied_lsn())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);
        // And the node does not certify over it.
        let error = node
            .refresh_secret_inventory(authority(&node))
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SecretUnavailable);
    });
}

#[test]
fn a_tombstone_of_a_subject_the_keystore_erased_is_read_as_erased() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = private_node(data.path(), env()).await;
        // The subject has a key, then none: erased through version 1.
        finished(&node, 1, fetch(Some("user:5"), None)).await;
        erase(&node, "user:5").await;
        finished(
            &node,
            2,
            with_sealed(
                fetch(Some("user:5"), None),
                pb::Sealed {
                    key_version: 1,
                    nonce: vec![0; 24],
                    ciphertext: Vec::new(),
                },
            ),
        )
        .await;
        let found = node.scan_secret_use(1, node.applied_lsn()).await.unwrap();
        assert_eq!(found.erased, 2);
        assert!(found.references.is_empty());
    });
}

#[test]
fn a_plain_request_of_an_erased_subject_still_has_to_be_covered() {
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = start(data.path(), env()).await;
        settle(&node).await;
        // Written while the mode was off, it stays plain: erasing the subject
        // does not touch it (`kronik privacy erase` counts such values), so
        // what it cites has to be a version the ledger knows.
        finished(
            &node,
            1,
            fetch(Some("user:4"), Some(("ghost", 3, &[8; 16]))),
        )
        .await;
        let refused = |node: Arc<Node>| async move {
            let found = node.scan_secret_use(1, node.applied_lsn()).await.unwrap();
            assert!(found.references.contains_key(&("ghost".to_owned(), 3)));
            assert_eq!(found.erased, 0);
            node.refresh_secret_inventory(authority(&node))
                .await
                .unwrap_err()
                .code
        };
        assert_eq!(refused(node.clone()).await, ErrorCode::SecretUnavailable);
        erase(&node, "user:4").await;
        assert_eq!(refused(node.clone()).await, ErrorCode::SecretUnavailable);
        assert_eq!(stats(&node).1, 0);
    });
}

/// The bytes of each segment of `log`, by start.
fn segments(log: &Path) -> std::collections::BTreeMap<kronik_core::ids::Lsn, Vec<u8>> {
    kronik_log::segment_starts(log)
        .unwrap()
        .into_iter()
        .map(|start| {
            let bytes = std::fs::read(log.join(kronik_log::segment_name(start))).unwrap();
            (start, bytes)
        })
        .collect()
}

/// A reseal marks a segment for the shipper durably before the resealed
/// image replaces it: once a segment is resealed no reseal finds it again,
/// so a mark lost after the rename would leave the plain copy in the bucket.
/// When the mark cannot be made durable, the segment keeps its image and
/// the reseal fails; one that goes through leaves a synced mark per segment
/// naming its new bytes. (v0.4.1 wrote the mark after the rename, and never
/// fsynced it.)
#[test]
fn a_reseal_marks_a_segment_durably_before_it_replaces_it() {
    use crate::durable::test_ops::{Op, watch};
    run(async {
        let data = tempfile::tempdir().unwrap();
        let node = crate::start_local(
            env(),
            data.path(),
            crate::NodeConfig {
                segment_max_bytes: Some(2_048),
                storage: Some(crate::snapshots::StorageConfig::new(
                    data.path().to_path_buf(),
                )),
                ..config()
            },
        )
        .await
        .unwrap();
        settle(&node).await;
        privacy(&node, pb::PrivacyState::On).await;
        quiesce(&node).await;
        finished(&node, 1, fetch(Some("user:1"), None)).await;
        finished(&node, 2, fetch(Some("user:2"), None)).await;
        append_noise(&node, 80).await;
        erase(&node, "user:1").await;
        let log = node.reader().dir().to_path_buf();
        let marks = data.path().join("privacy").join("reupload");

        let before = segments(&log);
        let failing = watch(
            &marks,
            |op| matches!(op, Op::Sync(path) if path.extension().is_some_and(|e| e == "tmp")),
        );
        let refused = node.reseal(audit(), false, authority(&node)).await;
        drop(failing);
        assert!(refused.is_err(), "{refused:?}");
        let after = segments(&log);
        let active = before.keys().next_back().copied();
        for (start, bytes) in before.iter().filter(|(s, _)| Some(**s) != active) {
            assert_eq!(
                after.get(start),
                Some(bytes),
                "segment {start} was rewritten although its mark failed"
            );
        }

        let watching = watch(&marks, |_| false);
        let done = node.reseal(audit(), false, authority(&node)).await.unwrap();
        let ops = watching.ops();
        drop(watching);
        assert!(done.segments >= 1, "{done:?}");
        assert_eq!(ops.len(), 3 * done.segments as usize, "{ops:#?}");
        for step in ops.chunks(3) {
            assert!(
                matches!(step, [Op::Sync(tmp), Op::Rename(from, to), Op::Sync(dir)]
                    if tmp == from && to.parent() == Some(marks.as_path()) && *dir == marks),
                "{ops:#?}"
            );
        }
        for (start, bytes) in segments(&log) {
            if marks.join(format!("{start:020}")).exists() {
                assert!(crate::reseal::reupload_ready(data.path(), start, &bytes));
            }
        }
        assert_eq!(
            crate::reseal::pending_reuploads(data.path()),
            done.segments,
            "a mark per resealed segment"
        );
    });
}
