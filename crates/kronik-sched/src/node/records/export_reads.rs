//! Issue #243: an export page deep in a segment must not CRC-walk the prefix.
use super::*;
use kronik_core::env::Env;
use kronik_core::env::test_fs::{FsCall, Then, hooked};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "export-read".into(),
        reason: "prefix walk".into(),
        wall_time_ms: 1,
    }
}

struct Hit {
    segment: u64,
    offset: u64,
}

/// The start a `.seg` file is named after; `None` for any other file.
fn segment_start(path: &Path) -> Option<u64> {
    if path.extension()? != "seg" {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

async fn append_n(node: &Arc<Node>, n: u32) {
    let auth = node.local_operator_authority().unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(256));
    let mut joins = Vec::with_capacity(n as usize);
    for i in 0..n {
        let permit = slots.clone().acquire_owned().await.unwrap();
        let node = node.clone();
        let env = node.env().clone();
        let auth = auth.clone();
        joins.push(env.spawn("test-append", async move {
            let _permit = permit;
            node.record_audit_event_authorized(
                "test.export.read",
                &i.to_string(),
                std::collections::BTreeMap::new(),
                audit(),
                auth,
            )
            .await
            .unwrap()
        }));
    }
    for join in joins {
        join.await.unwrap();
    }
}

#[tokio::test]
async fn a_page_100_000_records_into_a_segment_does_not_read_the_prefix() {
    const DEEP: u64 = 100_000;
    const BATCH: usize = 500;
    let data = tempfile::tempdir().unwrap();
    let real = Env::real(tokio::runtime::Handle::current());
    let armed = Arc::new(AtomicBool::new(false));
    let node_slot: Arc<OnceLock<Arc<Node>>> = Arc::new(OnceLock::new());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
    let lock_held = Arc::new(AtomicBool::new(false));
    let env = Env {
        // Real files. While `armed`: segment opens go to `opens`, segment
        // reads to `hits`, and a read under the node's snapshot lock sets
        // `lock_held`.
        fs: hooked(real.fs.clone(), {
            let (armed, node_slot, hits) = (armed.clone(), node_slot.clone(), hits.clone());
            let (opens, lock_held) = (opens.clone(), lock_held.clone());
            move |call| {
                if !armed.load(Ordering::SeqCst) {
                    return Then::Forward;
                }
                match call {
                    FsCall::Open(path, _) => {
                        if let Some(start) = segment_start(path) {
                            opens.lock().unwrap().push(start);
                        }
                    }
                    FsCall::ReadAt { path, offset, .. } => {
                        if let Some(segment) = segment_start(path) {
                            hits.lock().unwrap().push(Hit {
                                segment,
                                offset: *offset,
                            });
                            if let Some(node) = node_slot.get()
                                && node.snapshot_lock.try_lock().is_err()
                            {
                                lock_held.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    _ => {}
                }
                Then::Forward
            }
        }),
        ..real
    };
    let node = crate::start_local(
        env,
        data.path(),
        NodeConfig {
            // 100_000 small records stay in the segment after the one roll.
            segment_max_bytes: Some(32 << 20),
            group_commit_window: Some(Duration::from_millis(2)),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    assert!(node_slot.set(node.clone()).is_ok());
    let auth = node.local_operator_authority().unwrap();
    node.record_audit_event_authorized(
        "test.export.read",
        &"x".repeat(32 << 20),
        std::collections::BTreeMap::new(),
        audit(),
        auth,
    )
    .await
    .unwrap();
    append_n(&node, (DEEP + BATCH as u64) as u32).await;

    let starts = node.reader().starts().await.unwrap();
    assert!(
        starts.len() >= 2,
        "one oversized record should have rolled an earlier segment: {starts:?}"
    );
    let active = *starts.last().unwrap();
    let mut cursor = 0;
    let mut resume = None;
    loop {
        let reader = node.capture_export_reader(resume).await.unwrap();
        let page_start = cursor + 1;
        let deep = page_start >= active + DEEP - 1;
        if deep {
            hits.lock().unwrap().clear();
            opens.lock().unwrap().clear();
            lock_held.store(false, Ordering::SeqCst);
            armed.store(true, Ordering::SeqCst);
        }
        let page = reader
            .local_export_page(cursor, BATCH, 4 << 20)
            .await
            .unwrap();
        if deep {
            armed.store(false, Ordering::SeqCst);
            let floor = resume
                .expect("the deep page resumes at a file offset")
                .offset;
            let header = 24 + node.branch().len() as u64;
            let seen = hits.lock().unwrap();
            assert!(
                seen.iter().all(|hit| {
                    hit.segment >= active && (hit.offset < header || hit.offset >= floor)
                }),
                "a page at lsn {page_start} read the prefix or an earlier segment"
            );
            assert!(
                opens.lock().unwrap().iter().all(|start| *start >= active),
                "the deep page opened an earlier segment"
            );
            let reads = seen.len() as u64;
            let records = page.records.len() as u64;
            assert!(
                reads <= records * 2 + 32,
                "a page of {records} new records took {reads} read_ats"
            );
            assert!(
                !lock_held.load(Ordering::SeqCst),
                "snapshot lock held across the read"
            );
            assert!(!page.records.is_empty(), "the deep page was empty");
            break;
        }
        assert!(
            !page.records.is_empty(),
            "export ended at cursor {cursor} before a page {DEEP} records into segment {active}"
        );
        let last = &page.records.last().unwrap().1;
        resume = Some(ExportResume::after(last));
        cursor = last.lsn;
    }
}
