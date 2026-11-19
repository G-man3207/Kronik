//! Issue #243: an export page deep in a segment must not CRC-walk the prefix.
use super::*;
use kronik_core::env::{BoxFuture, Env, File, Fs, OpenMode};
use std::path::{Path, PathBuf};
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

struct CountingFs {
    inner: Arc<dyn Fs>,
    armed: Arc<AtomicBool>,
    node: Arc<OnceLock<Arc<Node>>>,
    hits: Arc<Mutex<Vec<Hit>>>,
    opens: Arc<Mutex<Vec<u64>>>,
    lock_held: Arc<AtomicBool>,
}

struct CountingFile {
    inner: Arc<dyn File>,
    segment: Option<u64>,
    armed: Arc<AtomicBool>,
    node: Arc<OnceLock<Arc<Node>>>,
    hits: Arc<Mutex<Vec<Hit>>>,
    lock_held: Arc<AtomicBool>,
}

fn segment_start(path: &Path) -> Option<u64> {
    let name = path.file_stem()?.to_str()?;
    name.parse().ok()
}

impl Fs for CountingFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: PathBuf,
        mode: OpenMode,
    ) -> BoxFuture<'static, std::io::Result<Arc<dyn File>>> {
        let segment = path.extension().is_some_and(|ext| ext == "seg");
        let start = segment.then(|| segment_start(&path)).flatten();
        if segment
            && self.armed.load(Ordering::SeqCst)
            && let Some(start) = start
        {
            self.opens.lock().unwrap().push(start);
        }
        let armed = self.armed.clone();
        let node = self.node.clone();
        let hits = self.hits.clone();
        let lock_held = self.lock_held.clone();
        let open = self.inner.open(path, mode);
        Box::pin(async move {
            let inner = open.await?;
            Ok(Arc::new(CountingFile {
                inner,
                segment: start,
                armed,
                node,
                hits,
                lock_held,
            }) as Arc<dyn File>)
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
        bytes: bytes::Bytes,
    ) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_secure_new(path, bytes)
    }
}

impl File for CountingFile {
    fn len(&self) -> BoxFuture<'static, std::io::Result<u64>> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, std::io::Result<Vec<u8>>> {
        if self.armed.load(Ordering::SeqCst)
            && let Some(segment) = self.segment
        {
            self.hits.lock().unwrap().push(Hit { segment, offset });
            if let Some(node) = self.node.get()
                && node.snapshot_lock.try_lock().is_err()
            {
                self.lock_held.store(true, Ordering::SeqCst);
            }
        }
        self.inner.read_at(offset, len)
    }
    fn write_at(&self, offset: u64, data: bytes::Bytes) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_data()
    }
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
    let node_slot = Arc::new(OnceLock::new());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let opens = Arc::new(Mutex::new(Vec::new()));
    let lock_held = Arc::new(AtomicBool::new(false));
    let env = Env {
        fs: Arc::new(CountingFs {
            inner: real.fs.clone(),
            armed: armed.clone(),
            node: node_slot.clone(),
            hits: hits.clone(),
            opens: opens.clone(),
            lock_held: lock_held.clone(),
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
