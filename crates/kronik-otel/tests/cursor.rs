//! Durable control against actual files, including indeterminate replacement.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::disallowed_methods,
    clippy::panic
)]

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use kronik_core::env::{BoxFuture, Env, File, Fs, OpenMode};
use kronik_otel::cursor::{Control, Cursors, Entry, Generation, Rewind};
use serde_json::json;

const A: Generation = [1; 16];
const B: Generation = [2; 16];
const C: Generation = [3; 16];

fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}

fn entry(lsn: u64, generation: Generation) -> Entry {
    Entry {
        lsn,
        state: json!({"checkpoint": lsn}),
        control: Some(Control::new(generation)),
    }
}

#[tokio::test]
async fn unversioned_fixture_keeps_opaque_state_and_omits_absent_control() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = include_bytes!("golden/cursor-unversioned.json");
    std::fs::write(dir.path().join(Cursors::FILE), bytes).unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    let traces = cursors.get("traces").unwrap();
    assert_eq!(traces.lsn, 41);
    assert_eq!(traces.state, json!({"open": [], "kept": []}));
    assert_eq!(traces.generation(), [0; 16]);
    assert_eq!(traces.pending_rewind(), None);
    assert_eq!(traces.control, None);
    cursors.stabilize().await.unwrap();
    let actual: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(Cursors::FILE)).unwrap()).unwrap();
    let expected: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(actual, expected);
    let reopened = Cursors::load(env(), dir.path()).await.unwrap();
    assert_eq!(reopened.get("traces"), Some(traces));
    assert_eq!(reopened.get("audit").unwrap().lsn, 9);
}

#[tokio::test]
async fn control_is_strict_and_rewind_requests_validate_durable_position() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(Cursors::FILE);
    let valid: serde_json::Value =
        serde_json::from_slice(include_bytes!("golden/cursor-control-v1.json")).unwrap();
    let mut invalid = Vec::new();
    for (field, value) in [("version", json!(2)), ("extra", json!(true))] {
        let mut bad = valid.clone();
        bad["traces"]["control"][field] = value;
        invalid.push(bad);
    }
    for (field, value) in [
        ("to", json!(21)),
        ("through", json!(4)),
        ("generation", json!(([0u8; 16]))),
        ("extra", json!(true)),
    ] {
        let mut bad = valid.clone();
        bad["traces"]["control"]["rewind"][field] = value;
        invalid.push(bad);
    }
    let mut past_cursor = valid.clone();
    past_cursor["traces"]["control"]["rewind"]["to"] = json!(21);
    past_cursor["traces"]["control"]["rewind"]["through"] = json!(30);
    invalid.push(past_cursor);
    let mut missing = valid.clone();
    missing["traces"]["control"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    invalid.push(missing);
    for bad in invalid {
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let error = Cursors::load(env(), dir.path()).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{bad}");
    }
    std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    for (generation, to) in [([0; 16], 0), (B, 21)] {
        let error = cursors
            .request_rewind("traces", generation, to)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let mut unsupported = entry(20, [0; 16]);
    unsupported.control.as_mut().unwrap().version = 2;
    assert_eq!(
        cursors
            .save("traces", unsupported)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn requests_merge_across_ack_race_and_restart_then_replay_clears_at_old_head() {
    let dir = tempfile::tempdir().unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    cursors.save("traces", entry(100, [0; 16])).await.unwrap();
    let stale = entry(110, [0; 16]);
    assert_eq!(
        cursors.request_rewind("traces", A, 40).await.unwrap(),
        Rewind {
            generation: A,
            to: 40,
            through: 100,
        }
    );
    let (request, ack) = tokio::join!(
        cursors.request_rewind("traces", B, 70),
        cursors.advance("traces", stale),
    );
    assert_eq!(request.unwrap().to, 40);
    ack.unwrap();
    let pending = Rewind {
        generation: B,
        to: 40,
        through: 110,
    };
    let saved = cursors.get("traces").unwrap();
    assert_eq!(saved.lsn, 110);
    assert_eq!(saved.generation(), [0; 16]);
    assert_eq!(saved.pending_rewind(), Some(pending));
    drop(cursors);
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    assert_eq!(cursors.get("traces"), Some(saved));

    let before = std::fs::read(dir.path().join(Cursors::FILE)).unwrap();
    assert_eq!(
        cursors
            .advance("traces", entry(41, B))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        std::fs::read(dir.path().join(Cursors::FILE)).unwrap(),
        before
    );
    let cut = cursors.advance("traces", entry(40, B)).await.unwrap();
    assert_eq!(cut.pending_rewind(), Some(pending));
    assert_eq!(cut.generation(), B);
    assert_eq!(cursors.get("traces"), Some(cut.clone()));
    assert_eq!(
        cursors
            .advance("traces", entry(111, [0; 16]))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(cursors.get("traces"), Some(cut));

    // A second request during replay keeps the first head, even below it.
    let pending = cursors.request_rewind("traces", C, 10).await.unwrap();
    assert_eq!(
        pending,
        Rewind {
            generation: C,
            to: 10,
            through: 110
        }
    );
    let mut old_ack = entry(110, B);
    old_ack.control.as_mut().unwrap().rewind = Some(Rewind {
        generation: B,
        to: 40,
        through: 110,
    });
    let old_ack = cursors.advance("traces", old_ack).await.unwrap();
    assert_eq!(old_ack.pending_rewind(), Some(pending));
    assert_eq!(old_ack.generation(), B);
    let cut = cursors.advance("traces", entry(10, C)).await.unwrap();
    assert_eq!(cut.pending_rewind(), Some(pending));
    assert_eq!(
        cursors
            .advance("traces", entry(110, B))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let almost = cursors.advance("traces", entry(109, C)).await.unwrap();
    assert_eq!(almost.pending_rewind(), Some(pending));
    let done = cursors.advance("traces", entry(110, C)).await.unwrap();
    assert_eq!(done.pending_rewind(), None);
    assert_eq!(done.generation(), C);
    let reopened = Cursors::load(env(), dir.path()).await.unwrap();
    assert_eq!(reopened.get("traces"), Some(done));
    assert_eq!(
        reopened
            .advance("traces", entry(111, B))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        reopened
            .advance("traces", entry(109, C))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        reopened
            .request_rewind("traces", C, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn exact_save_can_replace_control_and_clamp_state_for_restore() {
    let dir = tempfile::tempdir().unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    cursors.save("traces", entry(100, B)).await.unwrap();
    cursors.request_rewind("traces", C, 40).await.unwrap();
    let replacement = Entry {
        lsn: 20,
        state: serde_json::Value::Null,
        control: None,
    };
    cursors.save("traces", replacement.clone()).await.unwrap();
    assert_eq!(cursors.get("traces"), Some(replacement.clone()));
    let reopened = Cursors::load(env(), dir.path()).await.unwrap();
    assert_eq!(reopened.get("traces"), Some(replacement));
}

#[tokio::test]
async fn empty_stream_rewind_and_zero_length_replay_are_durable() {
    let dir = tempfile::tempdir().unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    let request = cursors.request_rewind("audit", A, 0).await.unwrap();
    assert_eq!(
        request,
        Rewind {
            generation: A,
            to: 0,
            through: 0
        }
    );
    let restored = Cursors::load(env(), dir.path()).await.unwrap();
    let saved = restored.get("audit").unwrap();
    assert_eq!(saved.generation(), [0; 16]);
    assert_eq!(saved.pending_rewind(), Some(request));
    let done = restored.advance("audit", entry(0, A)).await.unwrap();
    assert_eq!(done.pending_rewind(), None);
    assert_eq!(done.generation(), A);
}

#[derive(Clone)]
struct Faults {
    point: Arc<AtomicU8>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl Faults {
    fn event(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn inject(&self, point: u8) -> io::Result<()> {
        if self
            .point
            .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Err(io::Error::other("injected cursor I/O failure"))
        } else {
            Ok(())
        }
    }
}

struct FaultFs {
    inner: Arc<dyn Fs>,
    faults: Faults,
}

struct FaultFile {
    inner: Arc<dyn File>,
    faults: Faults,
}

impl File for FaultFile {
    fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
        self.inner.read_at(offset, len)
    }
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let faults = self.faults.clone();
        Box::pin(async move {
            faults.inject(2)?;
            inner.write_at(offset, data).await
        })
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let faults = self.faults.clone();
        Box::pin(async move {
            faults.event("file_sync");
            faults.inject(3)?;
            inner.sync_data().await
        })
    }
}

impl Fs for FaultFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
        let inner = self.inner.clone();
        let faults = self.faults.clone();
        Box::pin(async move {
            faults.inject(1)?;
            let file = inner.open(path, mode).await?;
            Ok(Arc::new(FaultFile {
                inner: file,
                faults,
            }) as Arc<dyn File>)
        })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
        self.inner.read_dir(path)
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let faults = self.faults.clone();
        Box::pin(async move {
            faults.event("rename");
            faults.inject(4)?;
            inner.rename(from, to).await?;
            faults.inject(5)
        })
    }
    fn sync_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
        let inner = self.inner.clone();
        let faults = self.faults.clone();
        Box::pin(async move {
            faults.event("dir_sync");
            faults.inject(6)?;
            inner.sync_dir(path).await
        })
    }
}

fn fault_env() -> (Env, Faults) {
    let mut env = env();
    let faults = Faults {
        point: Arc::new(AtomicU8::new(0)),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    env.fs = Arc::new(FaultFs {
        inner: env.fs.clone(),
        faults: faults.clone(),
    });
    (env, faults)
}

#[tokio::test]
async fn failed_save_request_and_advance_never_publish_through_another_stream() {
    for point in 1..=6 {
        let dir = tempfile::tempdir().unwrap();
        let (env, faults) = fault_env();
        let cursors = Cursors::load(env.clone(), dir.path()).await.unwrap();
        cursors.save("traces", entry(100, [0; 16])).await.unwrap();
        cursors.save("audit", entry(7, [0; 16])).await.unwrap();
        for operation in 0..3 {
            let before = cursors.get("traces").unwrap();
            faults.point.store(point, Ordering::SeqCst);
            let failed = match operation {
                0 => cursors.save("traces", entry(101, [0; 16])).await,
                1 => cursors.request_rewind("traces", A, 40).await.map(|_| ()),
                _ => cursors.advance("traces", entry(40, A)).await.map(|_| ()),
            };
            assert!(failed.is_err(), "point {point}, operation {operation}");
            assert_eq!(cursors.get("traces"), Some(before.clone()));
            assert_eq!(cursors.get("audit").unwrap().lsn, 7);
            cursors.save("audit", entry(7, [0; 16])).await.unwrap();
            let restored = Cursors::load(env.clone(), dir.path()).await.unwrap();
            assert_eq!(restored.get("traces"), Some(before));
            assert_eq!(restored.get("audit").unwrap().lsn, 7);
            if operation == 1 {
                cursors.request_rewind("traces", A, 40).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn failed_temporary_unlink_leaves_cache_and_other_stream_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let cursors = Cursors::load(env(), dir.path()).await.unwrap();
    cursors.save("traces", entry(10, [0; 16])).await.unwrap();
    let temporary = dir.path().join("export.json.tmp");
    std::fs::create_dir(&temporary).unwrap();
    assert!(cursors.save("traces", entry(20, [0; 16])).await.is_err());
    assert_eq!(cursors.get("traces").unwrap().lsn, 10);
    std::fs::remove_dir(temporary).unwrap();
    cursors.save("audit", entry(3, [0; 16])).await.unwrap();
    let restored = Cursors::load(env(), dir.path()).await.unwrap();
    assert_eq!(restored.get("traces").unwrap().lsn, 10);
    assert_eq!(restored.get("audit").unwrap().lsn, 3);
}

#[cfg(unix)]
#[tokio::test]
async fn stabilization_reselects_chosen_reference_on_fresh_inode_before_generation_reuse() {
    use std::os::unix::fs::MetadataExt;

    for point in [5, 6] {
        let dir = tempfile::tempdir().unwrap();
        let (env, faults) = fault_env();
        let cursors = Cursors::load(env.clone(), dir.path()).await.unwrap();
        let selected = dir.path().join("trace-state.0");
        let staged = dir.path().join("trace-state.1");
        std::fs::write(&selected, b"selected generation").unwrap();
        std::fs::write(&staged, b"staged generation").unwrap();
        let chosen = Entry {
            lsn: 1,
            state: json!({"file": "trace-state.0"}),
            control: None,
        };
        let candidate = Entry {
            lsn: 2,
            state: json!({"file": "trace-state.1"}),
            control: None,
        };
        cursors.save("traces", chosen.clone()).await.unwrap();
        faults.point.store(point, Ordering::SeqCst);
        assert!(cursors.save("traces", candidate.clone()).await.is_err());
        assert_eq!(cursors.get("traces"), Some(chosen.clone()));
        let manifest = dir.path().join(Cursors::FILE);
        let staged_inode = std::fs::File::open(&manifest).unwrap();
        let staged_bytes = std::fs::read(&manifest).unwrap();
        let observed = Cursors::load(env.clone(), dir.path()).await.unwrap();
        assert_eq!(observed.get("traces"), Some(candidate));
        faults.events.lock().unwrap().clear();
        cursors.stabilize().await.unwrap();
        assert_eq!(
            *faults.events.lock().unwrap(),
            ["file_sync", "rename", "dir_sync"]
        );
        assert_ne!(
            staged_inode.metadata().unwrap().ino(),
            std::fs::metadata(&manifest).unwrap().ino()
        );
        // The displaced inode is untouched; stabilization did not fsync it in place.
        let mut old = staged_inode;
        let mut old_bytes = Vec::new();
        std::io::Read::read_to_end(&mut old, &mut old_bytes).unwrap();
        assert_eq!(old_bytes, staged_bytes);
        std::fs::write(&staged, b"reused generation, no longer staged").unwrap();
        let restored = Cursors::load(env, dir.path()).await.unwrap();
        let durable = restored.get("traces").unwrap();
        assert_eq!(durable, chosen);
        let selected_path = dir.path().join(durable.state["file"].as_str().unwrap());
        assert_eq!(
            std::fs::read(selected_path).unwrap(),
            b"selected generation"
        );
    }
}

#[tokio::test]
async fn failed_stabilization_keeps_chosen_cache_and_can_reselect_on_fresh_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (env, faults) = fault_env();
    let cursors = Cursors::load(env.clone(), dir.path()).await.unwrap();
    let chosen = entry(1, [0; 16]);
    cursors.save("traces", chosen.clone()).await.unwrap();
    faults.point.store(6, Ordering::SeqCst);
    assert!(cursors.save("traces", entry(2, [0; 16])).await.is_err());
    faults.point.store(3, Ordering::SeqCst);
    assert!(cursors.stabilize().await.is_err());
    assert_eq!(cursors.get("traces"), Some(chosen.clone()));
    cursors.stabilize().await.unwrap();
    let reopened = Cursors::load(env, dir.path()).await.unwrap();
    assert_eq!(reopened.get("traces"), Some(chosen));
}

#[tokio::test]
async fn inactive_refuses_every_write_and_preserves_unknown_corrupt_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(Cursors::FILE);
    let corrupt = b"{unknown and truncated export state";
    std::fs::write(&path, corrupt).unwrap();
    assert_eq!(
        Cursors::load(env(), dir.path()).await.err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    let cursors = Cursors::inactive(env(), dir.path());
    assert_eq!(cursors.get("traces"), None);
    assert_eq!(
        cursors
            .save("traces", entry(0, [0; 16]))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        cursors
            .request_rewind("traces", A, 0)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        cursors
            .advance("traces", entry(0, [0; 16]))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        cursors.stabilize().await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(std::fs::read(path).unwrap(), corrupt);
    assert!(!dir.path().join("export.json.tmp").exists());
}
