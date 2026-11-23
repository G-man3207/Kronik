//! The blob store under power failures (ADR 0117 §4): wherever the simulated
//! disk loses or tears unsynced writes and names, a blob whose
//! `ensure_durable` returned (so a record could reference it) is complete
//! after the restart, every object that survives reads back intact, and the
//! restart leaves no part file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_blob::format::{HEADER_LEN, Header};
use kronik_blob::{
    BlobId, BlobKeys, BlobMeta, BlobStore, KeyAccess, KeyAnswer, Space, StoreConfig,
};
use kronik_core::env::{Env, OpenMode};
use kronik_sim::bao::SimNet;
use kronik_sim::exec::{Executor, Handle, NodeId, RunEnd, SUPERVISOR};
use kronik_sim::fs::{CrashModel, Disk, DiskFaults, SimFs};
use kronik_sim::{SimClock, SimEntropy, SimProcs, SimRng, SimSpawner};
use zeroize::Zeroizing;

fn derived(label: &str, subject: &str, version: u32) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(label);
    h.update(subject.as_bytes());
    h.update(&version.to_le_bytes());
    Zeroizing::new(*h.finalize().as_bytes())
}

struct Keys;

impl KeyAccess for Keys {
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer {
        KeyAnswer::Found(derived("sim seal", subject, version))
    }
    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer {
        KeyAnswer::Found(derived("sim identity", subject, version))
    }
}

fn blob_keys(subject: &str) -> BlobKeys {
    BlobKeys {
        subject: subject.into(),
        key_version: 1,
        identity: derived("sim identity", subject, 1),
        seal: Some(derived("sim seal", subject, 1)),
    }
}

fn content(seed: u64, i: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.update(&i.to_le_bytes());
    h.finalize_xof().fill(&mut out);
    out
}

fn env(
    handle: &Handle,
    node: NodeId,
    disk: &Arc<Mutex<Disk>>,
    seed: u64,
    model: CrashModel,
) -> Env {
    let clock = Arc::new(SimClock {
        exec: handle.clone(),
        wall_base_ms: 0,
        wall_offset_ms: Arc::new(AtomicI64::new(0)),
    });
    Env {
        clock: clock.clone(),
        spawner: Arc::new(SimSpawner {
            exec: handle.clone(),
            node,
        }),
        entropy: Arc::new(SimEntropy(SimRng::new(seed, &[b'e', node as u8]))),
        fs: Arc::new(SimFs::new(
            disk.clone(),
            clock.clone(),
            SimRng::new(seed, &[b'd', node as u8]),
            DiskFaults {
                crash_model: model,
                fsync_error: 0.0,
            },
        )),
        net: Arc::new(SimNet {
            bao: None,
            service: None,
        }),
        procs: Arc::new(SimProcs { clock }),
    }
}

/// What one run saw, for the coverage check across seeds.
#[derive(Default)]
struct Seen {
    durable_at_crash: u64,
    parts_at_restart: u64,
    loose_objects: u64,
}

/// (reference, content) of every blob whose `ensure_durable` returned.
type Durable = Arc<Mutex<Vec<(BlobMeta, Vec<u8>)>>>;

const WRITER: NodeId = 1;
const CHECKER: NodeId = 2;

fn run(seed: u64, model: CrashModel, seen: &Mutex<Seen>) {
    let executor = Executor::new(seed);
    let handle = executor.handle();
    let disk = Arc::new(Mutex::new(Disk::default()));
    let rng = SimRng::new(seed, b"blob-store");
    let data = PathBuf::from("data");
    let durable: Durable = Arc::default();
    let opened = Arc::new(AtomicBool::new(false));
    let crash = Arc::new(AtomicBool::new(false));

    let writer_env = env(&handle, WRITER, &disk, seed, model);
    let writers = 2 + rng.below(6);
    // (content index, size, chunk, sealed); some repeat an earlier blob, so
    // writers claim objects too.
    let mut plans: Vec<(u64, usize, usize, bool)> = Vec::new();
    for i in 0..writers {
        let chunk = 1 + rng.below(80_000) as usize;
        match plans.last() {
            Some(&(src, size, _, sealed)) if rng.chance(0.3) => {
                plans.push((src, size, chunk, sealed))
            }
            _ => {
                let size = [0, 1, 70_000, 200_000, 65_536][rng.below(5) as usize]
                    + rng.below(100) as usize;
                plans.push((i, size, chunk, rng.chance(0.4)));
            }
        }
    }
    {
        let (durable, opened, data, handle) = (
            durable.clone(),
            opened.clone(),
            data.clone(),
            handle.clone(),
        );
        handle.clone().spawn(
            WRITER,
            "open and write",
            Box::pin(async move {
                let store = BlobStore::open(writer_env, &data, StoreConfig::default())
                    .await
                    .unwrap();
                opened.store(true, Ordering::Relaxed);
                for (src, size, chunk, sealed) in plans {
                    let (store, durable) = (store.clone(), durable.clone());
                    handle.spawn(
                        WRITER,
                        "writer",
                        Box::pin(async move {
                            let bytes = content(seed, src, size);
                            let keys = sealed.then(|| blob_keys(&format!("user:{}", src % 2)));
                            let lease = store.leases().take("sim");
                            let mut w = store
                                .writer(Space::Main, keys, u64::MAX, lease)
                                .await
                                .unwrap();
                            for c in bytes.chunks(chunk) {
                                w.write(c).await.unwrap();
                            }
                            let meta = w.finish().await.unwrap();
                            store
                                .ensure_durable(&Space::Main, &[meta.id])
                                .await
                                .unwrap();
                            durable.lock().unwrap().push((meta, bytes));
                        }),
                    );
                }
            }),
        );
    }
    {
        let (opened, crash, clock) = (opened.clone(), crash.clone(), handle.clone());
        let after = Duration::from_micros(rng.below(40_000));
        handle.spawn(
            SUPERVISOR,
            "crash",
            Box::pin(async move {
                while !opened.load(Ordering::Relaxed) {
                    clock.sleep(Duration::from_micros(200)).await;
                }
                clock.sleep(after).await;
                crash.store(true, Ordering::Relaxed);
            }),
        );
    }
    let end = executor.run(50_000_000, || crash.load(Ordering::Relaxed));
    assert_ne!(end, RunEnd::StepLimit, "seed {seed}");
    handle.kill_node(WRITER);
    handle.kill_node(SUPERVISOR);
    disk.lock()
        .unwrap()
        .crash(model, &SimRng::new(seed, b"power failure"));
    let survived = durable.lock().unwrap().clone();
    seen.lock().unwrap().durable_at_crash += u64::from(!survived.is_empty());

    let checked = Arc::new(AtomicBool::new(false));
    let parts = Arc::new(AtomicU64::new(0));
    let loose = Arc::new(AtomicU64::new(0));
    {
        let check_env = env(&handle, CHECKER, &disk, seed, model);
        let (checked, parts, loose) = (checked.clone(), parts.clone(), loose.clone());
        handle.spawn(
            CHECKER,
            "restart and check",
            Box::pin(async move {
                let fs = check_env.fs.clone();
                let tmp = data.join("blobs/tmp");
                parts.store(
                    fs.read_dir(tmp.clone()).await.unwrap().len() as u64,
                    Ordering::Relaxed,
                );
                let store = BlobStore::open(check_env, &data, StoreConfig::default())
                    .await
                    .unwrap();
                assert!(
                    fs.read_dir(tmp).await.unwrap().is_empty(),
                    "seed {seed}: part files left"
                );
                // Every blob a record could reference is complete.
                for (meta, bytes) in &survived {
                    let r = store
                        .reader(&Space::Main, meta, &Keys)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("seed {seed} {model:?}: durable blob {} lost: {e}", meta.id)
                        });
                    assert_eq!(
                        r.read_at(0, bytes.len() + 1).await.unwrap(),
                        *bytes,
                        "seed {seed}"
                    );
                    r.verify(&Keys).await.unwrap();
                }
                // Every object that survived, referenced or not, is intact.
                let known: Vec<BlobId> = survived.iter().map(|(m, _)| m.id).collect();
                for shard in 0u16..256 {
                    let dir = data.join("blobs/objects").join(format!("{shard:02x}"));
                    for name in fs.read_dir(dir.clone()).await.unwrap() {
                        let id = BlobId::from_file_name(&name)
                            .unwrap_or_else(|| panic!("seed {seed}: stray file {name}"));
                        if !known.contains(&id) {
                            loose.fetch_add(1, Ordering::Relaxed);
                        }
                        let header = fs
                            .open(dir.join(&name), OpenMode::Read)
                            .await
                            .unwrap()
                            .read_at(0, HEADER_LEN)
                            .await
                            .unwrap();
                        let meta = meta_of(&header, id);
                        let r = store.reader(&Space::Main, &meta, &Keys).await.unwrap();
                        r.verify(&Keys).await.unwrap_or_else(|e| {
                            panic!("seed {seed} {model:?}: object {id} damaged: {e}")
                        });
                    }
                }
                checked.store(true, Ordering::Relaxed);
            }),
        );
    }
    executor.run(50_000_000, || checked.load(Ordering::Relaxed));
    assert!(
        checked.load(Ordering::Relaxed),
        "seed {seed}: the check did not finish"
    );
    let mut s = seen.lock().unwrap();
    s.parts_at_restart += u64::from(parts.load(Ordering::Relaxed) > 0);
    s.loose_objects += u64::from(loose.load(Ordering::Relaxed) > 0);
}

/// The reference an object's header names (to read an object no test
/// record knows).
fn meta_of(header: &[u8], id: BlobId) -> BlobMeta {
    let h = Header::decode(header).unwrap();
    BlobMeta {
        id,
        size: h.size,
        subject: h.subject,
        key_version: h.key_version,
    }
}

#[test]
fn durable_blobs_survive_every_crash_and_nothing_torn_remains() {
    let seen = Mutex::new(Seen::default());
    for model in [CrashModel::PrefixTorn, CrashModel::Reorder] {
        for seed in 0..48 {
            run(seed, model, &seen);
        }
    }
    let s = seen.lock().unwrap();
    // The crash points the test is about were all reached.
    assert!(s.durable_at_crash > 0, "no crash after a durable blob");
    assert!(s.parts_at_restart > 0, "no crash during a write");
    assert!(
        s.loose_objects > 0,
        "no crash between a name and its record"
    );
}
