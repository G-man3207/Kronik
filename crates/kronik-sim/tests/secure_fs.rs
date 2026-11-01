//! Actual secure-file operations on the existing timed, crashable simulated disk.
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use kronik_core::env::{Fs as _, OpenMode};
use kronik_sim::exec::{Executor, RunEnd};
use kronik_sim::fs::{CrashModel, Disk, DiskFaults, SimFs};
use kronik_sim::{SimClock, SimRng};

#[test]
fn secure_files_are_private_bounded_durable_and_exclusive_across_crashes() {
    for model in [CrashModel::PrefixTorn, CrashModel::Reorder] {
        for seed in 0..8 {
            let executor = Executor::new(seed);
            let handle = executor.handle();
            let clock = Arc::new(SimClock {
                exec: handle.clone(),
                wall_base_ms: 0,
                wall_offset_ms: Arc::new(AtomicI64::new(0)),
            });
            let disk = Arc::new(Mutex::new(Disk::default()));
            let fs = SimFs::new(
                disk.clone(),
                clock.clone(),
                SimRng::new(seed, b"secure-disk"),
                DiskFaults {
                    crash_model: model,
                    fsync_error: 0.0,
                },
            );
            let completed = Arc::new(AtomicBool::new(false));
            let done = completed.clone();
            handle.spawn(
                1,
                "secure file durability",
                Box::pin(async move {
                    fs.create_dir_all(PathBuf::from("state")).await.unwrap();
                    let path = PathBuf::from("state/private/token");
                    fs.write_secure_new(path.clone(), Bytes::from_static(b"first"))
                        .await
                        .unwrap();
                    assert_eq!(Disk::snapshot_durable(&disk, &path).unwrap(), b"first");
                    assert_eq!(fs.read_secure(path.clone(), 5).await.unwrap(), b"first");
                    assert_eq!(
                        fs.read_secure(path.clone(), 4).await.unwrap_err().kind(),
                        io::ErrorKind::InvalidData
                    );
                    assert_eq!(
                        fs.write_secure_new(path.clone(), Bytes::from_static(b"other"))
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::AlreadyExists
                    );
                    assert_eq!(fs.read_secure(path.clone(), 5).await.unwrap(), b"first");

                    let stale = PathBuf::from("state/private/.token.tmp");
                    let stale_file = fs
                        .open(stale.clone(), OpenMode::ReadWriteCreate)
                        .await
                        .unwrap();
                    stale_file
                        .write_at(0, Bytes::from_static(b"leftover"))
                        .await
                        .unwrap();
                    stale_file.sync_data().await.unwrap();
                    fs.sync_dir(PathBuf::from("state/private")).await.unwrap();
                    fs.write_secure(path.clone(), b"second".to_vec())
                        .await
                        .unwrap();
                    assert_eq!(Disk::snapshot_durable(&disk, &path).unwrap(), b"second");
                    assert_eq!(Disk::snapshot_durable(&disk, &stale).unwrap(), b"leftover");
                    disk.lock()
                        .unwrap()
                        .crash(model, &SimRng::new(seed, b"secure-crash"));
                    let restarted = SimFs::new(
                        disk.clone(),
                        clock,
                        SimRng::new(seed, b"secure-restart"),
                        DiskFaults {
                            crash_model: model,
                            fsync_error: 0.0,
                        },
                    );
                    assert_eq!(
                        restarted.read_secure(path.clone(), 6).await.unwrap(),
                        b"second"
                    );
                    assert_eq!(
                        restarted
                            .write_secure_new(path, Bytes::from_static(b"late"))
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::AlreadyExists
                    );

                    let ordinary = PathBuf::from("state/ordinary");
                    let file = restarted
                        .open(ordinary.clone(), OpenMode::ReadWriteCreate)
                        .await
                        .unwrap();
                    file.write_at(0, Bytes::from_static(b"ordinary"))
                        .await
                        .unwrap();
                    assert_eq!(
                        restarted
                            .read_secure(ordinary.clone(), 8)
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(
                        restarted
                            .write_secure(ordinary, b"replacement".to_vec())
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    restarted
                        .create_dir_all(PathBuf::from("state/public"))
                        .await
                        .unwrap();
                    assert_eq!(
                        restarted
                            .write_secure_new(PathBuf::from("state/public/key"), Bytes::new())
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );
                    assert_eq!(
                        restarted
                            .write_secure_new(
                                PathBuf::from("state/missing/intermediate/key"),
                                Bytes::new()
                            )
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::NotFound
                    );
                    assert_eq!(
                        restarted
                            .read_secure(PathBuf::from("state/../private/token"), 6)
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::PermissionDenied
                    );

                    let race = PathBuf::from("state/private/race");
                    let (first, second) = tokio::join!(
                        restarted.write_secure_new(race.clone(), Bytes::from_static(b"one")),
                        restarted.write_secure_new(race.clone(), Bytes::from_static(b"two")),
                    );
                    let expected: &[u8] = match (first, second) {
                        (Ok(()), Err(error)) => {
                            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                            b"one"
                        }
                        (Err(error), Ok(())) => {
                            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                            b"two"
                        }
                        result => {
                            panic!("exactly one exclusive simulated writer must commit: {result:?}")
                        }
                    };
                    assert_eq!(
                        restarted.read_secure(race.clone(), 3).await.unwrap(),
                        expected
                    );
                    assert_eq!(Disk::snapshot_durable(&disk, &race).unwrap(), expected);
                    done.store(true, Ordering::SeqCst);
                }),
            );
            assert_eq!(
                executor.run(4096, || completed.load(Ordering::SeqCst)),
                RunEnd::Stopped
            );
        }
    }
}

#[test]
fn secure_write_fsync_failure_preserves_the_previous_durable_credential() {
    for model in [CrashModel::PrefixTorn, CrashModel::Reorder] {
        for seed in 0..8 {
            let executor = Executor::new(seed);
            let handle = executor.handle();
            let clock = Arc::new(SimClock {
                exec: handle.clone(),
                wall_base_ms: 0,
                wall_offset_ms: Arc::new(AtomicI64::new(0)),
            });
            let disk = Arc::new(Mutex::new(Disk::default()));
            let fs = SimFs::new(
                disk.clone(),
                clock.clone(),
                SimRng::new(seed, b"secure-eio-setup"),
                DiskFaults {
                    crash_model: model,
                    fsync_error: 0.0,
                },
            );
            let failing = SimFs::new(
                disk.clone(),
                clock.clone(),
                SimRng::new(seed, b"secure-eio"),
                DiskFaults {
                    crash_model: model,
                    fsync_error: 1.0,
                },
            );
            let completed = Arc::new(AtomicBool::new(false));
            let done = completed.clone();
            handle.spawn(
                1,
                "secure file fsync EIO",
                Box::pin(async move {
                    fs.create_dir_all(PathBuf::from("state")).await.unwrap();
                    let path = PathBuf::from("state/private/token");
                    fs.write_secure_new(path.clone(), Bytes::from_static(b"old"))
                        .await
                        .unwrap();
                    assert_eq!(
                        failing
                            .write_secure(path.clone(), b"new".to_vec())
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::Other
                    );
                    assert_eq!(fs.read_secure(path.clone(), 3).await.unwrap(), b"old");
                    assert_eq!(Disk::snapshot_durable(&disk, &path).unwrap(), b"old");
                    disk.lock()
                        .unwrap()
                        .crash(model, &SimRng::new(seed, b"secure-eio-crash"));
                    let restarted = SimFs::new(
                        disk.clone(),
                        clock,
                        SimRng::new(seed, b"secure-eio-restart"),
                        DiskFaults {
                            crash_model: model,
                            fsync_error: 0.0,
                        },
                    );
                    assert_eq!(
                        restarted.read_secure(path.clone(), 3).await.unwrap(),
                        b"old"
                    );
                    assert_eq!(
                        restarted
                            .write_secure_new(path.clone(), Bytes::from_static(b"late"))
                            .await
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::AlreadyExists
                    );
                    restarted
                        .write_secure(path.clone(), b"next".to_vec())
                        .await
                        .unwrap();
                    assert_eq!(Disk::snapshot_durable(&disk, &path).unwrap(), b"next");
                    done.store(true, Ordering::SeqCst);
                }),
            );
            assert_eq!(
                executor.run(4096, || completed.load(Ordering::SeqCst)),
                RunEnd::Stopped
            );
        }
    }
}
