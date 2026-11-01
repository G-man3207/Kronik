//! Public SQLite FILESTAT diagnostics, never SQLite's private VFS layout.
// Allowlisted: public SQLite C string/control calls and a scoped borrow/fstat
// of its connection-owned Unix descriptor have no safe rusqlite binding.
#![allow(unsafe_code)]

use std::os::fd::BorrowedFd;

use rusqlite::{Connection, ffi};
use serde::Deserialize;

use crate::{PrivacyError, PublicationError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Deserialize)]
struct FileStat<'a> {
    h: i32,
    vfs: &'a str,
}

fn sqlite_error(code: i32) -> PrivacyError {
    PrivacyError::Sqlite(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None))
}

/// The caller holds the SAME connection mutex from construction through the
/// scoped borrow. Returned metadata is neither ownership nor caller authority.
///
/// Source safety: NEVER own, duplicate, open or close a database descriptor to
/// capture identity. Closing any such descriptor can release this process's
/// POSIX SQLite locks, including locks used by another connection. Retain the
/// SAME connection/Keystore Arc as the actual witness; borrow only during fstat.
pub(crate) fn file_identity(
    conn: &std::sync::MutexGuard<'_, Connection>,
) -> Result<FileIdentity, PrivacyError> {
    // SAFETY: the caller exclusively holds the live Connection. The public
    // FILESTAT opcode takes an initialized sqlite3_str, which finish consumes
    // exactly once even on errors. No SQLite private structure is inspected.
    let (code, error, length, text) = unsafe {
        let db = conn.handle();
        let output = ffi::sqlite3_str_new(db);
        let code = ffi::sqlite3_file_control(
            db,
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILESTAT,
            output.cast(),
        );
        let error = ffi::sqlite3_str_errcode(output);
        let length = ffi::sqlite3_str_length(output);
        (code, error, length, ffi::sqlite3_str_finish(output))
    };
    let result = (|| {
        if code == ffi::SQLITE_NOTFOUND {
            return Err(
                PublicationError::FileIdentity("public SQLite FILESTAT is unavailable").into(),
            );
        }
        if code != ffi::SQLITE_OK {
            return Err(sqlite_error(code));
        }
        if error != ffi::SQLITE_OK {
            return Err(sqlite_error(error));
        }
        if text.is_null() || !(1..=65_536).contains(&length) {
            return Err(
                PublicationError::FileIdentity("invalid FILESTAT diagnostic length").into(),
            );
        }
        // SAFETY: finish returned SQLite's allocation of the recorded length;
        // it remains allocated until the single sqlite3_free below.
        let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), length as usize) };
        let stat: FileStat<'_> = serde_json::from_slice(bytes)
            .map_err(|_| PublicationError::FileIdentity("invalid FILESTAT diagnostic JSON"))?;
        if stat.h < 0 || !matches!(stat.vfs, "unix" | "unix-excl") {
            return Err(
                PublicationError::FileIdentity("FILESTAT is not the canonical Unix file").into(),
            );
        }
        // SAFETY: the selected public Unix FILESTAT implementation reports its
        // live pFile->h. The caller still holds the Connection exclusively, so
        // SQLite cannot close it during this borrow. BorrowedFd never closes it.
        let descriptor = unsafe { BorrowedFd::borrow_raw(stat.h) };
        let metadata = rustix::fs::fstat(descriptor).map_err(|source| PrivacyError::CustodyIo {
            path: "the opened privacy keystore".into(),
            source: source.into(),
        })?;
        Ok(FileIdentity {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
        })
    })();
    // SAFETY: sqlite3_str_finish returns a sqlite3_malloc allocation or NULL;
    // sqlite3_free accepts either. All borrows into it ended with the closure.
    unsafe {
        ffi::sqlite3_free(text.cast());
    }
    result
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    #[ignore = "subprocess fault probe used by the actual SQLite descriptor-lock regression"]
    fn sqlite_lock_probe() {
        let path = std::env::var_os("KRONIK_TEST_BORROWED_SQLITE_LOCK")
            .expect("the parent supplies its private test database");
        // This deliberately bypasses the compliant process-owner API: it tests
        // SQLite's OS lock, not a directory-owner refusal or a new authority.
        let conn = Connection::open(path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let error = conn
            .execute("UPDATE safety_probe SET value = value + 1", [])
            .unwrap_err();
        assert!(matches!(error, rusqlite::Error::SqliteFailure(code, _)
            if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)));
    }

    fn probe(path: &std::path::Path) {
        let test = concat!(module_path!(), "::sqlite_lock_probe");
        let test = test.split_once("::").unwrap().1;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", test, "--test-threads=1"])
            .env("KRONIK_TEST_BORROWED_SQLITE_LOCK", path)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "a second process must still observe the real SQLite write lock"
        );
    }

    #[test]
    fn identity_capture_and_handle_drop_do_not_release_another_sqlite_handles_posix_lock() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("probe.db");
        let first = Mutex::new(Connection::open(&path).unwrap());
        let mut first = first.lock().unwrap();
        // Rollback-journal mode specifically exercises the DB-file POSIX lock;
        // a WAL write-lock probe alone could miss a wrongly closed DB fd.
        first
            .execute_batch(
                "PRAGMA journal_mode=DELETE;
            CREATE TABLE safety_probe(value INTEGER NOT NULL);
            INSERT INTO safety_probe VALUES(1);",
            )
            .unwrap();
        let tx = first
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        probe(&path);
        let second = Mutex::new(Connection::open(&path).unwrap());
        let identity = {
            let guard = second.lock().unwrap();
            file_identity(&guard).unwrap()
        };
        for _ in 0..4 {
            let guard = second.lock().unwrap();
            assert_eq!(file_identity(&guard).unwrap(), identity);
        }
        drop(second); // SQLite, not an extra OwnedFd/File, manages this close.
        probe(&path);
        assert_eq!(
            tx.query_row("SELECT value FROM safety_probe", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        tx.rollback().unwrap();
    }
}
