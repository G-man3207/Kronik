//! The only module with `unsafe` code (allowlisted in ADR 0005).
//!
//! It wraps the SQLite C APIs that `rusqlite` does not expose:
//! - a per-connection VFS whose clock is the turn's logical time
//!   (`xCurrentTimeInt64`), so every `'now'` in SQL is deterministic;
//! - a process-wide alternative `localtime()` that is UTC, so the
//!   `localtime`/`utc` date modifiers do not depend on the host's time zone;
//! - the session extension with `SQLITE_SESSION_OBJCONFIG_ROWID`, table
//!   filters, `sqlite3changeset_apply_v2` flags, and
//!   `sqlite3changegroup_add_change` for splitting a changeset per subject.
//!
//! Every function here takes or returns plain Rust data; no SQLite pointer
//! escapes this module except inside the RAII types defined here.
//
// Allowlisted: SQLite's session, VFS and localtime APIs have no safe binding.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::Once;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use rusqlite::Connection;
use rusqlite::ffi;

/// Milliseconds between the Julian-day epoch and the Unix epoch, as used by
/// SQLite's `xCurrentTimeInt64` (`24405875 * 8640000`).
const UNIX_EPOCH_JULIAN_MS: i64 = 210_866_760_000_000;

// ------------------------------------------------------------------- VFS

/// `sqlite3_vfs` must be the first field so that SQLite's `*mut sqlite3_vfs`
/// can be cast back to `*mut TimeVfsInner` (C "container-of" layout).
#[repr(C)]
struct TimeVfsInner {
    base: ffi::sqlite3_vfs,
    now_unix_ms: AtomicI64,
    _name: CString,
}

/// A clone of the default VFS (same I/O, locking and `pAppData`) whose clock
/// returns a value set by the host. Registered under a unique name; one per
/// connection because turns of different actors run concurrently.
pub struct TimeVfs {
    inner: *mut TimeVfsInner,
    name: String,
}

// SAFETY: the inner struct is only mutated through the atomic clock; SQLite
// reads the VFS from any thread under its own locking.
unsafe impl Send for TimeVfs {}

unsafe extern "C" fn current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    // SAFETY: SQLite passes back the pointer we registered, whose first field
    // is `base` (repr(C)); `out` is a valid pointer provided by SQLite.
    unsafe {
        let inner = vfs.cast::<TimeVfsInner>();
        *out = (*inner).now_unix_ms.load(Ordering::Relaxed) + UNIX_EPOCH_JULIAN_MS;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    let mut ms: ffi::sqlite3_int64 = 0;
    // SAFETY: same contract as above; `ms` is a local.
    unsafe {
        current_time_int64(vfs, &mut ms);
        *out = ms as f64 / 86_400_000.0;
    }
    ffi::SQLITE_OK
}

static NEXT_VFS: AtomicU64 = AtomicU64::new(1);

impl TimeVfs {
    pub fn new() -> rusqlite::Result<Self> {
        install_utc_localtime();
        let name = format!("kronik-time-{}", NEXT_VFS.fetch_add(1, Ordering::Relaxed));
        let cname = CString::new(name.clone()).map_err(|_| rusqlite::Error::InvalidQuery)?;
        // SAFETY: `sqlite3_vfs_find(NULL)` returns the default VFS, valid for
        // the life of the process; we copy it by value and override fields.
        unsafe {
            let default = ffi::sqlite3_vfs_find(ptr::null());
            if default.is_null() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let mut base = *default;
            base.pNext = ptr::null_mut();
            base.zName = cname.as_ptr();
            base.xCurrentTime = Some(current_time);
            base.xCurrentTimeInt64 = Some(current_time_int64);
            // Extensions are disabled at several layers; also remove the hook.
            base.xDlOpen = None;
            if base.iVersion < 2 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let inner = Box::into_raw(Box::new(TimeVfsInner {
                base,
                now_unix_ms: AtomicI64::new(0),
                _name: cname,
            }));
            let rc = ffi::sqlite3_vfs_register(&raw mut (*inner).base, 0);
            if rc != ffi::SQLITE_OK {
                drop(Box::from_raw(inner));
                return Err(rusqlite::Error::SqliteFailure(ffi::Error::new(rc), None));
            }
            Ok(Self { inner, name })
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_time_ms(&self, unix_ms: i64) {
        // SAFETY: `inner` stays valid until Drop.
        unsafe { (*self.inner).now_unix_ms.store(unix_ms, Ordering::Relaxed) }
    }
}

impl Drop for TimeVfs {
    fn drop(&mut self) {
        // SAFETY: every connection using this VFS has been closed (the owner
        // drops its `Connection` first); unregister, then free.
        unsafe {
            ffi::sqlite3_vfs_unregister(&raw mut (*self.inner).base);
            drop(Box::from_raw(self.inner));
        }
    }
}

// ------------------------------------------------------------- localtime

unsafe extern "C" fn utc_localtime(t: *const c_void, tm: *mut c_void) -> c_int {
    // SAFETY: SQLite passes a `time_t*` and a `struct tm*` (see
    // SQLITE_TESTCTRL_LOCALTIME_FAULT); gmtime_r is thread-safe.
    unsafe {
        if libc::gmtime_r(t.cast::<libc::time_t>(), tm.cast::<libc::tm>()).is_null() {
            1
        } else {
            0
        }
    }
}

/// Makes SQLite's `localtime`/`utc` modifiers compute in UTC, independent of
/// `TZ` and `/etc/localtime`. Process-wide and stateless.
pub fn install_utc_localtime() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: documented test-control with signature
        // (int op, int onoff, int(*)(const void*, void*)).
        unsafe {
            let f: unsafe extern "C" fn(*const c_void, *mut c_void) -> c_int = utc_localtime;
            ffi::sqlite3_test_control(ffi::SQLITE_TESTCTRL_LOCALTIME_FAULT, 2 as c_int, f);
        }
    });
}

// --------------------------------------------------------------- session

fn rc_err(rc: c_int, what: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(ffi::Error::new(rc), Some(what.to_string()))
}

unsafe extern "C" fn skip_kronik_tables(_ctx: *mut c_void, tab: *const c_char) -> c_int {
    // SAFETY: SQLite passes a NUL-terminated table name.
    let name = unsafe { CStr::from_ptr(tab) }.to_bytes();
    c_int::from(!name.starts_with(b"_kronik"))
}

/// A session recording every table of `main` except Kronik's own
/// `_kronik*` tables. Must be dropped before its connection.
pub struct Session {
    raw: *mut ffi::sqlite3_session,
}

// SAFETY: a session is only ever used together with its connection, by the
// owner of that connection (`SqlActor`, behind a mutex). SQLite in
// multi-thread mode allows a connection and its sessions to move between
// threads as long as they are not used concurrently.
unsafe impl Send for Session {}

impl Session {
    pub fn new(conn: &Connection, track_rowid_tables: bool) -> rusqlite::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: `conn.handle()` is a valid open connection; the session is
        // deleted in Drop before the connection is closed by our owner.
        unsafe {
            let rc = ffi::sqlite3session_create(conn.handle(), c"main".as_ptr(), &mut raw);
            if rc != ffi::SQLITE_OK {
                return Err(rc_err(rc, "sqlite3session_create"));
            }
            let mut on: c_int = c_int::from(track_rowid_tables);
            let rc = ffi::sqlite3session_object_config(
                raw,
                ffi::SQLITE_SESSION_OBJCONFIG_ROWID as c_int,
                (&raw mut on).cast(),
            );
            if rc != ffi::SQLITE_OK {
                ffi::sqlite3session_delete(raw);
                return Err(rc_err(rc, "SQLITE_SESSION_OBJCONFIG_ROWID"));
            }
            ffi::sqlite3session_table_filter(raw, Some(skip_kronik_tables), ptr::null_mut());
            let rc = ffi::sqlite3session_attach(raw, ptr::null());
            if rc != ffi::SQLITE_OK {
                ffi::sqlite3session_delete(raw);
                return Err(rc_err(rc, "sqlite3session_attach"));
            }
        }
        Ok(Self { raw })
    }

    pub fn changeset(&self) -> rusqlite::Result<Vec<u8>> {
        let mut n: c_int = 0;
        let mut p: *mut c_void = ptr::null_mut();
        // SAFETY: valid session; the buffer is copied and freed with sqlite3_free.
        unsafe {
            let rc = ffi::sqlite3session_changeset(self.raw, &mut n, &mut p);
            if rc != ffi::SQLITE_OK {
                return Err(rc_err(rc, "sqlite3session_changeset"));
            }
            Ok(take_buffer(p, n))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: created by sqlite3session_create, deleted exactly once.
        unsafe { ffi::sqlite3session_delete(self.raw) }
    }
}

/// Copies an sqlite3_malloc'ed buffer into a Vec and frees it.
unsafe fn take_buffer(p: *mut c_void, n: c_int) -> Vec<u8> {
    if p.is_null() || n <= 0 {
        if !p.is_null() {
            // SAFETY: allocated by SQLite.
            unsafe { ffi::sqlite3_free(p) };
        }
        return Vec::new();
    }
    // SAFETY: SQLite returned `n` valid bytes at `p`.
    let v = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), n as usize) }.to_vec();
    // SAFETY: allocated by SQLite.
    unsafe { ffi::sqlite3_free(p) };
    v
}

// ------------------------------------------------------------- changesets

/// A value inside a changeset; `None` in a change means "not present".
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

unsafe fn read_value(v: *mut ffi::sqlite3_value) -> Option<Val> {
    if v.is_null() {
        return None;
    }
    // SAFETY: `v` is a valid sqlite3_value owned by the iterator.
    unsafe {
        Some(match ffi::sqlite3_value_type(v) {
            ffi::SQLITE_INTEGER => Val::Int(ffi::sqlite3_value_int64(v)),
            ffi::SQLITE_FLOAT => Val::Real(ffi::sqlite3_value_double(v)),
            ffi::SQLITE_TEXT => {
                let n = ffi::sqlite3_value_bytes(v) as usize;
                let p = ffi::sqlite3_value_text(v);
                Val::Text(String::from_utf8_lossy(std::slice::from_raw_parts(p, n)).into_owned())
            }
            ffi::SQLITE_BLOB => {
                let n = ffi::sqlite3_value_bytes(v) as usize;
                let p = ffi::sqlite3_value_blob(v).cast::<u8>();
                Val::Blob(if n == 0 {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(p, n).to_vec()
                })
            }
            _ => Val::Null,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Insert,
    Update,
    Delete,
}

/// One decoded change.
#[derive(Debug, Clone)]
pub struct Change {
    pub table: String,
    pub op: Op,
    pub pk: Vec<bool>,
    pub old: Vec<Option<Val>>,
    pub new: Vec<Option<Val>>,
}

struct Iter(*mut ffi::sqlite3_changeset_iter);

impl Drop for Iter {
    fn drop(&mut self) {
        // SAFETY: started by sqlite3changeset_start, finalized once.
        unsafe { ffi::sqlite3changeset_finalize(self.0) };
    }
}

fn start(cs: &[u8]) -> rusqlite::Result<Iter> {
    let mut it = ptr::null_mut();
    // SAFETY: the iterator borrows `cs`, which outlives it in every caller.
    let rc = unsafe {
        ffi::sqlite3changeset_start(&mut it, cs.len() as c_int, cs.as_ptr() as *mut c_void)
    };
    if rc != ffi::SQLITE_OK {
        return Err(rc_err(rc, "sqlite3changeset_start"));
    }
    Ok(Iter(it))
}

unsafe fn decode(it: *mut ffi::sqlite3_changeset_iter) -> rusqlite::Result<Change> {
    // SAFETY: `it` points at a valid change (sqlite3changeset_next returned ROW).
    unsafe {
        let mut tab: *const c_char = ptr::null();
        let (mut ncol, mut op, mut indirect) = (0, 0, 0);
        let rc = ffi::sqlite3changeset_op(it, &mut tab, &mut ncol, &mut op, &mut indirect);
        if rc != ffi::SQLITE_OK {
            return Err(rc_err(rc, "sqlite3changeset_op"));
        }
        let mut pk_flags: *mut u8 = ptr::null_mut();
        let mut npk = 0;
        ffi::sqlite3changeset_pk(it, &mut pk_flags, &mut npk);
        let pk = (0..npk as usize).map(|i| *pk_flags.add(i) != 0).collect();
        let op = match op {
            ffi::SQLITE_INSERT => Op::Insert,
            ffi::SQLITE_UPDATE => Op::Update,
            _ => Op::Delete,
        };
        let mut old = Vec::new();
        let mut new = Vec::new();
        for i in 0..ncol {
            let mut v = ptr::null_mut();
            if op != Op::Insert && ffi::sqlite3changeset_old(it, i, &mut v) == ffi::SQLITE_OK {
                old.push(read_value(v));
            } else {
                old.push(None);
            }
            let mut v = ptr::null_mut();
            if op != Op::Delete && ffi::sqlite3changeset_new(it, i, &mut v) == ffi::SQLITE_OK {
                new.push(read_value(v));
            } else {
                new.push(None);
            }
        }
        Ok(Change {
            table: CStr::from_ptr(tab).to_string_lossy().into_owned(),
            op,
            pk,
            old,
            new,
        })
    }
}

/// Decodes every change of a changeset.
pub fn changes(cs: &[u8]) -> rusqlite::Result<Vec<Change>> {
    let it = start(cs)?;
    let mut out = Vec::new();
    // SAFETY: standard iterate-until-not-ROW loop.
    unsafe {
        while ffi::sqlite3changeset_next(it.0) == ffi::SQLITE_ROW {
            out.push(decode(it.0)?);
        }
    }
    Ok(out)
}

/// Splits a changeset into one changeset per key returned by `key` for each
/// change. Changes keep their relative order inside each output.
pub fn split<K: Ord + Clone>(
    cs: &[u8],
    mut key: impl FnMut(&Change) -> Result<K, String>,
) -> Result<BTreeMap<K, Vec<u8>>, String> {
    struct Group(*mut ffi::sqlite3_changegroup);
    impl Drop for Group {
        fn drop(&mut self) {
            // SAFETY: created by sqlite3changegroup_new, deleted once.
            unsafe { ffi::sqlite3changegroup_delete(self.0) }
        }
    }
    let it = start(cs).map_err(|e| e.to_string())?;
    let mut groups: BTreeMap<K, Group> = BTreeMap::new();
    // SAFETY: the iterator is valid while `cs` lives; groups are freed in Drop.
    unsafe {
        while ffi::sqlite3changeset_next(it.0) == ffi::SQLITE_ROW {
            let change = decode(it.0).map_err(|e| e.to_string())?;
            let k = key(&change)?;
            if !groups.contains_key(&k) {
                let mut g = ptr::null_mut();
                let rc = ffi::sqlite3changegroup_new(&mut g);
                if rc != ffi::SQLITE_OK {
                    return Err(format!("sqlite3changegroup_new: {rc}"));
                }
                groups.insert(k.clone(), Group(g));
            }
            let g = &groups[&k];
            let rc = ffi::sqlite3changegroup_add_change(g.0, it.0);
            if rc != ffi::SQLITE_OK {
                return Err(format!("sqlite3changegroup_add_change: {rc}"));
            }
        }
        let mut out = BTreeMap::new();
        for (k, g) in groups {
            let (mut n, mut p) = (0, ptr::null_mut());
            let rc = ffi::sqlite3changegroup_output(g.0, &mut n, &mut p);
            if rc != ffi::SQLITE_OK {
                return Err(format!("sqlite3changegroup_output: {rc}"));
            }
            out.insert(k, take_buffer(p, n));
        }
        Ok(out)
    }
}

struct ApplyCtx {
    conflicts: Vec<String>,
}

unsafe extern "C" fn on_conflict(
    ctx: *mut c_void,
    kind: c_int,
    it: *mut ffi::sqlite3_changeset_iter,
) -> c_int {
    // SAFETY: `ctx` is the ApplyCtx passed to apply_v2 below; `it` is valid
    // for the duration of the callback.
    unsafe {
        let ctx = &mut *ctx.cast::<ApplyCtx>();
        let what = match kind {
            ffi::SQLITE_CHANGESET_DATA => "DATA",
            ffi::SQLITE_CHANGESET_NOTFOUND => "NOTFOUND",
            ffi::SQLITE_CHANGESET_CONFLICT => "CONFLICT",
            ffi::SQLITE_CHANGESET_CONSTRAINT => "CONSTRAINT",
            ffi::SQLITE_CHANGESET_FOREIGN_KEY => "FOREIGN_KEY",
            _ => "OTHER",
        };
        let table = decode(it)
            .map(|c| format!("{} {:?}", c.table, c.op))
            .unwrap_or_default();
        ctx.conflicts.push(format!("{what} on {table}"));
        // The target must be in exactly the expected state (production
        // apply, rebuild, roll-forward): any conflict is divergence.
        ffi::SQLITE_CHANGESET_ABORT
    }
}

/// Applies a changeset inside the caller's transaction. Foreign-key actions
/// are suppressed (their effects are already in the changeset). Any
/// conflict aborts the apply and is returned as an error.
pub fn apply(conn: &Connection, cs: &[u8]) -> Result<(), String> {
    let mut ctx = ApplyCtx {
        conflicts: Vec::new(),
    };
    // SAFETY: `conn` is valid; `cs` and `ctx` outlive the call.
    let rc = unsafe {
        ffi::sqlite3changeset_apply_v2(
            conn.handle(),
            cs.len() as c_int,
            cs.as_ptr() as *mut c_void,
            None,
            Some(on_conflict),
            (&raw mut ctx).cast(),
            ptr::null_mut(),
            ptr::null_mut(),
            ffi::SQLITE_CHANGESETAPPLY_FKNOACTION as c_int,
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(format!(
            "changeset apply failed (rc {rc}): {:?}",
            ctx.conflicts
        ));
    }
    Ok(())
}

/// `last_insert_rowid()` is per-connection state; reset it at turn start so
/// a guest never observes a rowid from a previous turn or a host apply.
pub fn reset_last_insert_rowid(conn: &Connection) {
    // SAFETY: valid connection handle.
    unsafe { ffi::sqlite3_set_last_insert_rowid(conn.handle(), 0) }
}

/// The tables a changeset touches (without decoding values).
pub fn tables(cs: &[u8]) -> rusqlite::Result<std::collections::BTreeSet<String>> {
    let it = start(cs)?;
    let mut out = std::collections::BTreeSet::new();
    // SAFETY: standard iterate-until-not-ROW loop; the name is copied.
    unsafe {
        while ffi::sqlite3changeset_next(it.0) == ffi::SQLITE_ROW {
            let mut tab: *const c_char = ptr::null();
            let (mut ncol, mut op, mut indirect) = (0, 0, 0);
            if ffi::sqlite3changeset_op(it.0, &mut tab, &mut ncol, &mut op, &mut indirect)
                == ffi::SQLITE_OK
            {
                out.insert(CStr::from_ptr(tab).to_string_lossy().into_owned());
            }
        }
    }
    Ok(out)
}
