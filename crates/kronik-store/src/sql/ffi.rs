//! The only module with `unsafe` code (allowlisted in ADR 0005).
//!
//! It wraps the SQLite C APIs that `rusqlite` does not expose:
//! - a per-connection VFS whose clock is the turn's logical time
//!   (`xCurrentTimeInt64`), so every `'now'` in SQL is deterministic;
//! - a process-wide alternative `localtime()` that is UTC, so the
//!   `localtime`/`utc` date modifiers do not depend on the host's time zone;
//! - the session extension with `SQLITE_SESSION_OBJCONFIG_ROWID`, table
//!   filters, `sqlite3changeset_apply_v2` flags,
//!   `sqlite3changegroup_add_change` for splitting a changeset per subject,
//!   and `sqlite3changegroup_add` for combining those changesets on apply;
//! - a copy-on-write VFS so replay workers share one snapshot image (#197).
//!
//! Every function here takes or returns plain Rust data; no SQLite pointer
//! escapes this module except inside the RAII types defined here.
//
// Allowlisted: SQLite's session, VFS and localtime APIs have no safe binding.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Once};

use kronik_core::sync::lock;
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
        if libc::gmtime_r(t.cast(), tm.cast()).is_null() {
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

/// Combines changesets into one. Applying that once checks foreign keys
/// after every part, which separate applies do not. Changes of one primary
/// key are merged; a turn's split never puts one row in two parts.
pub fn combine(parts: &[&[u8]]) -> Result<Vec<u8>, String> {
    struct Group(*mut ffi::sqlite3_changegroup);
    impl Drop for Group {
        fn drop(&mut self) {
            // SAFETY: created by sqlite3changegroup_new, deleted once.
            unsafe { ffi::sqlite3changegroup_delete(self.0) }
        }
    }
    if parts.is_empty() {
        return Ok(Vec::new());
    }
    // SAFETY: the group is freed in Drop; each part outlives the add.
    unsafe {
        let mut raw = ptr::null_mut();
        let rc = ffi::sqlite3changegroup_new(&mut raw);
        if rc != ffi::SQLITE_OK {
            return Err(format!("sqlite3changegroup_new: {rc}"));
        }
        let group = Group(raw);
        for part in parts {
            let rc = ffi::sqlite3changegroup_add(
                group.0,
                part.len() as c_int,
                part.as_ptr().cast_mut().cast(),
            );
            if rc != ffi::SQLITE_OK {
                return Err(format!("sqlite3changegroup_add: {rc}"));
            }
        }
        let (mut n, mut p) = (0, ptr::null_mut());
        let rc = ffi::sqlite3changegroup_output(group.0, &mut n, &mut p);
        if rc != ffi::SQLITE_OK {
            return Err(format!("sqlite3changegroup_output: {rc}"));
        }
        Ok(take_buffer(p, n))
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
    // SAFETY: `ctx` is the ApplyCtx passed to apply_v2 below. `it` is a
    // row iterator except for FOREIGN_KEY, which only reports a count.
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
        // A FOREIGN_KEY iterator has no row. Decoding it dereferences null.
        let detail = if kind == ffi::SQLITE_CHANGESET_FOREIGN_KEY {
            let mut n = 0;
            let _ = ffi::sqlite3changeset_fk_conflicts(it, &mut n);
            n.to_string()
        } else {
            decode(it)
                .map(|c| format!("{} {:?}", c.table, c.op))
                .unwrap_or_default()
        };
        ctx.conflicts.push(format!("{what} on {detail}"));
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

// ------------------------------------------------------- shared snapshot

/// Page copied into a worker when it writes. The shared image is never written.
const COW_PAGE: u64 = 4096;

struct BoundImage {
    bytes: Arc<[u8]>,
    private: Arc<AtomicU64>,
}

struct CowBytes {
    base: Option<Arc<[u8]>>,
    dirty: HashMap<u64, Box<[u8; COW_PAGE as usize]>>,
    size: u64,
}

struct CowInner {
    bytes: Mutex<CowBytes>,
    private: Option<Arc<AtomicU64>>,
}

impl Drop for CowInner {
    fn drop(&mut self) {
        let Some(counter) = &self.private else {
            return;
        };
        let pages = lock(&self.bytes).dirty.len() as u64;
        counter.fetch_sub(pages * COW_PAGE, Ordering::Relaxed);
    }
}

#[repr(C)]
struct CowFile {
    base: ffi::sqlite3_file,
    inner: *const CowInner,
}

fn image_map() -> &'static Mutex<HashMap<String, BoundImage>> {
    static MAP: LazyLock<Mutex<HashMap<String, BoundImage>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    &MAP
}

fn lock_images() -> std::sync::MutexGuard<'static, HashMap<String, BoundImage>> {
    lock(image_map())
}

/// Shared private-byte counter for one snapshot image. Paths bound through
/// it stay registered until the last clone drops, which is after every
/// connection that opened them.
pub(crate) struct CowShare {
    private: Arc<AtomicU64>,
    paths: Mutex<Vec<String>>,
}

impl CowShare {
    pub(crate) fn new() -> CowShare {
        CowShare {
            private: Arc::new(AtomicU64::new(0)),
            paths: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn private_bytes(&self) -> u64 {
        self.private.load(Ordering::Relaxed)
    }

    pub(crate) fn bind(&self, path: &str, bytes: Arc<[u8]>) {
        lock_images().insert(
            path.to_owned(),
            BoundImage {
                bytes,
                private: self.private.clone(),
            },
        );
        lock(&self.paths).push(path.to_owned());
    }
}

impl Drop for CowShare {
    fn drop(&mut self) {
        let mut images = lock_images();
        for path in lock(&self.paths).drain(..) {
            images.remove(&path);
        }
    }
}

fn counter_for(path: &str) -> Option<Arc<AtomicU64>> {
    lock_images()
        .iter()
        .filter(|(key, _)| path.starts_with(key.as_str()))
        .max_by_key(|(key, _)| key.len())
        .map(|(_, bound)| bound.private.clone())
}

fn c_name(name: *const c_char) -> Option<String> {
    if name.is_null() {
        return None;
    }
    // SAFETY: SQLite passes a NUL-terminated path, or NULL which we rejected.
    Some(
        unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn write_at(bytes: &mut CowBytes, offset: u64, src: &[u8], private: &Option<Arc<AtomicU64>>) {
    let end = offset + src.len() as u64;
    if end > bytes.size {
        bytes.size = end;
    }
    for (i, byte) in src.iter().enumerate() {
        let at = offset + i as u64;
        let page = at / COW_PAGE;
        let within = (at % COW_PAGE) as usize;
        if let std::collections::hash_map::Entry::Vacant(slot) = bytes.dirty.entry(page) {
            let mut buf = Box::new([0u8; COW_PAGE as usize]);
            if let Some(base) = &bytes.base {
                let start = (page * COW_PAGE) as usize;
                if start < base.len() {
                    let n = (base.len() - start).min(COW_PAGE as usize);
                    buf[..n].copy_from_slice(&base[start..start + n]);
                }
            }
            if let Some(counter) = private {
                counter.fetch_add(COW_PAGE, Ordering::Relaxed);
            }
            slot.insert(buf);
        }
        if let Some(buf) = bytes.dirty.get_mut(&page) {
            buf[within] = *byte;
        }
    }
}

fn byte_at(bytes: &CowBytes, offset: u64) -> u8 {
    let page = offset / COW_PAGE;
    let within = (offset % COW_PAGE) as usize;
    if let Some(buf) = bytes.dirty.get(&page) {
        return buf[within];
    }
    bytes
        .base
        .as_ref()
        .and_then(|base| base.get(offset as usize).copied())
        .unwrap_or(0)
}

unsafe extern "C" fn cow_close(file: *mut ffi::sqlite3_file) -> c_int {
    // SAFETY: `file` is a `CowFile` we wrote in `cow_open`; the inner Arc
    // was leaked into the pointer and is rebuilt once here.
    unsafe {
        let inner = (*file.cast::<CowFile>()).inner;
        if !inner.is_null() {
            drop(Arc::from_raw(inner));
        }
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_read(
    file: *mut ffi::sqlite3_file,
    dst: *mut c_void,
    amt: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    if amt < 0 || offset < 0 {
        return ffi::SQLITE_IOERR;
    }
    let amt = amt as usize;
    let offset = offset as u64;
    // SAFETY: SQLite passes a writable buffer of `amt` bytes and our file.
    let out = unsafe { std::slice::from_raw_parts_mut(dst.cast::<u8>(), amt) };
    let inner = unsafe { &*(*file.cast::<CowFile>()).inner };
    let bytes = lock(&inner.bytes);
    if offset >= bytes.size {
        out.fill(0);
        return ffi::SQLITE_IOERR_SHORT_READ;
    }
    let have = (bytes.size - offset) as usize;
    let n = amt.min(have);
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = byte_at(&bytes, offset + i as u64);
    }
    if n < amt {
        out[n..].fill(0);
        return ffi::SQLITE_IOERR_SHORT_READ;
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_write(
    file: *mut ffi::sqlite3_file,
    src: *const c_void,
    amt: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    if amt < 0 || offset < 0 {
        return ffi::SQLITE_IOERR;
    }
    let amt = amt as usize;
    let offset = offset as u64;
    // SAFETY: SQLite passes `amt` readable bytes and our file.
    let input = unsafe { std::slice::from_raw_parts(src.cast::<u8>(), amt) };
    let inner = unsafe { &*(*file.cast::<CowFile>()).inner };
    let mut bytes = lock(&inner.bytes);
    write_at(&mut bytes, offset, input, &inner.private);
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_truncate(file: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    if size < 0 {
        return ffi::SQLITE_IOERR;
    }
    let inner = unsafe { &*(*file.cast::<CowFile>()).inner };
    let mut bytes = lock(&inner.bytes);
    bytes.size = size as u64;
    let keep = bytes.size.div_ceil(COW_PAGE);
    let before = bytes.dirty.len();
    bytes.dirty.retain(|page, _| *page < keep);
    let dropped = before.saturating_sub(bytes.dirty.len()) as u64;
    if dropped > 0
        && let Some(counter) = &inner.private
    {
        counter.fetch_sub(dropped * COW_PAGE, Ordering::Relaxed);
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_sync(_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_file_size(
    file: *mut ffi::sqlite3_file,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    let inner = unsafe { &*(*file.cast::<CowFile>()).inner };
    let size = lock(&inner.bytes).size;
    // SAFETY: SQLite passes a writable i64.
    unsafe { *out = size as ffi::sqlite3_int64 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_lock(_file: *mut ffi::sqlite3_file, _level: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_unlock(_file: *mut ffi::sqlite3_file, _level: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_check_reserved(_file: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    // SAFETY: SQLite passes a writable int.
    unsafe { *out = 0 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_file_control(
    _file: *mut ffi::sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    // Replay databases are ephemeral. Refuse mmap; ignore size hints.
    if op == ffi::SQLITE_FCNTL_MMAP_SIZE && !arg.is_null() {
        // SAFETY: SQLite passes an i64* for this opcode.
        unsafe { *arg.cast::<ffi::sqlite3_int64>() = 0 };
        return ffi::SQLITE_OK;
    }
    if op == ffi::SQLITE_FCNTL_HAS_MOVED && !arg.is_null() {
        unsafe { *arg.cast::<c_int>() = 0 };
        return ffi::SQLITE_OK;
    }
    if op == ffi::SQLITE_FCNTL_SIZE_HINT || op == ffi::SQLITE_FCNTL_PRAGMA {
        return ffi::SQLITE_NOTFOUND;
    }
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn cow_sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    512
}

unsafe extern "C" fn cow_device(_file: *mut ffi::sqlite3_file) -> c_int {
    ffi::SQLITE_IOCAP_ATOMIC
        | ffi::SQLITE_IOCAP_SAFE_APPEND
        | ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE
        | ffi::SQLITE_IOCAP_SEQUENTIAL
}

static COW_IO: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(cow_close),
    xRead: Some(cow_read),
    xWrite: Some(cow_write),
    xTruncate: Some(cow_truncate),
    xSync: Some(cow_sync),
    xFileSize: Some(cow_file_size),
    xLock: Some(cow_lock),
    xUnlock: Some(cow_unlock),
    xCheckReservedLock: Some(cow_check_reserved),
    xFileControl: Some(cow_file_control),
    xSectorSize: Some(cow_sector_size),
    xDeviceCharacteristics: Some(cow_device),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn cow_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    _flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let path = c_name(name)
        .unwrap_or_else(|| format!("kcow-tmp-{}", NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
    let bound = lock_images().get(&path).map(|b| BoundImage {
        bytes: b.bytes.clone(),
        private: b.private.clone(),
    });
    let (base, size, private) = match bound {
        Some(b) => (Some(b.bytes.clone()), b.bytes.len() as u64, Some(b.private)),
        None => (None, 0, counter_for(&path)),
    };
    let inner = Arc::new(CowInner {
        bytes: Mutex::new(CowBytes {
            base,
            dirty: HashMap::new(),
            size,
        }),
        private,
    });
    // SAFETY: SQLite allocated `szOsFile` bytes, which we set to fit `CowFile`.
    unsafe {
        ptr::write(
            file.cast::<CowFile>(),
            CowFile {
                base: ffi::sqlite3_file { pMethods: &COW_IO },
                inner: Arc::into_raw(inner),
            },
        );
        if !out_flags.is_null() {
            *out_flags = ffi::SQLITE_OPEN_READWRITE;
        }
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    // Journals are memory. The shared image is not deleted: other workers
    // still have it. A missing file is success.
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_access(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    _flags: c_int,
    out: *mut c_int,
) -> c_int {
    let exists = c_name(name).is_some_and(|path| lock_images().contains_key(&path));
    // SAFETY: SQLite passes a writable int.
    unsafe { *out = c_int::from(exists) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn cow_fullpath(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    n_out: c_int,
    out: *mut c_char,
) -> c_int {
    if name.is_null() || out.is_null() || n_out <= 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: `name` is NUL-terminated; `out` has `n_out` bytes.
    unsafe {
        let len = CStr::from_ptr(name).to_bytes().len();
        if len + 1 > n_out as usize {
            return ffi::SQLITE_CANTOPEN;
        }
        ptr::copy_nonoverlapping(name, out, len + 1);
        let _ = vfs;
    }
    ffi::SQLITE_OK
}

fn install_cow_methods(vfs: *mut ffi::sqlite3_vfs) {
    // SAFETY: `vfs` is a registered VFS we own or a TimeVfs just created
    // for this connection, not yet opened.
    unsafe {
        (*vfs).xOpen = Some(cow_open);
        (*vfs).xDelete = Some(cow_delete);
        (*vfs).xAccess = Some(cow_access);
        (*vfs).xFullPathname = Some(cow_fullpath);
        let need = std::mem::size_of::<CowFile>() as c_int;
        if (*vfs).szOsFile < need {
            (*vfs).szOsFile = need;
        }
        if (*vfs).mxPathname < 512 {
            (*vfs).mxPathname = 512;
        }
    }
}

/// The process-wide VFS replay uses for `state.db`. The static owns the
/// struct; SQLite keeps a pointer into it for the process.
pub(crate) fn cow_vfs_name() -> &'static str {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        // SAFETY: `COW_VFS` does not move after init. SQLite stores this
        // pointer and may write `pNext`; Rust does not read the struct again.
        unsafe {
            let vfs = COW_VFS.0.get();
            if (*vfs).zName.is_null() {
                return;
            }
            install_cow_methods(vfs);
            let _ = ffi::sqlite3_vfs_register(vfs, 0);
        }
    });
    "kronik-cow"
}

struct SyncVfs(std::cell::UnsafeCell<ffi::sqlite3_vfs>);

// SAFETY: the value stays in this static. SQLite, not Rust, uses the
// pointer from any thread after register. The raw pointers inside are the
// default VFS's, which SQLite already shares across threads.
unsafe impl Send for SyncVfs {}
unsafe impl Sync for SyncVfs {}

static COW_VFS: LazyLock<SyncVfs> = LazyLock::new(|| {
    // SAFETY: the default VFS, if any, lives for the process. Copied into
    // the static before any connection uses the name.
    unsafe {
        let default = ffi::sqlite3_vfs_find(ptr::null());
        let mut base = if default.is_null() {
            std::mem::zeroed()
        } else {
            *default
        };
        base.pNext = ptr::null_mut();
        base.zName = if default.is_null() {
            ptr::null()
        } else {
            c"kronik-cow".as_ptr()
        };
        base.xDlOpen = None;
        SyncVfs(std::cell::UnsafeCell::new(base))
    }
});

/// Point a just-created TimeVfs at the shared snapshot methods, so an actor
/// database opened on it copies pages only when that worker writes.
pub(crate) fn arm_cow_vfs(name: &str) -> Result<(), String> {
    let c_name = CString::new(name).map_err(|_| "vfs name has an interior nul".to_string())?;
    // SAFETY: the name is the VFS `SqlActor` just registered.
    unsafe {
        let vfs = ffi::sqlite3_vfs_find(c_name.as_ptr());
        if vfs.is_null() {
            return Err("snapshot vfs is not registered".into());
        }
        install_cow_methods(vfs);
    }
    Ok(())
}
