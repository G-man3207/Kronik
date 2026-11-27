//! Per-actor SQL state: one SQLite database per actor, owned by the host.
//!
//! A turn runs the guest's statements inside `SAVEPOINT kronik_turn` with a
//! session recording every table. At the end of the turn the changeset is
//! captured and split per subject, the savepoint is rolled back, and the
//! changeset is applied (after the turn record is durable in the real
//! daemon), so production, recovery and replay build the database the same
//! way. DDL is recorded as text and replayed before the changeset.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use kronik_core::sync::lock;
use rusqlite::functions::FunctionFlags;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, OpenFlags, StatementStatus};

use super::ffi::{self, Change, Op, Val};

/// `sql-error` from the WIT, plus fuel exhaustion (a turn-level trap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlError {
    Syntax(String),
    Constraint(String),
    Denied(String),
    TooLarge,
    /// The turn's SQL work budget ran out: the turn fails with `FUEL_EXHAUSTED`.
    FuelExhausted,
}

pub type SqlResult<T> = Result<T, SqlError>;

/// Rows returned by `sql.query`.
#[derive(Debug, Clone, PartialEq)]
pub struct Rows {
    pub columns: Vec<String>,
    pub values: Vec<Vec<Value>>,
}

#[derive(Clone)]
pub struct TurnOpts {
    pub seed: [u8; 32],
    pub time_ms: i64,
    pub default_subject: Option<String>,
    pub migrate: bool,
    /// SQL work budget in VM steps (deterministic, part of the turn's fuel).
    pub sql_budget: u64,
    /// The kind's database size limit for this turn's writes (0: 1 GiB).
    /// Applies and rebuilds are never limited.
    pub max_bytes: u64,
}

/// SQLite's largest `max_page_count`: no limit.
const UNLIMITED_PAGES: i64 = 4_294_967_294;

/// `pragma_table_info` returns the declared spelling. The write path treats
/// any ASCII case of `_subject` as the subject column, so erasure and
/// pseudonymization must too. SQLite `NOCASE` folds ASCII only, matching
/// [`is_subject_column`].
const SUBJECT_COL_EQ: &str = "c.name = '_subject' COLLATE NOCASE";

fn is_subject_column(name: &str) -> bool {
    name.eq_ignore_ascii_case("_subject")
}

/// What a turn contributes to its turn record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TurnSql {
    /// DDL exactly as executed, in order (`SqlSchemaChange`).
    pub ddl: Vec<String>,
    /// One changeset per subject (`SqlChangeset`, one `Sealable` each).
    pub changesets: Vec<(Option<String>, Vec<u8>)>,
    /// VM steps executed by the guest's statements.
    pub vm_steps: u64,
    /// The unsplit changeset. Not written to the log. `apply` uses it when
    /// it is set, which only tests do. Production combines `changesets`
    /// (ADR 0160).
    pub whole: Vec<u8>,
}

/// A turn's database size limit when its [`TurnOpts::max_bytes`] is 0.
const DEFAULT_MAX_BYTES: u64 = 1 << 30;
/// The largest string or blob (`SQLITE_LIMIT_LENGTH`, `randomblob`).
const VALUE_BYTES: i32 = 1 << 20;

#[derive(Default)]
struct Stmt {
    ddl: bool,
    dml: bool,
    select: bool,
    create_table: bool,
    denied: Option<String>,
}

struct Shared {
    host: bool,
    migrate: bool,
    dml_seen: bool,
    stmt: Stmt,
    rng: ChaCha20Rng,
    steps_in_progress: u64,
    budget: u64,
    rowid_max: bool,
    /// The turn's current default subject, returned by `kronik_subject()`.
    subject: Option<String>,
}

/// Opens actor databases: files in production, memory in the simulator
/// (ADR 0004). The opener never chooses the VFS; `SqlActor` passes its own.
pub trait SqliteOpener: Send + Sync {
    fn open(&self, actor: &str, vfs: &str) -> rusqlite::Result<Connection>;
    /// Whether the actor's database exists (without creating it).
    fn exists(&self, actor: &str) -> bool;
}

/// `sql/<2 hex>/<actor>.db` under a root directory.
pub struct FileOpener {
    pub root: std::path::PathBuf,
}

/// The longest actor name kept whole in its file name: with `-<8 hex>.db`
/// and SQLite's `-journal`, 255 bytes, the most a file name may have. Every
/// actor database created so far has a name this short: longer ones could
/// not create their journal.
const MAX_WHOLE_NAME: usize = 235;

pub fn actor_file(root: &std::path::Path, actor: &str) -> std::path::PathBuf {
    let h = blake3::hash(actor.as_bytes()).to_hex();
    let safe: String = actor
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '~'
            }
        })
        .collect();
    if safe.len() > MAX_WHOLE_NAME {
        // A key of up to 256 bytes: a prefix and the whole hash (`safe` is ASCII).
        return root.join(&h[..2]).join(format!("{}-{h}.db", &safe[..100]));
    }
    root.join(&h[..2]).join(format!("{safe}-{}.db", &h[..8]))
}

impl SqliteOpener for FileOpener {
    fn exists(&self, actor: &str) -> bool {
        actor_file(&self.root, actor).exists()
    }

    fn open(&self, actor: &str, vfs: &str) -> rusqlite::Result<Connection> {
        let path = actor_file(&self.root, actor);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|_| rusqlite::Error::InvalidPath(path.clone()))?;
        }
        let conn = Connection::open_with_flags_and_vfs(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs,
        )?;
        // Derived state: consistency after power loss is required (WAL keeps
        // every commit atomic), durability is not (the log is the truth, and
        // `applied_lsn` says where to resume). Exclusive locking: no -shm.
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Closing must not checkpoint (and fsync): connections are closed
        // often by the LRU. The WAL stays and is checkpointed by size.
        conn.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )?;
        Ok(conn)
    }
}

/// In-memory databases for the deterministic simulator. A database lives as
/// long as its connection: use a pool capacity that never evicts.
pub struct MemOpener;

impl SqliteOpener for MemOpener {
    fn exists(&self, _actor: &str) -> bool {
        false
    }

    fn open(&self, _actor: &str, vfs: &str) -> rusqlite::Result<Connection> {
        Connection::open_with_flags_and_vfs(
            ":memory:",
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs,
        )
    }
}

/// Read-only introspection pragmas a guest may run. Everything else
/// (storage, planner, behaviour, header fields) is denied.
const PRAGMA_QUERY: &[&str] = &[
    "table_info",
    "table_xinfo",
    "table_list",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "foreign_key_check",
    "collation_list",
    "function_list",
    "pragma_list",
    "compile_options",
];
/// Pragmas allowed only without a value (reads).
const PRAGMA_READ_ONLY: &[&str] = &[
    "user_version",
    "schema_version",
    "application_id",
    "encoding",
];

/// Functions whose result depends on connection history or physical layout.
const DENIED_FUNCTIONS: &[&str] = &[
    "load_extension",
    "changes",
    "total_changes",
    "sqlite_offset",
    "fts3_tokenizer",
    SCRUB_REPLACE,
];

/// The host's byte replace for the secret scrub of blob cells; a guest may
/// not call it ([`DENIED_FUNCTIONS`]).
const SCRUB_REPLACE: &str = "kronik_scrub_replace";

/// `haystack` with every occurrence of `needle` replaced by `with`, left to
/// right, byte for byte. An empty needle replaces nothing.
fn replace_bytes(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut rest = haystack;
    while !rest.is_empty() {
        if rest.starts_with(needle) {
            out.extend_from_slice(with);
            rest = &rest[needle.len()..];
        } else {
            out.push(rest[0]);
            rest = &rest[1..];
        }
    }
    out
}

/// Eponymous virtual tables that expose physical state.
const DENIED_TABLES: &[&str] = &["dbstat", "sqlite_dbpage", "sqlite_stmt"];

/// The schema tables that DDL writes to.
const SCHEMA_TABLES: &[&str] = &[
    "sqlite_master",
    "sqlite_schema",
    "sqlite_temp_master",
    "sqlite_temp_schema",
];

/// The first keyword of a statement, skipping whitespace and comments.
fn first_keyword(sql: &str) -> &str {
    let mut rest = sql;
    loop {
        rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix("--") {
            rest = r.split_once('\n').map(|(_, t)| t).unwrap_or("");
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = r.split_once("*/").map(|(_, t)| t).unwrap_or("");
        } else {
            break;
        }
    }
    let end = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    &rest[..end]
}

fn authorize(s: &mut Shared, ctx: &AuthContext<'_>) -> Authorization {
    let deny = |s: &mut Shared, why: String| {
        if s.stmt.denied.is_none() {
            s.stmt.denied = Some(why);
        }
        Authorization::Deny
    };
    if let AuthAction::Function { function_name } = &ctx.action {
        for name in ["sqlite_filestat", "sqlite_walstat"] {
            if function_name.eq_ignore_ascii_case(name) {
                return deny(s, format!("function {name}() is not allowed"));
            }
        }
    }
    if s.host {
        return Authorization::Allow;
    }
    let internal = |t: &str| t.starts_with("_kronik");
    match &ctx.action {
        AuthAction::Pragma {
            pragma_name,
            pragma_value,
        } => {
            let name = pragma_name.to_ascii_lowercase();
            if PRAGMA_QUERY.contains(&name.as_str())
                || (PRAGMA_READ_ONLY.contains(&name.as_str()) && pragma_value.is_none())
            {
                Authorization::Allow
            } else {
                deny(s, format!("PRAGMA {name} is not allowed"))
            }
        }
        AuthAction::Attach { .. } | AuthAction::Detach { .. } => {
            deny(s, "ATTACH and DETACH are not allowed".into())
        }
        AuthAction::Analyze { .. } => {
            deny(s, "ANALYZE is not allowed (it changes query plans)".into())
        }
        // CREATE INDEX authorizes a REINDEX of the new index after its
        // schema write; a standalone REINDEX statement has no schema write.
        AuthAction::Reindex { .. } if s.stmt.ddl => Authorization::Allow,
        AuthAction::Reindex { .. } => deny(s, "REINDEX is not allowed".into()),
        AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } => deny(
            s,
            "transactions and savepoints are managed by Kronik".into(),
        ),
        AuthAction::Function { function_name } => {
            let f = function_name.to_ascii_lowercase();
            if DENIED_FUNCTIONS.contains(&f.as_str()) {
                deny(s, format!("function {f}() is not allowed"))
            } else {
                Authorization::Allow
            }
        }
        AuthAction::CreateVtable { .. } | AuthAction::DropVtable { .. } => {
            deny(s, "virtual tables are not allowed".into())
        }
        AuthAction::CreateTempIndex { .. }
        | AuthAction::CreateTempTable { .. }
        | AuthAction::CreateTempTrigger { .. }
        | AuthAction::CreateTempView { .. }
        | AuthAction::DropTempIndex { .. }
        | AuthAction::DropTempTable { .. }
        | AuthAction::DropTempTrigger { .. }
        | AuthAction::DropTempView { .. } => deny(
            s,
            "TEMP objects are not allowed (they would outlive the turn on the connection)".into(),
        ),
        AuthAction::Read { table_name, .. } => {
            if internal(table_name) || DENIED_TABLES.contains(table_name) {
                deny(s, format!("table {table_name} is not accessible"))
            } else {
                Authorization::Allow
            }
        }
        AuthAction::Select | AuthAction::Recursive => {
            s.stmt.select = true;
            Authorization::Allow
        }
        AuthAction::Insert { table_name }
        | AuthAction::Delete { table_name }
        | AuthAction::Update { table_name, .. } => {
            // DDL first authorizes its write to the schema table; that write
            // is only possible through DDL (defensive mode, no writable_schema).
            if SCHEMA_TABLES.contains(table_name) {
                s.stmt.ddl = true;
                return Authorization::Allow;
            }
            if internal(table_name) || table_name.starts_with("sqlite_") {
                return deny(s, format!("table {table_name} is not writable"));
            }
            if let AuthAction::Update { column_name, .. } = &ctx.action
                && is_subject_column(column_name)
            {
                return deny(
                    s,
                    "changing _subject is not allowed; delete the row in one turn and insert it in a later one".into(),
                );
            }
            s.stmt.dml = true;
            Authorization::Allow
        }
        AuthAction::CreateTable { table_name } => {
            s.stmt.ddl = true;
            s.stmt.create_table = true;
            if internal(table_name) {
                return deny(s, "names starting with _kronik are reserved".into());
            }
            Authorization::Allow
        }
        AuthAction::CreateIndex { .. }
        | AuthAction::CreateTrigger { .. }
        | AuthAction::CreateView { .. }
        | AuthAction::DropIndex { .. }
        | AuthAction::DropTable { .. }
        | AuthAction::DropTrigger { .. }
        | AuthAction::DropView { .. }
        | AuthAction::AlterTable { .. } => {
            s.stmt.ddl = true;
            Authorization::Allow
        }
        AuthAction::Unknown { code, .. } => deny(s, format!("unknown authorizer action {code}")),
        _ => Authorization::Allow,
    }
}

/// A full scan whose changeset has not been applied yet. Confirmed only when
/// `apply` sees that changeset, so a discarded turn does not skip the next scan.
struct PendingScrub {
    secrets: Vec<(String, [u8; 32])>,
    cs_hash: Option<blake3::Hash>,
}

fn secret_id(name: &str, value: &[u8]) -> (String, [u8; 32]) {
    (name.to_owned(), *blake3::hash(value).as_bytes())
}

fn changeset_hash(changesets: &[(Option<String>, Vec<u8>)]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    for (subject, cs) in changesets {
        let subject = subject.as_deref().unwrap_or("");
        hasher.update(&(subject.len() as u64).to_le_bytes());
        hasher.update(subject.as_bytes());
        hasher.update(&(cs.len() as u64).to_le_bytes());
        hasher.update(cs);
    }
    hasher.finalize()
}

fn load_scrubbed(conn: &Connection) -> rusqlite::Result<HashSet<(String, [u8; 32])>> {
    let exists: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name = '_kronik_scrubbed'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(HashSet::new());
    }
    let mut st = conn.prepare("SELECT name, value_hash FROM _kronik_scrubbed")?;
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = HashSet::new();
    for row in rows {
        let (name, hash) = row?;
        if let Ok(hash) = <[u8; 32]>::try_from(hash) {
            out.insert((name, hash));
        }
    }
    Ok(out)
}

/// One actor's SQL database. Field order matters: the session must be
/// dropped before the connection, and the connection before its VFS.
pub struct SqlActor {
    session: Option<ffi::Session>,
    pub conn: Connection,
    vfs: ffi::TimeVfs,
    shared: Arc<Mutex<Shared>>,
    ddl: Vec<String>,
    steps: u64,
    default_subject: Option<String>,
    subject_cols: BTreeMap<String, Option<usize>>,
    /// SQLite rolled the whole transaction back (SQLITE_FULL, `OR ROLLBACK`,
    /// `RAISE(ROLLBACK)`): the turn's SQL is gone and the turn must fail.
    poisoned: bool,
    /// Whether the schema has triggers (cached; refreshed after DDL).
    has_triggers: Option<bool>,
    page_size: u64,
    /// Erasures applied while a turn had its savepoint open (subject, LSN):
    /// they run when the turn ends ([`SqlActor::erase_subject`]).
    deferred_erasures: Vec<(String, u64)>,
    /// A delete already ran, but its WAL checkpoint could not: a turn had
    /// the connection. [`SqlActor::end_turn`] and [`SqlActor::abort_turn`]
    /// checkpoint once the connection is idle (H11).
    erasure_checkpoint: bool,
    /// Secret values already removed from every user cell (name, blake3 of
    /// the value). A later turn scrubs only the rows it wrote (#198).
    seen_secrets: HashSet<(String, [u8; 32])>,
    /// The one-time scan of this turn, until its changeset is applied.
    pending_scrub: Option<PendingScrub>,
    /// Full-scan steps of the last `scrub`. A seen secret must not scan.
    #[cfg(test)]
    pub last_scrub_fullscan_steps: u64,
}

fn sql_err(e: rusqlite::Error, shared: &Mutex<Shared>) -> SqlError {
    let denied = lock(shared).stmt.denied.take();
    if let Some(why) = denied {
        return SqlError::Denied(why);
    }
    match e {
        rusqlite::Error::SqliteFailure(f, msg) => match f.code {
            rusqlite::ErrorCode::ConstraintViolation => {
                SqlError::Constraint(msg.unwrap_or_default())
            }
            rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::TooBig => SqlError::TooLarge,
            _ if msg.as_deref().is_some_and(|m| m.contains("too big")) => SqlError::TooLarge,
            rusqlite::ErrorCode::OperationInterrupted => SqlError::FuelExhausted,
            rusqlite::ErrorCode::AuthorizationForStatementDenied => {
                SqlError::Denied(msg.unwrap_or_default())
            }
            _ => SqlError::Syntax(msg.unwrap_or_else(|| f.to_string())),
        },
        other => SqlError::Syntax(other.to_string()),
    }
}

type LoggedChangesets = Vec<(Option<String>, Vec<u8>)>;
type CellRewrite<'a> = &'a dyn Fn(&str, &[u8]) -> Vec<u8>;

impl SqlActor {
    pub fn open(opener: &dyn SqliteOpener, actor: &str) -> rusqlite::Result<Self> {
        let vfs = ffi::TimeVfs::new()?;
        let mut conn = opener.open(actor, vfs.name())?;
        // secure_delete (H11): deleted rows are zeroed in their pages, so an
        // erasure leaves no copy in the file once the WAL is checkpointed.
        conn.execute_batch(
            "PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;
             PRAGMA recursive_triggers = OFF;
             PRAGMA cache_size = -512;
             PRAGMA secure_delete = ON;",
        )?;
        let has_meta: bool = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = '_kronik_meta'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)?;
        if !has_meta {
            conn.execute_batch(
                "CREATE TABLE _kronik_meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
                 INSERT INTO _kronik_meta VALUES ('applied_lsn', 0);",
            )?;
        }
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        // The size limit applies to a turn's writes only (begin_turn).
        conn.pragma_update(None, "max_page_count", UNLIMITED_PAGES)?;
        use rusqlite::config::DbConfig;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
        conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        conn.set_limit(Limit::SQLITE_LIMIT_WORKER_THREADS, 0)?;
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, VALUE_BYTES)?;
        conn.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 1 << 20)?;
        conn.set_limit(Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 32)?;

        let shared = Arc::new(Mutex::new(Shared {
            host: true,
            migrate: false,
            dml_seen: false,
            stmt: Stmt::default(),
            rng: ChaCha20Rng::from_seed([0; 32]),
            steps_in_progress: 0,
            budget: u64::MAX,
            rowid_max: false,
            subject: None,
        }));

        // Deterministic replacements for SQLite's PRNG-backed functions,
        // seeded per turn (ChaCha20 stream 4 of the turn seed).
        let s = shared.clone();
        conn.create_scalar_function(
            "random",
            0,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            move |_| Ok(lock(&s).rng.next_u64() as i64),
        )?;
        let s = shared.clone();
        let max_len = i64::from(VALUE_BYTES);
        conn.create_scalar_function(
            "randomblob",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            move |ctx| {
                let n = ctx.get::<i64>(0).unwrap_or(1).max(1);
                if n > max_len {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_TOOBIG),
                        Some("string or blob too big".into()),
                    ));
                }
                let mut b = vec![0u8; n as usize];
                lock(&s).rng.fill_bytes(&mut b);
                Ok(b)
            },
        )?;
        // The turn's default subject, e.g. `_subject TEXT DEFAULT
        // (kronik_subject())`. Innocuous so schemas may use it with
        // trusted_schema off; not deterministic because it changes per turn.
        let s = shared.clone();
        conn.create_scalar_function(
            "kronik_subject",
            0,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
            move |_| Ok(lock(&s).subject.clone()),
        )?;
        // The secret scrub's replace for blob cells (`scrub`): byte for byte.
        // SQLite's replace() takes a pattern whose first byte is NUL for an
        // empty one and leaves the value as it is. Host only (`authorize`).
        conn.create_scalar_function(
            SCRUB_REPLACE,
            3,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let bytes = |i: usize| -> rusqlite::Result<Vec<u8>> {
                    Ok(match ctx.get_raw(i) {
                        rusqlite::types::ValueRef::Blob(b) | rusqlite::types::ValueRef::Text(b) => {
                            b.to_vec()
                        }
                        _ => Vec::new(),
                    })
                };
                Ok(replace_bytes(&bytes(0)?, &bytes(1)?, &bytes(2)?))
            },
        )?;
        let s = shared.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            authorize(&mut lock(&s), &ctx)
        }))?;
        // SQLite picks a *random* rowid once max(rowid) = i64::MAX; forbid
        // ever storing that rowid so the random path is unreachable.
        let s = shared.clone();
        conn.update_hook(Some(move |_op, _db: &str, _tbl: &str, rowid: i64| {
            if rowid == i64::MAX {
                lock(&s).rowid_max = true;
            }
        }))?;
        // Interrupt runaway statements deterministically (VM step counts).
        let s = shared.clone();
        conn.progress_handler(
            1000,
            Some(move || {
                let mut g = lock(&s);
                if g.host {
                    return false;
                }
                g.steps_in_progress += 1000;
                g.steps_in_progress > g.budget
            }),
        )?;
        lock(&shared).host = true;
        // Existing tables gain the erasure index outside the apply lock:
        // the first open is the pin before that lock (#196).
        ensure_subject_indexes(&conn).map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e),
            )
        })?;
        let seen_secrets = load_scrubbed(&conn)?;
        Ok(Self {
            session: None,
            conn,
            vfs,
            shared,
            ddl: Vec::new(),
            steps: 0,
            default_subject: None,
            subject_cols: BTreeMap::new(),
            poisoned: false,
            has_triggers: None,
            page_size: page_size.max(512) as u64,
            deferred_erasures: Vec::new(),
            erasure_checkpoint: false,
            seen_secrets,
            pending_scrub: None,
            #[cfg(test)]
            last_scrub_fullscan_steps: 0,
        })
    }

    /// Runs host statements (`;`-separated) through the statement cache.
    fn host_batch(&self, sql: &str) -> rusqlite::Result<()> {
        lock(&self.shared).host = true;
        for part in sql.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            self.conn.prepare_cached(part)?.execute([])?;
        }
        Ok(())
    }

    pub fn applied_lsn(&self) -> rusqlite::Result<u64> {
        lock(&self.shared).host = true;
        self.conn
            .query_row(
                "SELECT v FROM _kronik_meta WHERE k = 'applied_lsn'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
    }

    pub fn begin_turn(&mut self, opts: &TurnOpts) -> rusqlite::Result<()> {
        self.vfs.set_time_ms(opts.time_ms);
        {
            let mut g = lock(&self.shared);
            let mut rng = ChaCha20Rng::from_seed(opts.seed);
            rng.set_stream(4);
            g.rng = rng;
            g.migrate = opts.migrate;
            g.dml_seen = false;
            g.budget = opts.sql_budget;
            g.steps_in_progress = 0;
            g.rowid_max = false;
            g.subject = opts.default_subject.clone();
            g.host = true;
        }
        self.ddl.clear();
        self.steps = 0;
        self.default_subject = opts.default_subject.clone();
        self.poisoned = false;
        self.pending_scrub = None;
        ffi::reset_last_insert_rowid(&self.conn);
        let max = if opts.max_bytes == 0 {
            DEFAULT_MAX_BYTES
        } else {
            opts.max_bytes
        };
        self.conn
            .pragma_update(None, "max_page_count", (max / self.page_size).max(1) as i64)?;
        self.host_batch("SAVEPOINT kronik_turn")?;
        self.session = Some(ffi::Session::new(&self.conn)?);
        Ok(())
    }

    /// `sql.execute`: returns the number of changed rows.
    pub fn execute(&mut self, sql: &str, params: &[Value]) -> SqlResult<u64> {
        self.run(sql, params).map(|(_, changed)| changed)
    }

    /// `sql.query`.
    pub fn query(&mut self, sql: &str, params: &[Value]) -> SqlResult<Rows> {
        self.run(sql, params).map(|(rows, _)| rows)
    }

    fn run(&mut self, sql: &str, params: &[Value]) -> SqlResult<(Rows, u64)> {
        let res = self.run_guest(sql, params);
        // Every exit (including a statement that failed to prepare) hands
        // the connection back to the host, or the session's own queries at
        // the end of the turn would be checked as guest statements.
        lock(&self.shared).host = true;
        res
    }

    fn run_guest(&mut self, sql: &str, params: &[Value]) -> SqlResult<(Rows, u64)> {
        {
            let mut g = lock(&self.shared);
            g.host = false;
            g.stmt = Stmt::default();
        }
        if self.poisoned {
            return Err(SqlError::Denied(
                "the turn's SQL transaction was rolled back; the turn will fail".into(),
            ));
        }
        // VACUUM is not visible to the authorizer.
        if first_keyword(sql).eq_ignore_ascii_case("vacuum") {
            return Err(SqlError::Denied("VACUUM is not allowed".into()));
        }
        let prepared = self.conn.prepare(sql);
        let mut stmt = match prepared {
            Ok(s) => s,
            Err(e) => return Err(sql_err(e, &self.shared)),
        };
        let kind = std::mem::take(&mut lock(&self.shared).stmt);
        if let Some(why) = kind.denied {
            return Err(SqlError::Denied(why));
        }
        let migrate = lock(&self.shared).migrate;
        let dml_seen = lock(&self.shared).dml_seen;
        if kind.ddl && !migrate {
            return Err(SqlError::Denied("DDL is only allowed in migrate".into()));
        }
        if kind.ddl && dml_seen {
            return Err(SqlError::Denied(
                "DDL must come before the first DML statement of the migrate turn".into(),
            ));
        }
        if kind.ddl && kind.dml {
            return Err(SqlError::Denied(
                "a statement may not mix DDL and DML".into(),
            ));
        }
        if kind.create_table && kind.select {
            return Err(SqlError::Denied(
                "CREATE TABLE ... AS SELECT is not allowed".into(),
            ));
        }
        let columns: Vec<String> = stmt.column_names().map(|s| s.to_string()).collect();
        // SQLite falls back to random suffixes when more than a few result
        // columns share a name. Detect it by preparing again.
        if columns.iter().any(|c| {
            c.rsplit_once(':')
                .is_some_and(|(_, d)| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        }) {
            let again: Vec<String> = match self.conn.prepare(sql) {
                Ok(s2) => s2.column_names().map(|s| s.to_string()).collect(),
                Err(e) => return Err(sql_err(e, &self.shared)),
            };
            if again != columns {
                return Err(SqlError::Denied(
                    "ambiguous duplicate column names; give each column a unique alias".into(),
                ));
            }
        }
        lock(&self.shared).host = true;
        if let Err(e) = self.host_batch("SAVEPOINT kronik_stmt") {
            return Err(SqlError::Syntax(e.to_string()));
        }
        lock(&self.shared).host = false;

        let mut values = Vec::new();
        let result: Result<(), rusqlite::Error> = (|| {
            let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                let mut out = Vec::with_capacity(columns.len());
                for i in 0..columns.len() {
                    out.push(match row.get_ref(i)? {
                        ValueRef::Null => Value::Null,
                        ValueRef::Integer(v) => Value::Integer(v),
                        ValueRef::Real(v) => Value::Real(v),
                        ValueRef::Text(t) => Value::Text(String::from_utf8_lossy(t).into_owned()),
                        ValueRef::Blob(b) => Value::Blob(b.to_vec()),
                    });
                }
                values.push(out);
            }
            Ok(())
        })();
        self.steps += stmt.get_status(StatementStatus::VmStep) as u64;
        drop(stmt);
        let changed = self.conn.changes();
        let rowid_max = std::mem::take(&mut lock(&self.shared).rowid_max);
        lock(&self.shared).host = true;
        let outcome = match result {
            Err(e) => Err(sql_err(e, &self.shared)),
            Ok(()) if rowid_max => Err(SqlError::Denied(
                "rowid 9223372036854775807 may not be stored".into(),
            )),
            Ok(()) => Ok(()),
        };
        if self.conn.is_autocommit() {
            // No savepoints left to release or roll back.
            self.poisoned = true;
            self.session = None;
            return Err(outcome.err().unwrap_or(SqlError::Denied(
                "the turn's SQL transaction was rolled back".into(),
            )));
        }
        let end = if outcome.is_err() {
            "ROLLBACK TO kronik_stmt; RELEASE kronik_stmt"
        } else {
            "RELEASE kronik_stmt"
        };
        if let Err(e) = self.host_batch(end) {
            return Err(SqlError::Syntax(e.to_string()));
        }
        outcome?;
        if kind.ddl {
            self.ddl.push(sql.to_string());
        } else if kind.dml {
            lock(&self.shared).dml_seen = true;
        }
        Ok((Rows { columns, values }, if kind.dml { changed } else { 0 }))
    }

    fn subject_col(&mut self, table: &str) -> rusqlite::Result<Option<usize>> {
        if let Some(c) = self.subject_cols.get(table) {
            return Ok(*c);
        }
        lock(&self.shared).host = true;
        let mut st = self
            .conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
        let names: Vec<String> = st
            .query_map([table], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let pk_rowid = !self.has_explicit_pk(table)?;
        let col = names
            .iter()
            .position(|n| is_subject_column(n))
            .map(|i| i + usize::from(pk_rowid));
        self.subject_cols.insert(table.to_string(), col);
        Ok(col)
    }

    fn has_explicit_pk(&self, table: &str) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info(?1) WHERE pk > 0",
                [table],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
    }

    /// Ends the turn: capture and split the changeset, roll the savepoint
    /// back. With `commit = false` (failed turn) everything is discarded.
    pub fn end_turn(&mut self, commit: bool) -> Result<TurnSql, String> {
        let res = self.end_turn_inner(commit);
        lock(&self.shared).host = true;
        let unlimit = self
            .conn
            .pragma_update(None, "max_page_count", UNLIMITED_PAGES)
            .map_err(|e| e.to_string());
        let erased = self.run_deferred_erasures();
        self.checkpoint_pending_erasure();
        let t = res?;
        if commit {
            self.note_captured_scrub(&t.changesets);
        } else {
            self.pending_scrub = None;
        }
        unlimit?;
        erased?;
        Ok(t)
    }

    /// The erasures applied while the turn that just ended was open.
    fn run_deferred_erasures(&mut self) -> Result<(), String> {
        for (subject, lsn) in std::mem::take(&mut self.deferred_erasures) {
            self.erase_subject(&subject, lsn)?;
        }
        Ok(())
    }

    /// Replaces exact occurrences of each secret with `[secret:<name>]`
    /// inside the turn, so the captured changeset and the applied database
    /// do not hold the value (#37, #198).
    ///
    /// A turn that wrote nothing does not run `instr`. The first write that
    /// presents a secret value scans every user cell once; that scan is part
    /// of this turn's changeset. A later turn replaces the secret only in
    /// the rows it wrote. A blob cell stays a blob. A value that is not
    /// UTF-8 can only be in a blob. Values shorter than 4 bytes are skipped.
    /// Returns the number of changed cells.
    pub fn scrub<N: AsRef<str>, V: AsRef<[u8]>>(
        &mut self,
        secrets: &[(N, V)],
    ) -> Result<u64, String> {
        #[cfg(test)]
        {
            self.last_scrub_fullscan_steps = 0;
        }
        if self.session.is_none() || self.poisoned {
            return Ok(0);
        }
        let secrets: Vec<(&str, &[u8])> = secrets
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
            .filter(|(_, value)| value.len() >= 4)
            .collect();
        if secrets.is_empty() {
            return Ok(0);
        }
        lock(&self.shared).host = true;
        let Some(session) = self.session.as_ref() else {
            return Ok(0);
        };
        let cs = session.changeset().map_err(|e| e.to_string())?;
        if cs.is_empty() {
            return Ok(0);
        }
        let changes = ffi::changes(&cs).map_err(|e| e.to_string())?;
        let (unseen, seen): (Vec<_>, Vec<_>) = secrets
            .iter()
            .copied()
            .partition(|(name, value)| !self.seen_secrets.contains(&secret_id(name, value)));
        let mut changed = 0u64;
        if !unseen.is_empty() {
            changed += self.scrub_tables(&unseen)?;
            self.pending_scrub = Some(PendingScrub {
                secrets: unseen
                    .iter()
                    .map(|(name, value)| secret_id(name, value))
                    .collect(),
                cs_hash: None,
            });
        }
        if !seen.is_empty() {
            changed += self.scrub_written(&changes, &seen)?;
        }
        Ok(changed)
    }

    fn note_captured_scrub(&mut self, changesets: &[(Option<String>, Vec<u8>)]) {
        if changesets.is_empty() {
            self.pending_scrub = None;
            return;
        }
        if let Some(pending) = &mut self.pending_scrub {
            pending.cs_hash = Some(changeset_hash(changesets));
        }
    }

    fn matching_pending(
        &self,
        changesets: &[(Option<String>, Vec<u8>)],
    ) -> Option<Vec<(String, [u8; 32])>> {
        let pending = self.pending_scrub.as_ref()?;
        let expected = pending.cs_hash?;
        (expected == changeset_hash(changesets)).then(|| pending.secrets.clone())
    }

    fn write_scrubbed(&self, secrets: &[(String, [u8; 32])]) -> Result<(), String> {
        lock(&self.shared).host = true;
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS _kronik_scrubbed (
                    name TEXT NOT NULL,
                    value_hash BLOB NOT NULL,
                    PRIMARY KEY (name, value_hash))",
            )
            .map_err(|e| e.to_string())?;
        for (name, hash) in secrets {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO _kronik_scrubbed (name, value_hash) VALUES (?1, ?2)",
                    rusqlite::params![name, hash.as_slice()],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn scrub_tables(&mut self, secrets: &[(&str, &[u8])]) -> Result<u64, String> {
        let tables = self.user_tables()?;
        let mut changed = 0u64;
        for table in &tables {
            changed += self.scrub_one_table(table, secrets)?;
        }
        Ok(changed)
    }

    fn scrub_written(
        &mut self,
        changes: &[Change],
        secrets: &[(&str, &[u8])],
    ) -> Result<u64, String> {
        let mut changed = 0u64;
        for change in changes {
            if change.op == Op::Delete {
                continue;
            }
            match self.row_key(change)? {
                Some(key) => changed += self.scrub_row(&change.table, &key, secrets)?,
                // No key to name the row: scan that table, not the others.
                None => changed += self.scrub_one_table(&change.table, secrets)?,
            }
        }
        Ok(changed)
    }

    fn scrub_one_table(&mut self, table: &str, secrets: &[(&str, &[u8])]) -> Result<u64, String> {
        let cols = self.table_columns(table)?;
        let mut changed = 0u64;
        for col in &cols {
            changed += self.scrub_column(table, col, secrets, "", &[])?;
        }
        Ok(changed)
    }

    fn scrub_row(
        &mut self,
        table: &str,
        key: &[(String, Value)],
        secrets: &[(&str, &[u8])],
    ) -> Result<u64, String> {
        let cols = self.table_columns(table)?;
        let pred = key
            .iter()
            .enumerate()
            .map(|(i, (col, _))| format!("{} = ?{}", quote_ident(col), i + 3))
            .collect::<Vec<_>>()
            .join(" AND ");
        let extra = format!("{pred} AND ");
        let params: Vec<Value> = key.iter().map(|(_, value)| value.clone()).collect();
        let mut changed = 0u64;
        for col in &cols {
            changed += self.scrub_column(table, col, secrets, &extra, &params)?;
        }
        Ok(changed)
    }

    fn scrub_column(
        &mut self,
        table: &str,
        col: &str,
        secrets: &[(&str, &[u8])],
        extra_where: &str,
        extra: &[Value],
    ) -> Result<u64, String> {
        let table = quote_ident(table);
        let col = quote_ident(col);
        let mut changed = 0u64;
        for (name, value) in secrets {
            let marker = format!("[secret:{name}]");
            if let Ok(text) = std::str::from_utf8(value) {
                let sql = format!(
                    "UPDATE {table} SET {col} = replace({col}, ?1, ?2) \
                     WHERE {extra_where}typeof({col}) = 'text' AND instr({col}, ?1) > 0"
                );
                let mut params = vec![Value::Text(text.to_owned()), Value::Text(marker.clone())];
                params.extend(extra.iter().cloned());
                changed += self.exec_scrub(&sql, &params)?;
            }
            // A blob needle makes instr() compare bytes. The host's replace
            // answers a blob, byte for byte.
            let sql = format!(
                "UPDATE {table} SET {col} = {SCRUB_REPLACE}({col}, ?1, ?2) \
                 WHERE {extra_where}typeof({col}) = 'blob' AND instr({col}, ?1) > 0"
            );
            let mut params = vec![Value::Blob(value.to_vec()), Value::Text(marker)];
            params.extend(extra.iter().cloned());
            changed += self.exec_scrub(&sql, &params)?;
        }
        Ok(changed)
    }

    fn exec_scrub(&mut self, sql: &str, params: &[Value]) -> Result<u64, String> {
        lock(&self.shared).host = true;
        let mut stmt = self.conn.prepare(sql).map_err(|e| e.to_string())?;
        let n = stmt
            .execute(rusqlite::params_from_iter(params.iter()))
            .map_err(|e| e.to_string())? as u64;
        #[cfg(test)]
        {
            self.last_scrub_fullscan_steps = self.last_scrub_fullscan_steps.saturating_add(
                u64::try_from(stmt.get_status(StatementStatus::FullscanStep)).unwrap_or(0),
            );
        }
        Ok(n)
    }

    fn user_tables(&self) -> Result<Vec<String>, String> {
        lock(&self.shared).host = true;
        user_tables(&self.conn).map_err(|e| e.to_string())
    }

    fn table_columns(&self, table: &str) -> Result<Vec<String>, String> {
        lock(&self.shared).host = true;
        self.conn
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
            .and_then(|mut st| st.query_map([table], |r| r.get(0))?.collect())
            .map_err(|e| e.to_string())
    }

    /// Primary key of a live row the session changed, as it is now.
    fn row_key(&self, change: &Change) -> Result<Option<Vec<(String, Value)>>, String> {
        if change.op == Op::Delete {
            return Ok(None);
        }
        let rowid_table = !self
            .has_explicit_pk(&change.table)
            .map_err(|e| e.to_string())?;
        let names = self.table_columns(&change.table)?;
        let mut key = Vec::new();
        for (index, is_pk) in change.pk.iter().enumerate() {
            if !is_pk {
                continue;
            }
            let col = if rowid_table {
                if index == 0 {
                    "rowid".to_string()
                } else {
                    names.get(index - 1).cloned().ok_or_else(|| {
                        format!("changeset column {index} of {} has no name", change.table)
                    })?
                }
            } else {
                names.get(index).cloned().ok_or_else(|| {
                    format!("changeset column {index} of {} has no name", change.table)
                })?
            };
            let Some(value) = change
                .new
                .get(index)
                .cloned()
                .flatten()
                .or_else(|| change.old.get(index).cloned().flatten())
            else {
                return Ok(None);
            };
            key.push((col, super::value_of(value)));
        }
        Ok((!key.is_empty()).then_some(key))
    }

    fn end_turn_inner(&mut self, commit: bool) -> Result<TurnSql, String> {
        if self.poisoned {
            self.session = None;
            self.ddl.clear();
            return if commit {
                Err("the turn's SQL transaction was rolled back by SQLite".into())
            } else {
                Ok(TurnSql::default())
            };
        }
        let captured = if commit {
            self.capture()
        } else {
            Ok((Vec::new(), Vec::new()))
        };
        self.session = None;
        // Always roll back: the changeset (if any) is applied separately.
        self.host_batch("ROLLBACK TO kronik_turn; RELEASE kronik_turn")
            .map_err(|e| e.to_string())?;
        let (changesets, whole) = captured?;
        Ok(TurnSql {
            ddl: std::mem::take(&mut self.ddl),
            changesets,
            vm_steps: self.steps,
            whole,
        })
    }

    /// Captures the turn's changeset and splits it per subject.
    #[allow(clippy::type_complexity)]
    fn capture(&mut self) -> Result<(Vec<(Option<String>, Vec<u8>)>, Vec<u8>), String> {
        let cs = match &self.session {
            Some(s) => s.changeset().map_err(|e| e.to_string())?,
            None => return Ok((Vec::new(), Vec::new())),
        };
        if cs.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let tables = ffi::tables(&cs).map_err(|e| e.to_string())?;
        // A turn with a default subject may only write tables that have a
        // `_subject` column (ADR 0005 §6, option B). A turn without a
        // subject may still write anywhere.
        if self.default_subject.is_some() {
            let mut missing = Vec::new();
            for table in &tables {
                if self
                    .subject_col(table)
                    .map_err(|e| e.to_string())?
                    .is_none()
                {
                    missing.push(table.clone());
                }
            }
            if !missing.is_empty() {
                return Err(format!(
                    "subjects/table-without-subject: {} has no _subject column",
                    missing.join(", ")
                ));
            }
        }
        // Fast path: no changed table has a `_subject` column, so the whole
        // changeset belongs to the turn's default subject.
        let mut any_subject_col = false;
        for table in &tables {
            any_subject_col |= self
                .subject_col(table)
                .map_err(|e| e.to_string())?
                .is_some();
        }
        if !any_subject_col {
            return Ok((vec![(self.default_subject.clone(), cs.clone())], cs));
        }
        let decoded = ffi::changes(&cs).map_err(|e| e.to_string())?;
        let mut subjects = Vec::with_capacity(decoded.len());
        for c in &decoded {
            subjects.push(self.subject_of(c)?);
        }
        let mut next = subjects.into_iter();
        let split = ffi::split(&cs, |_c: &Change| {
            next.next()
                .ok_or_else(|| "changeset changed while splitting".to_string())
        })?;
        Ok((split.into_iter().collect(), cs))
    }

    /// Replaces text and blob cells of subject-tagged changesets. `_subject`,
    /// any ASCII case, is left as recorded: its index comes from this
    /// database after the turn's DDL, not from which cell equals the subject
    /// id. A cell that does equal the id is rewritten.
    fn rewrite_subject_changesets(
        &mut self,
        changesets: &[(Option<String>, Vec<u8>)],
        rewrite: CellRewrite<'_>,
    ) -> Result<LoggedChangesets, String> {
        let mut out = Vec::with_capacity(changesets.len());
        for (subject, cs) in changesets {
            let Some(subject) = subject else {
                out.push((None, cs.clone()));
                continue;
            };
            if cs.is_empty() {
                out.push((Some(subject.clone()), Vec::new()));
                continue;
            }
            let changes = ffi::changes(cs).map_err(|e| e.to_string())?;
            let mut skip = BTreeSet::new();
            let mut seen = BTreeSet::new();
            for change in &changes {
                if !seen.insert(change.table.clone()) {
                    continue;
                }
                if let Some(index) = self.subject_col(&change.table).map_err(|e| e.to_string())? {
                    skip.insert((change.table.clone(), index));
                }
            }
            let bytes = super::pseudonymize_changeset(cs, &skip, |value| rewrite(subject, value))?;
            out.push((Some(subject.clone()), bytes));
        }
        Ok(out)
    }

    /// Applies a turn's SQL (DDL, then the changesets) and advances
    /// `applied_lsn`, atomically. Subjects in `erased` are skipped: their
    /// changesets are unreadable after erasure. The rest are combined into
    /// one apply, so a foreign key that crosses subjects is checked after
    /// every change (ADR 0160).
    pub fn apply(
        &mut self,
        t: &TurnSql,
        lsn: u64,
        erased: &BTreeSet<String>,
    ) -> Result<(), String> {
        self.apply_inner(t, lsn, erased, None)
    }

    /// [`Self::apply`] for a `--no-pii` fork. Subject-tagged changesets are
    /// pseudonymized after this turn's DDL, using this database's schema to
    /// find `_subject`.
    pub(crate) fn apply_rewriting(
        &mut self,
        t: &TurnSql,
        lsn: u64,
        erased: &BTreeSet<String>,
        rewrite: CellRewrite<'_>,
    ) -> Result<(), String> {
        self.apply_inner(t, lsn, erased, Some(rewrite))
    }

    fn apply_inner(
        &mut self,
        t: &TurnSql,
        lsn: u64,
        erased: &BTreeSet<String>,
        rewrite: Option<CellRewrite<'_>>,
    ) -> Result<(), String> {
        // A savepoint, not BEGIN: applies nest inside an isolated-replay
        // overlay transaction that is rolled back afterwards.
        self.host_batch("SAVEPOINT kronik_apply")
            .map_err(|e| e.to_string())?;
        // Trigger effects are already in the changeset: applying must not
        // fire triggers again. Toggling the flag expires every prepared
        // statement, so only do it when the schema has (or may get) triggers.
        use rusqlite::config::DbConfig;
        let schema_triggers = match self.has_triggers {
            Some(v) => v,
            None => {
                let v: bool = self
                    .conn
                    .query_row(
                        "SELECT count(*) > 0 FROM sqlite_schema WHERE type = 'trigger'",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                self.has_triggers = Some(v);
                v
            }
        };
        let toggle = schema_triggers || !t.ddl.is_empty();
        if toggle {
            self.conn
                .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
                .map_err(|e| e.to_string())?;
        }
        let pending = if erased.is_empty() {
            self.matching_pending(&t.changesets)
        } else {
            None
        };
        let r = (|| {
            for ddl in &t.ddl {
                self.conn
                    .execute_batch(ddl)
                    .map_err(|e| format!("DDL replay: {e}"))?;
            }
            if !t.ddl.is_empty() {
                lock(&self.shared).host = true;
                ensure_subject_indexes(&self.conn)?;
                // The lookup below must see columns this DDL added.
                self.subject_cols.clear();
            }
            let rewritten = match rewrite {
                Some(rewrite) => Some(self.rewrite_subject_changesets(&t.changesets, rewrite)?),
                None => None,
            };
            let changesets = rewritten.as_deref().unwrap_or(t.changesets.as_slice());
            // `whole` is the unsplit changeset tests set. A fork rewrite uses
            // the per-subject bytes, which are what the log holds.
            if rewrite.is_none() && erased.is_empty() && !t.whole.is_empty() {
                ffi::apply(&self.conn, &t.whole)?;
            } else {
                // One apply: the foreign-key check runs after every subject.
                // The log still holds the per-subject bytes (ADR 0160).
                let parts: Vec<&[u8]> = changesets
                    .iter()
                    .filter(|(subject, cs)| {
                        !cs.is_empty() && !subject.as_ref().is_some_and(|s| erased.contains(s))
                    })
                    .map(|(_, cs)| cs.as_slice())
                    .collect();
                match parts.as_slice() {
                    [] => {}
                    [one] => ffi::apply(&self.conn, one)?,
                    many => ffi::apply(&self.conn, &ffi::combine(many)?)?,
                }
            }
            self.conn
                .prepare_cached("UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn'")
                .and_then(|mut st| st.execute([lsn as i64]))
                .map_err(|e| e.to_string())?;
            if let Some(secrets) = &pending {
                self.write_scrubbed(secrets)?;
            }
            Ok(())
        })();
        if toggle
            && let Err(e) = self
                .conn
                .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
        {
            return Err(e.to_string());
        }
        if !t.ddl.is_empty() {
            self.has_triggers = None;
        }
        let end = if r.is_ok() {
            "RELEASE kronik_apply"
        } else {
            "ROLLBACK TO kronik_apply; RELEASE kronik_apply"
        };
        self.host_batch(end).map_err(|e| e.to_string())?;
        if !t.ddl.is_empty() {
            self.subject_cols.clear();
        }
        if r.is_ok()
            && let Some(secrets) = pending
        {
            self.seen_secrets.extend(secrets);
            self.pending_scrub = None;
        }
        r
    }

    /// Erasure turn for privacy mode: physically deletes the subject's rows
    /// from every table with a `_subject` column, in any ASCII case.
    /// Recorded in the log as an operation, not as a changeset (whose old
    /// values would be the erased data itself).
    ///
    /// Tables without `_subject` are untouched here. A turn with a subject
    /// cannot write them (`subjects/table-without-subject`); rows written
    /// before that decision, and rows whose `_subject` is NULL, belong to
    /// nobody. See [`rows_without_subject_column`].
    ///
    /// While a turn of the actor has its savepoint open, the erasure waits
    /// for the turn to end and runs right after its savepoint is rolled
    /// back: run inside it, the turn's end would roll the deletes back with
    /// it, and its session would record them as the turn's own changes.
    /// Until then the database's applied LSN stays below `lsn`, so a stop
    /// in between replays the erasure.
    pub fn erase_subject(&mut self, subject: &str, lsn: u64) -> Result<u64, String> {
        let (n, checkpoint) = self.erase_subject_at(subject, lsn)?;
        if checkpoint {
            self.checkpoint_erasure();
        }
        Ok(n)
    }

    /// The deletes of [`erase_subject`] without the WAL checkpoint.
    /// `checkpoint` is true when the deletes ran and the connection is idle,
    /// so the caller can truncate the WAL after it releases the apply lock.
    ///
    /// A parent deleted before its child fails an immediate foreign-key
    /// check. Checks are deferred until every delete of this subject has
    /// run, then the savepoint is released only if they pass. A row of
    /// another subject that references a row this would delete is refused
    /// before any delete: `ON DELETE CASCADE` or `SET NULL` would change
    /// that row, and turning foreign keys off would leave it dangling.
    pub(crate) fn erase_subject_at(
        &mut self,
        subject: &str,
        lsn: u64,
    ) -> Result<(u64, bool), String> {
        if self.session.is_some() {
            self.deferred_erasures.push((subject.to_owned(), lsn));
            return Ok((0, false));
        }
        lock(&self.shared).host = true;
        if let Some(why) = other_subject_reference(&self.conn, subject)? {
            return Err(erasure_constraint(&why));
        }
        let tables = tables_with_subject_column(&self.conn)?;
        self.host_batch("SAVEPOINT kronik_apply")
            .map_err(|e| e.to_string())?;
        let deleted: Result<u64, String> = (|| {
            // Inside the savepoint: the pragma resets on commit or rollback.
            self.conn
                .pragma_update(None, "defer_foreign_keys", "ON")
                .map_err(|e| e.to_string())?;
            // Nested RELEASE does not check; a violation already present is not this erasure's.
            let before = foreign_key_violations(&self.conn)?;
            let mut n = 0u64;
            for t in &tables {
                n += self
                    .conn
                    .execute(&subject_delete_sql(t), [subject])
                    .map_err(|e| e.to_string())? as u64;
            }
            n += rows_without_subject_column(&self.conn, subject)?;
            self.conn
                .execute(
                    "UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn'",
                    [lsn as i64],
                )
                .map_err(|e| e.to_string())?;
            if foreign_key_violations(&self.conn)?
                .difference(&before)
                .next()
                .is_some()
            {
                return Err(erasure_constraint("FOREIGN KEY constraint failed"));
            }
            Ok(n)
        })();
        let closed = self.finish_erasure_savepoint(deleted.is_ok());
        match (deleted, closed) {
            (Ok(n), Ok(())) => Ok((n, self.conn.is_autocommit())),
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Err(close)) => Err(format!("{e}; savepoint: {close}")),
        }
    }

    /// Rolls `kronik_apply` back when `release` is false, or when releasing
    /// it fails, so a failed statement does not leave the savepoint open.
    fn finish_erasure_savepoint(&self, release: bool) -> Result<(), String> {
        if !release {
            return self
                .host_batch("ROLLBACK TO kronik_apply; RELEASE kronik_apply")
                .map_err(|e| e.to_string());
        }
        if let Err(e) = self.host_batch("RELEASE kronik_apply") {
            self.host_batch("ROLLBACK TO kronik_apply; RELEASE kronik_apply")
                .map_err(|rb| rb.to_string())?;
            let msg = e.to_string();
            if msg.contains("FOREIGN KEY") {
                return Err(erasure_constraint(&msg));
            }
            return Err(msg);
        }
        Ok(())
    }

    /// Why erasing `subject` would change or dangle a row that is not
    /// theirs. `None` when every referencing row is also theirs.
    pub(crate) fn erasure_blocked_by(&self, subject: &str) -> Result<Option<String>, String> {
        lock(&self.shared).host = true;
        other_subject_reference(&self.conn, subject)
    }

    /// H11: truncate the WAL after an erasure. A caller that holds the apply
    /// lock must call this after releasing it. If a turn has the connection,
    /// the checkpoint waits for [`SqlActor::end_turn`].
    pub(crate) fn checkpoint_erasure(&mut self) {
        if !self.conn.is_autocommit() {
            self.erasure_checkpoint = true;
            return;
        }
        self.erasure_checkpoint = false;
        #[cfg(test)]
        {
            assert!(
                !crate::apply_lock_held(),
                "actor WAL checkpoint ran under the apply lock"
            );
            crate::ACTOR_ERASURE_CHECKPOINTS.with(|c| c.set(c.get() + 1));
        }
        // The WAL still holds the pages from before the deletes (H11).
        crate::db::checkpoint_truncate(&self.conn, "actor database");
    }

    fn checkpoint_pending_erasure(&mut self) {
        if self.erasure_checkpoint {
            self.checkpoint_erasure();
        }
    }

    /// Whether a guest table has no `_subject` column (any ASCII case). A
    /// subject's erasure leaves such a table's rows, which a turn with a
    /// subject could write before ADR 0005 §6 option B refused it.
    pub fn has_table_without_subject(&self) -> Result<bool, String> {
        lock(&self.shared).host = true;
        let sql = format!(
            "SELECT count(*) > 0 FROM sqlite_schema m WHERE m.type = 'table' \
             AND m.name NOT LIKE '\\_kronik%' ESCAPE '\\' AND m.name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
             AND NOT EXISTS (SELECT 1 FROM pragma_table_info(m.name) c WHERE {SUBJECT_COL_EQ})"
        );
        self.conn
            .query_row(&sql, [], |r| r.get(0))
            .map_err(|e| e.to_string())
    }

    /// Replaces text and blob cells of rows tagged with `_subject` (any
    /// ASCII case of that name). Integer and real values, and the subject
    /// column itself, are left as they are. A `--no-pii` fork does this to a
    /// snapshot it continues, with the same function it uses on changesets,
    /// so a later UPDATE still matches and the guest cannot read the plaintext.
    pub fn pseudonymize_subject_cells(
        &mut self,
        mut rewrite: impl FnMut(&str, &[u8]) -> Vec<u8>,
    ) -> Result<(), String> {
        lock(&self.shared).host = true;
        let tables = tables_with_subject_column(&self.conn)?;
        if tables.is_empty() {
            return Ok(());
        }
        use rusqlite::config::DbConfig;
        self.conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .map_err(|e| e.to_string())?;
        self.conn
            .pragma_update(None, "foreign_keys", "OFF")
            .map_err(|e| e.to_string())?;
        self.host_batch("SAVEPOINT kronik_pii")
            .map_err(|e| e.to_string())?;
        let result = (|| {
            for table in &tables {
                rewrite_subject_table(&self.conn, table, &mut rewrite)?;
            }
            Ok(())
        })();
        let _ = self
            .conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true);
        let _ = self.conn.pragma_update(None, "foreign_keys", "ON");
        let end = if result.is_ok() {
            "RELEASE kronik_pii"
        } else {
            "ROLLBACK TO kronik_pii; RELEASE kronik_pii"
        };
        self.host_batch(end).map_err(|e| e.to_string())?;
        result
    }

    /// Sets the turn's default subject for the following statements (the
    /// guest called `privacy.set-subject`). Rows of tables without
    /// `_subject` are attributed to the subject at the end of the turn.
    pub fn set_subject(&mut self, subject: Option<&str>) {
        if self.default_subject.as_deref() != subject {
            self.default_subject = subject.map(str::to_owned);
            lock(&self.shared).subject = self.default_subject.clone();
        }
    }

    /// Canonical hash: schema plus every row in primary-key order (rowid
    /// order, rowid included, for tables without one), type-tagged.
    pub fn canonical_hash(&self) -> rusqlite::Result<String> {
        canonical_hash(&self.conn, &self.shared)
    }

    /// Starts an overlay on this database (isolated replay).
    pub fn overlay_begin(&mut self) -> Result<(), String> {
        self.host_batch("SAVEPOINT kronik_overlay")
            .map_err(|e| e.to_string())
    }

    /// Discards everything since `overlay_begin`.
    pub fn overlay_rollback(&mut self) -> Result<(), String> {
        self.abort_turn();
        self.host_batch("ROLLBACK TO kronik_overlay; RELEASE kronik_overlay")
            .map_err(|e| e.to_string())?;
        self.subject_cols.clear();
        self.has_triggers = None;
        Ok(())
    }

    /// Rolls back a turn in progress, as closing the connection would (the
    /// simulator's crash of a node whose databases outlive it).
    pub fn abort_turn(&mut self) {
        if self.session.take().is_some() || !self.conn.is_autocommit() {
            let _ = self.host_batch("ROLLBACK TO kronik_turn; RELEASE kronik_turn");
        }
        self.ddl.clear();
        self.poisoned = false;
        // A failure leaves the applied LSN below the erasure's: the next
        // start replays it.
        let _ = self.run_deferred_erasures();
        self.checkpoint_pending_erasure();
    }

    /// Every user table's rows in canonical order: primary-key order, or
    /// rowid order with the rowid as first column (behavior diffs).
    pub fn canonical_rows(&self) -> rusqlite::Result<Vec<TableRows>> {
        lock(&self.shared).host = true;
        let names: Vec<String> = user_tables(&self.conn)?;
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let cols: Vec<(String, i64)> = self
                .conn
                .prepare("SELECT name, pk FROM pragma_table_info(?1) ORDER BY cid")?
                .query_map([&name], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            let mut pk: Vec<(i64, usize)> = cols
                .iter()
                .enumerate()
                .filter(|(_, (_, p))| *p > 0)
                .map(|(i, (_, p))| (*p, i))
                .collect();
            pk.sort();
            let quoted = quote_ident(&name);
            let (columns, pk, select): (Vec<String>, Vec<usize>, String) = if pk.is_empty() {
                let mut c = vec!["rowid".to_string()];
                c.extend(cols.iter().map(|(n, _)| n.clone()));
                (
                    c,
                    vec![0],
                    format!("SELECT rowid, * FROM {quoted} ORDER BY rowid"),
                )
            } else {
                let order = pk
                    .iter()
                    .map(|(_, i)| quote_ident(&cols[*i].0))
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    cols.iter().map(|(n, _)| n.clone()).collect(),
                    pk.iter().map(|(_, i)| *i).collect(),
                    format!("SELECT * FROM {quoted} ORDER BY {order}"),
                )
            };
            let mut st = self.conn.prepare(&select)?;
            let n = st.column_count();
            let rows = st
                .query_map([], |r| {
                    (0..n)
                        .map(|i| r.get::<_, Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out.push(TableRows {
                name,
                columns,
                pk,
                rows,
            });
        }
        Ok(out)
    }

    /// User tables and their row counts (for `actors inspect`).
    pub fn table_rows(&self) -> rusqlite::Result<Vec<(String, u64)>> {
        lock(&self.shared).host = true;
        let names: Vec<String> = user_tables(&self.conn)?;
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let rows: i64 = self.conn.query_row(
                &format!("SELECT count(*) FROM {}", quote_ident(&n)),
                [],
                |r| r.get(0),
            )?;
            out.push((n, rows as u64));
        }
        Ok(out)
    }

    pub fn set_host(&self) {
        lock(&self.shared).host = true;
    }

    pub(crate) fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Distinct non-empty `_subject` values. One scan on open, for databases
    /// written before the actor-subject index existed (#196).
    pub(crate) fn distinct_subjects(&mut self) -> Result<Vec<String>, String> {
        lock(&self.shared).host = true;
        let mut out = BTreeSet::new();
        for table in tables_with_subject_column(&self.conn)? {
            let sql = format!(
                "SELECT DISTINCT _subject FROM {} WHERE _subject IS NOT NULL",
                quote_ident(&table)
            );
            let mut st = self.conn.prepare(&sql).map_err(|e| e.to_string())?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            for row in rows {
                let subject = row.map_err(|e| e.to_string())?;
                if !subject.is_empty() {
                    out.insert(subject);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Forgets cached schema facts (after the database was replaced).
    pub fn reset_caches(&mut self) {
        self.subject_cols.clear();
        self.has_triggers = None;
    }
}

/// One table's rows in canonical order.
#[derive(Debug, Clone, PartialEq)]
pub struct TableRows {
    pub name: String,
    pub columns: Vec<String>,
    /// Indices of the primary-key columns (the rowid for tables without
    /// one).
    pub pk: Vec<usize>,
    pub rows: Vec<Vec<Value>>,
}

fn val_text(v: Option<Val>) -> Option<String> {
    match v {
        Some(Val::Text(s)) => Some(s),
        Some(Val::Null) | None => None,
        Some(other) => Some(format!("{other:?}")),
    }
}

pub(super) fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Rewrites text and blob cells of one `_subject` table. The row is matched
/// by rowid, or by its primary key when the table has none.
fn rewrite_subject_table(
    conn: &Connection,
    table: &str,
    rewrite: &mut impl FnMut(&str, &[u8]) -> Vec<u8>,
) -> Result<(), String> {
    let cols: Vec<(String, i64)> = conn
        .prepare("SELECT name, pk FROM pragma_table_info(?1) ORDER BY cid")
        .and_then(|mut st| {
            st.query_map([table], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        })
        .map_err(|e| e.to_string())?;
    let subject_at = cols
        .iter()
        .position(|(name, _)| is_subject_column(name))
        .ok_or_else(|| format!("{table} has no _subject column"))?;
    let without_rowid: bool = conn
        .query_row(
            "SELECT sql LIKE '%WITHOUT ROWID%' FROM sqlite_schema WHERE name = ?1",
            [table],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let quoted = quote_ident(table);
    let select = if without_rowid {
        format!("SELECT * FROM {quoted} WHERE _subject IS NOT NULL")
    } else {
        format!("SELECT rowid, * FROM {quoted} WHERE _subject IS NOT NULL")
    };
    let mut st = conn.prepare(&select).map_err(|e| e.to_string())?;
    let n = st.column_count();
    let rows = st
        .query_map([], |r| {
            (0..n)
                .map(|i| r.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    drop(st);
    let data_at = usize::from(!without_rowid);
    for row in rows {
        let Some(Value::Text(subject)) = row.get(data_at + subject_at) else {
            continue;
        };
        let mut sets = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        for (i, (name, _)) in cols.iter().enumerate() {
            if i == subject_at {
                continue;
            }
            let Some(value) = row.get(data_at + i) else {
                continue;
            };
            let rewritten = match value {
                Value::Text(text) => {
                    let bytes = rewrite(subject, text.as_bytes());
                    if bytes.as_slice() == text.as_bytes() {
                        continue;
                    }
                    match String::from_utf8(bytes) {
                        Ok(text) => Value::Text(text),
                        Err(err) => {
                            Value::Text(String::from_utf8_lossy(err.as_bytes()).into_owned())
                        }
                    }
                }
                Value::Blob(bytes) => {
                    let next = rewrite(subject, bytes);
                    if next == *bytes {
                        continue;
                    }
                    Value::Blob(next)
                }
                _ => continue,
            };
            sets.push(format!("{} = ?{}", quote_ident(name), params.len() + 1));
            params.push(rewritten);
        }
        if sets.is_empty() {
            continue;
        }
        let where_sql = if without_rowid {
            let mut pk: Vec<(i64, &str)> = cols
                .iter()
                .filter(|(_, pk)| *pk > 0)
                .map(|(name, pk)| (*pk, name.as_str()))
                .collect();
            pk.sort_by_key(|(n, _)| *n);
            if pk.is_empty() {
                return Err(format!("{table} has no primary key to rewrite"));
            }
            let mut parts = Vec::new();
            for (_, name) in pk {
                let idx = cols.iter().position(|(n, _)| n == name).unwrap_or(0);
                parts.push(format!("{} = ?{}", quote_ident(name), params.len() + 1));
                params.push(row.get(data_at + idx).cloned().unwrap_or(Value::Null));
            }
            parts.join(" AND ")
        } else {
            let rowid = row.first().cloned().unwrap_or(Value::Null);
            params.push(rowid);
            format!("rowid = ?{}", params.len())
        };
        conn.execute(
            &format!("UPDATE {quoted} SET {} WHERE {where_sql}", sets.join(", ")),
            rusqlite::params_from_iter(params.iter()),
        )
        .map_err(|e| format!("pseudonymize {table}: {e}"))?;
    }
    Ok(())
}

impl SqlActor {
    /// The subject a change belongs to: the row's `_subject` value when the
    /// table has that column, otherwise the turn's default subject. An
    /// UPDATE record carries only changed columns, so the (unchanged)
    /// `_subject` of an updated row is read from the database by key.
    fn subject_of(&mut self, c: &Change) -> Result<Option<String>, String> {
        let Some(i) = self.subject_col(&c.table).map_err(|e| e.to_string())? else {
            return Ok(self.default_subject.clone());
        };
        match c.op {
            Op::Insert => Ok(val_text(c.new.get(i).cloned().flatten())),
            Op::Delete => Ok(val_text(c.old.get(i).cloned().flatten())),
            Op::Update => {
                // A REPLACE, or a DELETE and INSERT of the same key, is
                // recorded as one UPDATE whose old values are one subject's
                // and new values another's: no changeset may hold both.
                if c.new.get(i).cloned().flatten().is_some() {
                    return Err(format!(
                        "subjects/move-detected: a change to {} moves a row to another \
                         _subject; delete the row in one turn and insert it in a later one",
                        c.table
                    ));
                }
                let rowid_table = !self.has_explicit_pk(&c.table).map_err(|e| e.to_string())?;
                let names: Vec<String> = self
                    .conn
                    .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
                    .and_then(|mut st| st.query_map([&c.table], |r| r.get(0))?.collect())
                    .map_err(|e| e.to_string())?;
                let mut conds = Vec::new();
                let mut params = Vec::new();
                for (k, is_pk) in c.pk.iter().enumerate() {
                    if !is_pk {
                        continue;
                    }
                    let col = if rowid_table {
                        if k == 0 {
                            "rowid".to_string()
                        } else {
                            names[k - 1].clone()
                        }
                    } else {
                        names[k].clone()
                    };
                    conds.push(format!("{} = ?{}", quote_ident(&col), params.len() + 1));
                    params.push(
                        c.old
                            .get(k)
                            .cloned()
                            .flatten()
                            .map(super::value_of)
                            .unwrap_or(Value::Null),
                    );
                }
                let sql = format!(
                    "SELECT _subject FROM {} WHERE {}",
                    quote_ident(&c.table),
                    conds.join(" AND ")
                );
                lock(&self.shared).host = true;
                let v: Option<String> = self
                    .conn
                    .query_row(&sql, rusqlite::params_from_iter(params.iter()), |r| {
                        r.get(0)
                    })
                    .map_err(|e| format!("subject lookup in {}: {e}", c.table))?;
                Ok(v)
            }
        }
    }
}

fn canonical_hash(conn: &Connection, shared: &Mutex<Shared>) -> rusqlite::Result<String> {
    lock(shared).host = true;
    canonical_hash_raw(conn)
}

pub fn canonical_hash_raw(conn: &Connection) -> rusqlite::Result<String> {
    let mut h = blake3::Hasher::new();
    let mut st = conn.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema \
         WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY type, name",
    )?;
    let schema: Vec<(String, String, String, Option<String>)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (ty, name, tbl, sql) in &schema {
        h.update(
            format!(
                "schema|{ty}|{name}|{tbl}|{}\n",
                sql.as_deref().unwrap_or("")
            )
            .as_bytes(),
        );
    }
    for (ty, name, _, _) in &schema {
        if ty != "table" {
            continue;
        }
        let mut pk: Vec<(i64, String)> = conn
            .prepare("SELECT pk, name FROM pragma_table_info(?1) WHERE pk > 0")?
            .query_map([name], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        pk.sort();
        let without_rowid: bool = conn.query_row(
            "SELECT sql LIKE '%WITHOUT ROWID%' FROM sqlite_schema WHERE name = ?1",
            [name],
            |r| r.get(0),
        )?;
        let (select, order) = if pk.is_empty() {
            (
                format!("SELECT rowid, * FROM {}", quote_ident(name)),
                "rowid".to_string(),
            )
        } else {
            let o = pk
                .iter()
                .map(|(_, c)| quote_ident(c))
                .collect::<Vec<_>>()
                .join(", ");
            (format!("SELECT * FROM {}", quote_ident(name)), o)
        };
        let _ = without_rowid;
        let mut st = conn.prepare(&format!("{select} ORDER BY {order}"))?;
        let n = st.column_count();
        let mut rows = st.query([])?;
        while let Some(row) = rows.next()? {
            h.update(format!("row|{name}|").as_bytes());
            for i in 0..n {
                match row.get_ref(i)? {
                    ValueRef::Null => h.update(b"N;"),
                    ValueRef::Integer(v) => h.update(format!("I{v};").as_bytes()),
                    ValueRef::Real(v) => h.update(format!("R{:016x};", v.to_bits()).as_bytes()),
                    ValueRef::Text(t) => {
                        h.update(format!("T{}:", t.len()).as_bytes());
                        h.update(t)
                    }
                    ValueRef::Blob(b) => {
                        h.update(format!("B{}:", b.len()).as_bytes());
                        h.update(b)
                    }
                };
            }
            h.update(b"\n");
        }
    }
    Ok(format!("b3:{}", &h.finalize().to_hex()[..16]))
}

/// The statement [`SqlActor::erase_subject_at`] runs. Tests explain it.
pub(crate) fn subject_delete_sql(table: &str) -> String {
    format!("DELETE FROM {} WHERE _subject = ?1", quote_ident(table))
}

/// Index `_subject` so that delete is a search (#196). A guest index that
/// already leads with the column is enough. The name starts with `_kronik`,
/// so it stays out of the canonical hash.
fn ensure_subject_indexes(conn: &Connection) -> Result<(), String> {
    for table in tables_with_subject_column(conn)? {
        if subject_indexed(conn, &table).map_err(|e| e.to_string())? {
            continue;
        }
        let name = subject_index_name(&table);
        conn.execute(
            &format!(
                "CREATE INDEX IF NOT EXISTS {} ON {}(_subject)",
                quote_ident(&name),
                quote_ident(&table)
            ),
            [],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn subject_indexed(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) > 0 FROM pragma_index_list(?1) i, pragma_index_info(i.name) c \
         WHERE c.seqno = 0 AND c.name = '_subject' COLLATE NOCASE",
        [table],
        |r| r.get(0),
    )
}

fn subject_index_name(table: &str) -> String {
    let hash = blake3::hash(table.as_bytes());
    format!("_kronik_subject_{}", &hash.to_hex()[..16])
}

fn tables_with_subject_column(conn: &Connection) -> Result<Vec<String>, String> {
    let sql = format!(
        "SELECT m.name FROM sqlite_schema m, pragma_table_info(m.name) c \
         WHERE m.type = 'table' AND {SUBJECT_COL_EQ} \
         AND m.name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY m.name"
    );
    let mut st = conn.prepare(&sql).map_err(|e| e.to_string())?;
    st.query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<_>>()
        .map_err(|e| e.to_string())
}

/// Rows in tables without a `_subject` column. A turn with a default
/// subject may not write those tables (`subjects/table-without-subject`),
/// so this stays a no-op: there is no owner to delete. Rows written before
/// that decision, and rows whose `_subject` is NULL, belong to nobody and
/// survive erasure. Erasure of rows that have a `_subject` value is the
/// `DELETE` in [`SqlActor::erase_subject`], not this function.
fn rows_without_subject_column(_conn: &Connection, _subject: &str) -> Result<u64, String> {
    Ok(0)
}

/// Prefix of an erasure error that is a foreign-key constraint, not a
/// corrupt database. The store maps it off `STORAGE_CORRUPT`.
pub(crate) fn erasure_constraint(why: &str) -> String {
    format!("constraint: {why}")
}

type FkViolation = (String, Option<i64>, String, i64);

fn foreign_key_violations(conn: &Connection) -> Result<BTreeSet<FkViolation>, String> {
    let mut st = conn
        .prepare("SELECT \"table\", rowid, parent, fkid FROM pragma_foreign_key_check")
        .map_err(|e| e.to_string())?;
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<_>>()
        .map_err(|e| e.to_string())
}

struct ForeignKey {
    parent: String,
    pairs: Vec<(String, String)>,
}

fn foreign_keys(conn: &Connection, child: &str) -> Result<Vec<ForeignKey>, String> {
    let mut st = conn
        .prepare(
            "SELECT id, \"table\", \"from\", \"to\" FROM pragma_foreign_key_list(?1) \
             ORDER BY id, seq",
        )
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([child], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut start = 0;
    while start < rows.len() {
        let id = rows[start].0;
        let mut end = start + 1;
        while end < rows.len() && rows[end].0 == id {
            end += 1;
        }
        let parent = rows[start].1.clone();
        let pairs = rows[start..end]
            .iter()
            .map(|(_, _, from, to)| (from.clone(), to.clone()))
            .collect();
        out.push(ForeignKey {
            parent: parent.clone(),
            pairs: resolve_parent_columns(conn, &parent, pairs)?,
        });
        start = end;
    }
    Ok(out)
}

/// `REFERENCES parent` stores a NULL parent column: the primary key, or rowid.
fn resolve_parent_columns(
    conn: &Connection,
    parent: &str,
    pairs: Vec<(String, Option<String>)>,
) -> Result<Vec<(String, String)>, String> {
    let keys = if pairs.iter().all(|(_, to)| to.is_some()) {
        Vec::new()
    } else {
        parent_key_columns(conn, parent)?
    };
    pairs
        .into_iter()
        .enumerate()
        .map(|(i, (from, to))| {
            let to = match to {
                Some(to) => to,
                None => keys
                    .get(i)
                    .cloned()
                    .ok_or_else(|| format!("foreign key to {parent} has no parent column {i}"))?,
            };
            Ok((from, to))
        })
        .collect()
}

fn parent_key_columns(conn: &Connection, parent: &str) -> Result<Vec<String>, String> {
    let mut st = conn
        .prepare("SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk")
        .map_err(|e| e.to_string())?;
    let cols = st
        .query_map([parent], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(|e| e.to_string())?;
    if cols.is_empty() {
        Ok(vec!["rowid".into()])
    } else {
        Ok(cols)
    }
}

fn user_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' \
         AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
         AND name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY name",
    )?;
    st.query_map([], |r| r.get(0))?.collect()
}

/// A row that is not `subject` references a row of `subject` that erasure
/// would delete. That includes a table with no `_subject` column: its rows
/// belong to nobody and are not deleted.
fn other_subject_reference(conn: &Connection, subject: &str) -> Result<Option<String>, String> {
    let parents = tables_with_subject_column(conn)?;
    if parents.is_empty() {
        return Ok(None);
    }
    let has = |name: &str| parents.iter().any(|t| t.eq_ignore_ascii_case(name));
    for child in user_tables(conn).map_err(|e| e.to_string())? {
        let child_has_subject = has(&child);
        for fk in foreign_keys(conn, &child)? {
            if !has(&fk.parent) || fk.pairs.is_empty() {
                continue;
            }
            if references_other(conn, subject, &child, child_has_subject, &fk)? {
                return Ok(Some(format!(
                    "a row that is not {subject} in {child} references {} of {subject}",
                    fk.parent
                )));
            }
        }
    }
    Ok(None)
}

fn references_other(
    conn: &Connection,
    subject: &str,
    child: &str,
    child_has_subject: bool,
    fk: &ForeignKey,
) -> Result<bool, String> {
    let on = fk
        .pairs
        .iter()
        .map(|(from, to)| format!("c.{} = p.{}", quote_ident(from), quote_ident(to)))
        .collect::<Vec<_>>()
        .join(" AND ");
    let child_filter = if child_has_subject {
        " AND (c._subject IS NULL OR c._subject != ?1)"
    } else {
        ""
    };
    let sql = format!(
        "SELECT 1 FROM {} AS c JOIN {} AS p ON {on} WHERE p._subject = ?1{child_filter} LIMIT 1",
        quote_ident(child),
        quote_ident(&fk.parent)
    );
    match conn.query_row(&sql, [subject], |_| Ok(())) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_valid_key_has_a_file_name_and_short_names_keep_theirs() {
        let root = std::path::Path::new("/data/sql");
        // As existing data directories have it.
        assert_eq!(
            actor_file(root, "notes/n0"),
            root.join("ec").join("notes~n0-ec100964.db")
        );
        let dir = tempfile::tempdir().unwrap();
        let opener = FileOpener {
            root: dir.path().to_path_buf(),
        };
        let longest = format!("notes/{}", "k".repeat(256));
        let name = actor_file(dir.path(), &longest);
        let len = name.file_name().unwrap().len();
        assert!(len + "-journal".len() <= 255, "{}", name.display());
        let conn = opener.open(&longest, "unix").unwrap();
        conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
            .unwrap();
        assert!(opener.exists(&longest));
        assert_ne!(actor_file(dir.path(), &format!("{longest}x")), name);
    }

    #[test]
    fn the_longest_whole_name_and_the_first_hashed_one_open() {
        let dir = tempfile::tempdir().unwrap();
        let opener = FileOpener {
            root: dir.path().to_path_buf(),
        };
        for (len, whole) in [(MAX_WHOLE_NAME, true), (MAX_WHOLE_NAME + 1, false)] {
            let actor = format!("notes/{}", "k".repeat(len - "notes/".len()));
            let name = actor_file(dir.path(), &actor);
            let name_len = name.file_name().unwrap().len();
            assert_eq!(name_len == len + "-12345678.db".len(), whole, "{len}");
            let conn = opener.open(&actor, "unix").unwrap();
            conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
                .unwrap();
        }
    }

    /// Issue #196: `DELETE WHERE _subject = ?` searches, including on a
    /// database created before the index and on a case-variant column.
    #[test]
    fn subject_delete_searches_instead_of_scanning() {
        let dir = tempfile::tempdir().unwrap();
        let opener = FileOpener {
            root: dir.path().to_path_buf(),
        };
        {
            let conn = opener.open("notes/old", "unix").unwrap();
            conn.execute_batch(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, _Subject TEXT);
                 INSERT INTO notes VALUES (1, 'user:1');",
            )
            .unwrap();
        }
        let actor = SqlActor::open(&opener, "notes/old").unwrap();
        let sql = subject_delete_sql("notes");
        crate::assert_search(&actor.conn, &sql, "user:1");
        let gone = actor.conn.execute(&sql, ["user:1"]).unwrap();
        assert_eq!(gone, 1);
    }
}
