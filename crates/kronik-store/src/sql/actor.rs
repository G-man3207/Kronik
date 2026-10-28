//! Per-actor SQL state: one SQLite database per actor, owned by the host.
//!
//! A turn runs the guest's statements inside `SAVEPOINT kronik_turn` with a
//! session recording every table. At the end of the turn the changeset is
//! captured and split per subject, the savepoint is rolled back, and the
//! changeset is applied (after the turn record is durable in the real
//! daemon), so production, recovery and replay build the database the same
//! way. DDL is recorded as text and replayed before the changeset.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng, SeedableRng};
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
    /// The kind's database size limit for this turn's writes (0: the
    /// pool's default). Applies and rebuilds are never limited.
    pub max_bytes: u64,
}

/// SQLite's largest `max_page_count`: no limit.
const UNLIMITED_PAGES: i64 = 4_294_967_294;

/// What a turn contributes to its turn record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TurnSql {
    /// DDL exactly as executed, in order (`SqlSchemaChange`).
    pub ddl: Vec<String>,
    /// One changeset per subject (`SqlChangeset`, one `Sealable` each).
    pub changesets: Vec<(Option<String>, Vec<u8>)>,
    /// VM steps executed by the guest's statements.
    pub vm_steps: u64,
    /// The unsplit changeset, used for the live apply (one
    /// `sqlite3changeset_apply` call). Not written to the log; rebuilds
    /// apply the per-subject changesets.
    pub whole: Vec<u8>,
}

/// Configuration of one actor database.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_bytes: u64,
    pub value_bytes: i32,
    pub track_rowid_tables: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 1 << 30,
            value_bytes: 1 << 20,
            track_rowid_tables: true,
        }
    }
}

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
];

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
    if s.host {
        return Authorization::Allow;
    }
    let deny = |s: &mut Shared, why: String| {
        if s.stmt.denied.is_none() {
            s.stmt.denied = Some(why);
        }
        Authorization::Deny
    };
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
                && column_name.eq_ignore_ascii_case("_subject")
            {
                return deny(
                    s,
                    "changing _subject is not allowed; delete the row and insert it again".into(),
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

/// One actor's SQL database. Field order matters: the session must be
/// dropped before the connection, and the connection before its VFS.
pub struct SqlActor {
    session: Option<ffi::Session>,
    pub conn: Connection,
    vfs: ffi::TimeVfs,
    shared: Arc<Mutex<Shared>>,
    limits: Limits,
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
}

fn lock(m: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    m.lock().unwrap_or_else(|e| e.into_inner())
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

impl SqlActor {
    pub fn open(opener: &dyn SqliteOpener, actor: &str, limits: Limits) -> rusqlite::Result<Self> {
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
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, limits.value_bytes)?;
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
        let max_len = limits.value_bytes as i64;
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
        Ok(Self {
            session: None,
            conn,
            vfs,
            shared,
            limits,
            ddl: Vec::new(),
            steps: 0,
            default_subject: None,
            subject_cols: BTreeMap::new(),
            poisoned: false,
            has_triggers: None,
            page_size: page_size.max(512) as u64,
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
        ffi::reset_last_insert_rowid(&self.conn);
        let max = if opts.max_bytes == 0 {
            self.limits.max_bytes
        } else {
            opts.max_bytes
        };
        self.conn
            .pragma_update(None, "max_page_count", (max / self.page_size).max(1) as i64)?;
        self.host_batch("SAVEPOINT kronik_turn")?;
        self.session = Some(ffi::Session::new(
            &self.conn,
            self.limits.track_rowid_tables,
        )?);
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
        let pk_rowid = self.limits.track_rowid_tables && !self.has_explicit_pk(table)?;
        let col = names
            .iter()
            .position(|n| n.eq_ignore_ascii_case("_subject"))
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
        let t = res?;
        unlimit?;
        Ok(t)
    }

    /// Replaces every exact occurrence of each secret value in the text
    /// columns of every user table with `[secret:<name>]`, inside the turn,
    /// so the turn's changeset never holds the value. Returns the number of
    /// changed cells.
    pub fn scrub(&mut self, secrets: &[(String, Vec<u8>)]) -> Result<u64, String> {
        if self.session.is_none() || self.poisoned {
            return Ok(0);
        }
        lock(&self.shared).host = true;
        let tables: Vec<String> = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
                 AND name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY name",
            )
            .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
            .map_err(|e| e.to_string())?;
        let mut changed = 0u64;
        for t in &tables {
            let cols: Vec<String> = self
                .conn
                .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
                .and_then(|mut st| st.query_map([t], |r| r.get(0))?.collect())
                .map_err(|e| e.to_string())?;
            for c in &cols {
                for (name, value) in secrets {
                    let Ok(v) = std::str::from_utf8(value) else {
                        continue;
                    };
                    if v.len() < 4 {
                        continue;
                    }
                    let q = format!(
                        "UPDATE \"{t}\" SET \"{c}\" = replace(\"{c}\", ?1, ?2) \
                         WHERE typeof(\"{c}\") = 'text' AND instr(\"{c}\", ?1) > 0",
                        t = t.replace('"', "\"\""),
                        c = c.replace('"', "\"\"")
                    );
                    changed += self
                        .conn
                        .execute(&q, rusqlite::params![v, format!("[secret:{name}]")])
                        .map_err(|e| e.to_string())? as u64;
                }
            }
        }
        Ok(changed)
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
        // Fast path: no changed table has a `_subject` column, so the whole
        // changeset belongs to the turn's default subject.
        let mut any_subject_col = false;
        for t in ffi::tables(&cs).map_err(|e| e.to_string())? {
            any_subject_col |= self.subject_col(&t).map_err(|e| e.to_string())?.is_some();
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

    /// Applies a turn's SQL (DDL, then each subject's changeset) and
    /// advances `applied_lsn`, atomically. Subjects in `erased` are skipped:
    /// their changesets are unreadable after erasure.
    pub fn apply(
        &mut self,
        t: &TurnSql,
        lsn: u64,
        erased: &BTreeSet<String>,
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
        let r = (|| {
            for ddl in &t.ddl {
                self.conn
                    .execute_batch(ddl)
                    .map_err(|e| format!("DDL replay: {e}"))?;
            }
            if erased.is_empty() && !t.whole.is_empty() {
                ffi::apply(&self.conn, &t.whole)?;
            }
            for (subject, cs) in t
                .changesets
                .iter()
                .filter(|_| !erased.is_empty() || t.whole.is_empty())
            {
                if subject.as_ref().is_some_and(|s| erased.contains(s)) {
                    continue;
                }
                ffi::apply(&self.conn, cs)?;
            }
            self.conn
                .prepare_cached("UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn'")
                .and_then(|mut st| st.execute([lsn as i64]))
                .map_err(|e| e.to_string())?;
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
        r
    }

    /// Erasure turn for privacy mode: physically deletes the subject's rows
    /// from every table with a `_subject` column. Recorded in the log as an
    /// operation, not as a changeset (whose old values would be the erased
    /// data itself).
    ///
    /// Tables without `_subject` are untouched here: see
    /// [`rows_without_subject_column`] (the open owner question, ADR 0005 §6,
    /// docs/design/m8-privacy.md §7).
    pub fn erase_subject(&mut self, subject: &str, lsn: u64) -> Result<u64, String> {
        lock(&self.shared).host = true;
        let tables: Vec<String> = {
            let mut st = self
                .conn
                .prepare(
                    "SELECT m.name FROM sqlite_schema m, pragma_table_info(m.name) c \
                     WHERE m.type = 'table' AND c.name = '_subject' AND m.name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY m.name",
                )
                .map_err(|e| e.to_string())?;
            st.query_map([], |r| r.get(0))
                .map_err(|e| e.to_string())?
                .collect::<rusqlite::Result<_>>()
                .map_err(|e| e.to_string())?
        };
        self.host_batch("SAVEPOINT kronik_apply")
            .map_err(|e| e.to_string())?;
        let mut n = 0;
        for t in &tables {
            n += self
                .conn
                .execute(
                    &format!("DELETE FROM \"{t}\" WHERE _subject = ?1"),
                    [subject],
                )
                .map_err(|e| e.to_string())? as u64;
        }
        n += rows_without_subject_column(&self.conn, subject)?;
        self.conn
            .execute(
                "UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn'",
                [lsn as i64],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute_batch("RELEASE kronik_apply")
            .map_err(|e| e.to_string())?;
        // The WAL still holds the pages from before the deletes (H11).
        if self.conn.is_autocommit() {
            crate::db::checkpoint_truncate(&self.conn, "actor database");
        }
        Ok(n)
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
    }

    /// Every user table's rows in canonical order: primary-key order, or
    /// rowid order with the rowid as first column (behavior diffs).
    pub fn canonical_rows(&self) -> rusqlite::Result<Vec<TableRows>> {
        lock(&self.shared).host = true;
        let names: Vec<String> = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
                 AND name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY name",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
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
            let quoted = name.replace('"', "\"\"");
            let (columns, pk, select): (Vec<String>, Vec<usize>, String) = if pk.is_empty() {
                let mut c = vec!["rowid".to_string()];
                c.extend(cols.iter().map(|(n, _)| n.clone()));
                (
                    c,
                    vec![0],
                    format!("SELECT rowid, * FROM \"{quoted}\" ORDER BY rowid"),
                )
            } else {
                let order = pk
                    .iter()
                    .map(|(_, i)| format!("\"{}\"", cols[*i].0.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    cols.iter().map(|(n, _)| n.clone()).collect(),
                    pk.iter().map(|(_, i)| *i).collect(),
                    format!("SELECT * FROM \"{quoted}\" ORDER BY {order}"),
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
        let names: Vec<String> = self
            .conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
                 AND name NOT LIKE '\\_kronik%' ESCAPE '\\' ORDER BY name",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out = Vec::with_capacity(names.len());
        for n in names {
            let rows: i64 = self.conn.query_row(
                &format!("SELECT count(*) FROM \"{}\"", n.replace('"', "\"\"")),
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

fn to_sql(v: &Val) -> Value {
    match v {
        Val::Null => Value::Null,
        Val::Int(i) => Value::Integer(*i),
        Val::Real(r) => Value::Real(*r),
        Val::Text(t) => Value::Text(t.clone()),
        Val::Blob(b) => Value::Blob(b.clone()),
    }
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
                if c.new.get(i).cloned().flatten().is_some() {
                    return Err(format!(
                        "a change to {} moves a row to another _subject",
                        c.table
                    ));
                }
                let rowid_table = self.limits.track_rowid_tables
                    && !self.has_explicit_pk(&c.table).map_err(|e| e.to_string())?;
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
                    conds.push(format!("\"{col}\" = ?{}", params.len() + 1));
                    params.push(
                        c.old
                            .get(k)
                            .cloned()
                            .flatten()
                            .map(|v| to_sql(&v))
                            .unwrap_or(Value::Null),
                    );
                }
                let sql = format!(
                    "SELECT _subject FROM \"{}\" WHERE {}",
                    c.table,
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
                format!("SELECT rowid, * FROM \"{name}\""),
                "rowid".to_string(),
            )
        } else {
            let o = pk
                .iter()
                .map(|(_, c)| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            (format!("SELECT * FROM \"{name}\""), o)
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

/// THE SEAM for the open owner question (docs/design/m8-privacy.md §7, ADR
/// 0005 §6): rows that a turn with a default subject wrote to a table
/// without a `_subject` column. Erasure deletes every row with `_subject =
/// subject` (common to both options); what happens to these rows depends on
/// the answer:
///
/// - Option A (such rows belong to the turn's default subject): the store
///   would keep a host-side row-owner table maintained at apply, and this
///   function would delete the rows it lists.
/// - Option B (ADR 0005's recommendation): such writes are refused at turn
///   time with `subjects/table-without-subject`, so there are no such rows
///   and this function stays a no-op.
///
/// Until the owner decides, it deletes nothing and returns 0: such rows
/// survive erasure, as `subjects/gap-without-column` documents.
fn rows_without_subject_column(_conn: &Connection, _subject: &str) -> Result<u64, String> {
    Ok(0)
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
}
