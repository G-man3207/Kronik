//! Adapters from the store to the runtime's host traits, shared by the
//! node and by replay (kronik-fork).

use std::sync::{Arc, Mutex};

use kronik_core::ids::ActorRef;
use kronik_privacy::sealer::Opened;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{SqlError, SqlHost, SqlHostError, SqlRows, SqlValue, StateView};
use kronik_store::Store;
use kronik_store::sql::{self, SqlActor, TurnOpts, TurnSql};
use rusqlite::types::Value;

/// The actor's committed key-value state. The actor runs one turn at a time
/// and the previous turn is applied before the next starts, so reading
/// `state.db` during the turn sees exactly the state at turn start.
pub struct KvView {
    pub store: Arc<Store>,
    pub actor: ActorRef,
    pub sealer: Arc<kronik_privacy::sealer::Sealer>,
}

impl StateView for KvView {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let value = self
            .store
            .db()
            .kv_get_for_guest(&self.actor.kind, &self.actor.key, key)
            .map_err(|e| e.to_string())?;
        let value = match value {
            None => return Ok(None),
            // Off mode's case: the stored bytes, moved, as before M8.
            Some(pb::Sealable {
                value: Some(pb::sealable::Value::Plain(v)),
                ..
            }) => return Ok(Some(v)),
            Some(value) => value,
        };
        // The guest reads plaintext; an erased value reads as absent
        // (docs/design/m8-privacy.md §5).
        match self.sealer.open(&value) {
            Opened::Value(v) => Ok(Some(v.into_owned())),
            Opened::Erased { .. } => Ok(None),
            Opened::Unreadable { why, .. } => {
                Err(format!("state value {key:?} cannot be unsealed: {why}"))
            }
        }
    }

    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        self.store
            .db()
            .kv_keys(&self.actor.kind, &self.actor.key, prefix)
            .map_err(|e| e.to_string())
    }

    fn timer_pending(&self, id: u64) -> Result<bool, String> {
        self.store
            .db()
            .timer_pending(&self.actor.kind, &self.actor.key, id)
            .map_err(|e| e.to_string())
    }
}

/// The actor's SQL database for one turn, opened and begun on first use.
pub struct SqlTurn {
    store: Arc<Store>,
    name: String,
    opts: TurnOpts,
    db: Option<Arc<Mutex<SqlActor>>>,
}

impl SqlTurn {
    pub fn new(store: Arc<Store>, actor: &ActorRef, opts: TurnOpts) -> SqlTurn {
        SqlTurn {
            store,
            name: actor.to_string(),
            opts,
            db: None,
        }
    }

    fn begin(&mut self) -> Result<Arc<Mutex<SqlActor>>, SqlHostError> {
        if let Some(db) = &self.db {
            return Ok(db.clone());
        }
        let db = self
            .store
            .sql
            .get(&self.name)
            .map_err(|e| SqlHostError::Host(format!("open SQL of {}: {e}", self.name)))?;
        db.lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin_turn(&self.opts)
            .map_err(|e| SqlHostError::Host(format!("begin SQL turn of {}: {e}", self.name)))?;
        self.db = Some(db.clone());
        Ok(db)
    }

    /// Ends the turn's SQL: the changes when `commit`, nothing otherwise.
    /// Values of `secrets` the turn wrote are scrubbed first. `Ok(None)` when
    /// the turn never used SQL; `Err` when SQLite rolled the transaction back
    /// (the turn must fail).
    pub fn end(
        &mut self,
        commit: bool,
        secrets: &[(String, Vec<u8>)],
    ) -> Result<Option<TurnSql>, String> {
        let Some(db) = self.db.take() else {
            return Ok(None);
        };
        let mut g = db.lock().unwrap_or_else(|e| e.into_inner());
        if commit && !secrets.is_empty() {
            g.scrub(secrets)?;
        }
        g.end_turn(commit).map(Some)
    }
}

/// The handle given to the runtime; the scheduler keeps the other `Arc`.
pub struct SqlHandle(pub Arc<Mutex<SqlTurn>>);

fn to_value(v: SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(i) => Value::Integer(i),
        SqlValue::Real(r) => Value::Real(r),
        SqlValue::Text(t) => Value::Text(t),
        SqlValue::Blob(b) => Value::Blob(b),
    }
}

fn from_value(v: Value) -> SqlValue {
    match v {
        Value::Null => SqlValue::Null,
        Value::Integer(i) => SqlValue::Integer(i),
        Value::Real(r) => SqlValue::Real(r),
        Value::Text(t) => SqlValue::Text(t),
        Value::Blob(b) => SqlValue::Blob(b),
    }
}

fn map_err(e: sql::SqlError) -> Result<SqlError, SqlHostError> {
    Ok(match e {
        sql::SqlError::Syntax(m) => SqlError::Syntax(m),
        sql::SqlError::Constraint(m) => SqlError::Constraint(m),
        sql::SqlError::Denied(m) => SqlError::Denied(m),
        sql::SqlError::TooLarge => SqlError::TooLarge,
        sql::SqlError::FuelExhausted => return Err(SqlHostError::FuelExhausted),
    })
}

impl SqlHandle {
    fn with<T>(
        &mut self,
        subject: Option<&str>,
        f: impl FnOnce(&mut SqlActor) -> sql::SqlResult<T>,
    ) -> Result<Result<T, SqlError>, SqlHostError> {
        let db = self.0.lock().unwrap_or_else(|e| e.into_inner()).begin()?;
        let mut g = db.lock().unwrap_or_else(|e| e.into_inner());
        g.set_subject(subject);
        match f(&mut g) {
            Ok(v) => Ok(Ok(v)),
            Err(e) => map_err(e).map(Err),
        }
    }
}

impl SqlHost for SqlHandle {
    fn query(
        &mut self,
        statement: &str,
        params: Vec<SqlValue>,
        subject: Option<&str>,
    ) -> Result<Result<SqlRows, SqlError>, SqlHostError> {
        let params: Vec<Value> = params.into_iter().map(to_value).collect();
        Ok(self
            .with(subject, |db| db.query(statement, &params))?
            .map(|rows| SqlRows {
                columns: rows.columns,
                values: rows
                    .values
                    .into_iter()
                    .map(|r| r.into_iter().map(from_value).collect())
                    .collect(),
            }))
    }

    fn execute(
        &mut self,
        statement: &str,
        params: Vec<SqlValue>,
        subject: Option<&str>,
    ) -> Result<Result<u64, SqlError>, SqlHostError> {
        let params: Vec<Value> = params.into_iter().map(to_value).collect();
        self.with(subject, |db| db.execute(statement, &params))
    }
}
