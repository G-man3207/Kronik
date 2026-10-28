//! `ctx.sql()`: the actor's own SQLite database, owned by the host.

use crate::bindings::kronik::actor::{log, sql};
use crate::{Error, Rows, SqlValue};

/// The actor's SQL database (see `kronik explain sql-state`).
///
/// Every actor has its own SQLite database. A turn's statements run in a
/// savepoint, and their changes are recorded and applied only if the turn
/// commits. DDL is allowed only in [`Actor::migrate`](crate::Actor::migrate),
/// before the first statement that changes data. `datetime('now')`,
/// `random()` and `randomblob()` are deterministic, and `kronik_subject()`
/// returns the turn's default subject, for example in
/// `_subject TEXT DEFAULT (kronik_subject())`.
pub struct Sql {
    _private: (),
}

impl Sql {
    pub(crate) fn new() -> Self {
        Sql { _private: () }
    }

    /// Runs a query and returns its rows. Parameters bind to `?`, `?N` or
    /// `:name` in order; see [`params!`](crate::params).
    ///
    /// A query without `ORDER BY` that returns several rows logs a warning:
    /// their order is whatever SQLite's plan gives, and that can change when
    /// the schema or SQLite changes.
    pub fn query(&self, statement: &str, params: &[SqlValue]) -> Result<Rows, Error> {
        let rows = sql::query(statement, params).map_err(Error::Sql)?;
        if rows.values.len() > 1 && !has_order_by(statement) {
            log::emit(
                log::Level::Warn,
                "a query returned several rows without ORDER BY, so their order is not guaranteed (see `kronik explain sql-state`)",
                &[
                    ("rows".to_string(), rows.values.len().to_string()),
                    ("statement".to_string(), statement.to_string()),
                ],
            );
        }
        Ok(rows)
    }

    /// Runs a statement that returns no rows and returns the number of rows
    /// it changed.
    pub fn execute(&self, statement: &str, params: &[SqlValue]) -> Result<u64, Error> {
        sql::execute(statement, params).map_err(Error::Sql)
    }
}

/// Whether `statement` contains the keywords `ORDER BY` outside string
/// literals, quoted identifiers and comments.
pub(crate) fn has_order_by(statement: &str) -> bool {
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut chars = statement.chars().peekable();
    while let Some(c) = chars.next() {
        let end_word = |word: &mut String, words: &mut Vec<String>| {
            if !word.is_empty() {
                words.push(word.to_ascii_uppercase());
                word.clear();
            }
        };
        match c {
            '\'' | '"' | '`' | '[' => {
                end_word(&mut word, &mut words);
                let close = if c == '[' { ']' } else { c };
                // A doubled quote inside a literal is an escaped quote and
                // ends nothing: skipping to each closing quote handles both.
                for d in chars.by_ref() {
                    if d == close {
                        break;
                    }
                }
                words.push(String::new());
            }
            '-' if chars.peek() == Some(&'-') => {
                end_word(&mut word, &mut words);
                for d in chars.by_ref() {
                    if d == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                end_word(&mut word, &mut words);
                chars.next();
                let mut star = false;
                for d in chars.by_ref() {
                    if star && d == '/' {
                        break;
                    }
                    star = d == '*';
                }
            }
            c if c.is_alphanumeric() || c == '_' => word.push(c),
            _ => end_word(&mut word, &mut words),
        }
    }
    if !word.is_empty() {
        words.push(word.to_ascii_uppercase());
    }
    words.windows(2).any(|w| w[0] == "ORDER" && w[1] == "BY")
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Integer(v)
    }
}

impl From<i32> for SqlValue {
    fn from(v: i32) -> Self {
        SqlValue::Integer(v.into())
    }
}

impl From<u32> for SqlValue {
    fn from(v: u32) -> Self {
        SqlValue::Integer(v.into())
    }
}

impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        SqlValue::Integer(v.into())
    }
}

impl From<f64> for SqlValue {
    fn from(v: f64) -> Self {
        SqlValue::Real(v)
    }
}

impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        SqlValue::Text(v)
    }
}

impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        SqlValue::Text(v.to_string())
    }
}

impl From<&String> for SqlValue {
    fn from(v: &String) -> Self {
        SqlValue::Text(v.clone())
    }
}

impl From<Vec<u8>> for SqlValue {
    fn from(v: Vec<u8>) -> Self {
        SqlValue::Blob(v)
    }
}

impl From<&[u8]> for SqlValue {
    fn from(v: &[u8]) -> Self {
        SqlValue::Blob(v.to_vec())
    }
}

impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        v.map_or(SqlValue::Null, Into::into)
    }
}

impl SqlValue {
    /// The SQLite type name of this value, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            SqlValue::Null => "NULL",
            SqlValue::Integer(_) => "INTEGER",
            SqlValue::Real(_) => "REAL",
            SqlValue::Text(_) => "TEXT",
            SqlValue::Blob(_) => "BLOB",
        }
    }
}

/// A Rust type that a SQL value converts into, for [`Row::get`].
pub trait FromSql: Sized {
    /// The SQL type expected, for error messages.
    const EXPECTED: &'static str;

    /// Converts `value`, or returns `None` if it has another type.
    fn from_sql(value: &SqlValue) -> Option<Self>;
}

impl FromSql for i64 {
    const EXPECTED: &'static str = "INTEGER";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match value {
            SqlValue::Integer(v) => Some(*v),
            _ => None,
        }
    }
}

impl FromSql for u64 {
    const EXPECTED: &'static str = "a non-negative INTEGER";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        i64::from_sql(value).and_then(|v| u64::try_from(v).ok())
    }
}

impl FromSql for i32 {
    const EXPECTED: &'static str = "a 32-bit INTEGER";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        i64::from_sql(value).and_then(|v| i32::try_from(v).ok())
    }
}

impl FromSql for u32 {
    const EXPECTED: &'static str = "a non-negative 32-bit INTEGER";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        i64::from_sql(value).and_then(|v| u32::try_from(v).ok())
    }
}

impl FromSql for bool {
    const EXPECTED: &'static str = "INTEGER 0 or 1";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match i64::from_sql(value)? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

impl FromSql for f64 {
    const EXPECTED: &'static str = "REAL";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match value {
            SqlValue::Real(v) => Some(*v),
            // SQLite stores integral REAL values in columns of any affinity
            // as integers when it can, so accept them.
            SqlValue::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }
}

impl FromSql for String {
    const EXPECTED: &'static str = "TEXT";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match value {
            SqlValue::Text(v) => Some(v.clone()),
            _ => None,
        }
    }
}

impl FromSql for Vec<u8> {
    const EXPECTED: &'static str = "BLOB";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match value {
            SqlValue::Blob(v) => Some(v.clone()),
            _ => None,
        }
    }
}

impl FromSql for SqlValue {
    const EXPECTED: &'static str = "any value";

    fn from_sql(value: &SqlValue) -> Option<Self> {
        Some(value.clone())
    }
}

impl<T: FromSql> FromSql for Option<T> {
    const EXPECTED: &'static str = T::EXPECTED;

    fn from_sql(value: &SqlValue) -> Option<Self> {
        match value {
            SqlValue::Null => Some(None),
            v => T::from_sql(v).map(Some),
        }
    }
}

impl Rows {
    /// The number of rows.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The rows, in the order the query returned them.
    pub fn iter(&self) -> impl Iterator<Item = Row<'_>> {
        self.values.iter().map(|values| Row {
            columns: &self.columns,
            values,
        })
    }

    /// The first row, if any.
    pub fn first(&self) -> Option<Row<'_>> {
        self.iter().next()
    }
}

/// One row of [`Rows`].
#[derive(Clone, Copy)]
pub struct Row<'a> {
    columns: &'a [String],
    values: &'a [SqlValue],
}

impl Row<'_> {
    /// The value of the column called `column` as a `T`. A `NULL` converts
    /// only into an `Option`.
    pub fn get<T: FromSql>(&self, column: &str) -> Result<T, Error> {
        let index = self
            .columns
            .iter()
            .position(|c| c == column)
            .ok_or_else(|| Error::Value(format!("the query has no column called {column:?}")))?;
        self.get_index(index)
    }

    /// The value of the column at `index` (from 0) as a `T`.
    pub fn get_index<T: FromSql>(&self, index: usize) -> Result<T, Error> {
        let name = self.columns.get(index).map_or("?", String::as_str);
        let value = self.values.get(index).ok_or_else(|| {
            Error::Value(format!(
                "the query has {} columns, not {}",
                self.values.len(),
                index + 1
            ))
        })?;
        T::from_sql(value).ok_or_else(|| {
            Error::Value(format!(
                "column {name:?}: expected {}, got {}",
                T::EXPECTED,
                value.type_name()
            ))
        })
    }

    /// The row's values, in column order.
    pub fn values(&self) -> &[SqlValue] {
        self.values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_by_detection() {
        assert!(has_order_by("SELECT * FROM notes ORDER BY id"));
        assert!(has_order_by(
            "select id from notes order\n  by created desc"
        ));
        assert!(has_order_by(
            "SELECT id FROM (SELECT id FROM t) ORDER /* c */ BY id"
        ));
        assert!(!has_order_by("SELECT * FROM notes"));
        assert!(!has_order_by(
            "SELECT * FROM notes WHERE title = 'order by'"
        ));
        assert!(!has_order_by("SELECT \"order\", by FROM t"));
        assert!(!has_order_by("SELECT x FROM t -- ORDER BY x"));
        assert!(!has_order_by("SELECT x FROM t /* ORDER BY x */"));
        assert!(!has_order_by("SELECT recorder, bypass FROM t"));
        assert!(!has_order_by("SELECT 'it''s' ORDER_BY FROM t"));
    }

    #[test]
    fn params_convert() {
        let p = crate::params![1_i64, "t", 2.5, None::<i64>, true, vec![1_u8, 2], Some("x")];
        let kinds: Vec<_> = p.iter().map(SqlValue::type_name).collect();
        assert_eq!(
            kinds,
            ["INTEGER", "TEXT", "REAL", "NULL", "INTEGER", "BLOB", "TEXT"]
        );
        assert!(crate::params![].is_empty());
    }

    #[test]
    fn typed_row_access() {
        let rows = Rows {
            columns: vec!["id".into(), "title".into(), "done".into(), "note".into()],
            values: vec![
                vec![
                    SqlValue::Integer(7),
                    SqlValue::Text("milk".into()),
                    SqlValue::Integer(1),
                    SqlValue::Null,
                ],
                vec![
                    SqlValue::Integer(-1),
                    SqlValue::Blob(vec![0]),
                    SqlValue::Integer(2),
                    SqlValue::Text("n".into()),
                ],
            ],
        };
        assert_eq!(rows.len(), 2);
        let first = rows.first().unwrap_or_else(|| panic!("no rows"));
        assert_eq!(first.get::<i64>("id").ok(), Some(7));
        assert_eq!(first.get::<String>("title").ok().as_deref(), Some("milk"));
        assert_eq!(first.get::<bool>("done").ok(), Some(true));
        assert_eq!(first.get::<Option<String>>("note").ok(), Some(None));
        assert_eq!(first.get_index::<f64>(0).ok(), Some(7.0));

        let second = rows.iter().nth(1).unwrap_or_else(|| panic!("one row"));
        let err = |r: Result<u64, Error>| r.err().map(|e| e.to_string());
        assert_eq!(
            err(second.get::<u64>("id")).as_deref(),
            Some(
                "column \"id\": expected a non-negative INTEGER, got INTEGER (see `kronik explain sql-state`)"
            )
        );
        assert_eq!(
            err(second.get::<u64>("nope")).as_deref(),
            Some("the query has no column called \"nope\" (see `kronik explain sql-state`)")
        );
        assert!(second.get::<bool>("done").is_err());
        assert!(second.get::<String>("title").is_err());
        assert_eq!(
            second
                .get::<Option<String>>("note")
                .ok()
                .flatten()
                .as_deref(),
            Some("n")
        );
    }
}
