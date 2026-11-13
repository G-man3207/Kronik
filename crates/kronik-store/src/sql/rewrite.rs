//! Rebuild a subject-tagged changeset with text and blob cells replaced.
//!
//! The session extension records the rewritten rows, so the bytes
//! `sqlite3changeset_apply` accepts are produced by SQLite rather than by a
//! hand-rolled encoder. Integer and real values are copied through, including
//! primary keys, so a later UPDATE still finds the row. A column whose every
//! present text value is the changeset's subject is left unchanged: that is
//! the `_subject` column, and erasure deletes by that id.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::types::Value;
use rusqlite::{Connection, params_from_iter};

use super::ffi::{self, Change, Op, Val};

/// Replaces text and blob cell values in `cs` and returns a changeset that
/// applies to the same schema. `rewrite` is the pseudonym of one cell; equal
/// inputs must yield equal outputs so an UPDATE's old image matches the row
/// a previous change inserted.
pub fn pseudonymize_changeset(
    cs: &[u8],
    subject: &str,
    mut rewrite: impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    if cs.is_empty() {
        return Ok(Vec::new());
    }
    let changes = ffi::changes(cs).map_err(|e| e.to_string())?;
    if changes.is_empty() {
        return Ok(cs.to_vec());
    }
    let skip = subject_columns(&changes, subject);
    let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
    create_tables(&conn, &changes)?;
    preinsert(&conn, &changes, &skip, &mut rewrite)?;
    let session = ffi::Session::new(&conn, true).map_err(|e| e.to_string())?;
    for change in &changes {
        replay(&conn, change, &skip, &mut rewrite)?;
    }
    session.changeset().map_err(|e| e.to_string())
}

/// Columns to leave unchanged: exactly one column per table whose every
/// present text value is `subject` (the `_subject` column). More than one
/// such column is ambiguous, so none of them is skipped.
fn subject_columns(changes: &[Change], subject: &str) -> BTreeSet<(String, usize)> {
    let mut by_table: BTreeMap<&str, Vec<&Change>> = BTreeMap::new();
    for change in changes {
        by_table
            .entry(change.table.as_str())
            .or_default()
            .push(change);
    }
    let mut skip = BTreeSet::new();
    for (table, group) in by_table {
        let ncol = group
            .iter()
            .map(|c| c.pk.len().max(c.old.len()).max(c.new.len()))
            .max()
            .unwrap_or(0);
        let mut candidates = Vec::new();
        for col in 0..ncol {
            let mut saw = false;
            let mut all_subject = true;
            for change in &group {
                for image in [&change.old, &change.new] {
                    let Some(Some(value)) = image.get(col) else {
                        continue;
                    };
                    if let Val::Text(text) = value {
                        saw = true;
                        if text != subject {
                            all_subject = false;
                        }
                    }
                }
            }
            if saw && all_subject {
                candidates.push(col);
            }
        }
        if candidates.len() == 1 {
            skip.insert((table.to_string(), candidates[0]));
        }
    }
    skip
}

fn create_tables(conn: &Connection, changes: &[Change]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for change in changes {
        if !seen.insert(change.table.clone()) {
            continue;
        }
        let ncol = change.pk.len().max(change.old.len()).max(change.new.len());
        if ncol == 0 {
            return Err(format!("SQL changeset for {} has no columns", change.table));
        }
        let cols = (0..ncol)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let pk = change
            .pk
            .iter()
            .enumerate()
            .filter(|(_, is_pk)| **is_pk)
            .map(|(i, _)| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = if pk.is_empty() {
            format!("CREATE TABLE {} ({cols})", quote(&change.table))
        } else {
            format!(
                "CREATE TABLE {} ({cols}, PRIMARY KEY ({pk}))",
                quote(&change.table)
            )
        };
        conn.execute_batch(&sql).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Rows an UPDATE or DELETE names that this changeset does not insert first.
/// They are written before the session starts, so the session records only
/// the original operations, with rewritten images.
fn preinsert(
    conn: &Connection,
    changes: &[Change],
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<(), String> {
    let mut present = BTreeSet::new();
    for change in changes {
        let key = row_key(change, &image_of(change), skip, rewrite);
        match change.op {
            Op::Insert => {
                present.insert(key);
            }
            Op::Update | Op::Delete => {
                if present.insert(key.clone()) {
                    insert_image(conn, change, &change.old, skip, rewrite)?;
                }
                if change.op == Op::Delete {
                    present.remove(&key);
                } else {
                    let new_key = row_key(change, &change.new, skip, rewrite);
                    if new_key != key {
                        present.remove(&key);
                        present.insert(new_key);
                    }
                }
            }
        }
    }
    Ok(())
}

fn image_of(change: &Change) -> Vec<Option<Val>> {
    if change.op == Op::Insert {
        change.new.clone()
    } else {
        change.old.clone()
    }
}

fn replay(
    conn: &Connection,
    change: &Change,
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<(), String> {
    match change.op {
        Op::Insert => insert_image(conn, change, &change.new, skip, rewrite),
        Op::Delete => delete_row(conn, change, skip, rewrite),
        Op::Update => update_row(conn, change, skip, rewrite),
    }
}

fn insert_image(
    conn: &Connection,
    change: &Change,
    image: &[Option<Val>],
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<(), String> {
    let ncol = change.pk.len().max(change.old.len()).max(change.new.len());
    let cols = (0..ncol)
        .map(|i| format!("c{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = (1..=ncol)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let params: Vec<Value> = (0..ncol)
        .map(|i| value_at(change, image, i, skip, rewrite))
        .collect();
    conn.execute(
        &format!(
            "INSERT INTO {} ({cols}) VALUES ({placeholders})",
            quote(&change.table)
        ),
        params_from_iter(params),
    )
    .map(|_| ())
    .map_err(|e| format!("SQL changeset insert into {}: {e}", change.table))
}

fn update_row(
    conn: &Connection,
    change: &Change,
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<(), String> {
    let ncol = change.pk.len().max(change.old.len()).max(change.new.len());
    let mut sets = Vec::new();
    let mut params = Vec::new();
    for i in 0..ncol {
        if change.new.get(i).and_then(|v| v.as_ref()).is_none() {
            continue;
        }
        sets.push(format!("c{i} = ?{}", params.len() + 1));
        params.push(value_at(change, &change.new, i, skip, rewrite));
    }
    if sets.is_empty() {
        return Ok(());
    }
    let (wheres, where_params) = pk_where(change, &change.old, skip, rewrite, params.len())?;
    params.extend(where_params);
    conn.execute(
        &format!(
            "UPDATE {} SET {} WHERE {}",
            quote(&change.table),
            sets.join(", "),
            wheres
        ),
        params_from_iter(params),
    )
    .map(|_| ())
    .map_err(|e| format!("SQL changeset update of {}: {e}", change.table))
}

fn delete_row(
    conn: &Connection,
    change: &Change,
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<(), String> {
    let (wheres, params) = pk_where(change, &change.old, skip, rewrite, 0)?;
    conn.execute(
        &format!("DELETE FROM {} WHERE {wheres}", quote(&change.table)),
        params_from_iter(params),
    )
    .map(|_| ())
    .map_err(|e| format!("SQL changeset delete from {}: {e}", change.table))
}

fn pk_where(
    change: &Change,
    image: &[Option<Val>],
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
    already: usize,
) -> Result<(String, Vec<Value>), String> {
    let mut wheres = Vec::new();
    let mut params = Vec::new();
    for (i, is_pk) in change.pk.iter().enumerate() {
        if !is_pk {
            continue;
        }
        match image.get(i).and_then(|v| v.as_ref()) {
            Some(_) => {
                wheres.push(format!("c{i} = ?{}", already + params.len() + 1));
                params.push(value_at(change, image, i, skip, rewrite));
            }
            None => wheres.push(format!("c{i} IS NULL")),
        }
    }
    if wheres.is_empty() {
        return Err(format!(
            "SQL changeset for {} has no primary key to match",
            change.table
        ));
    }
    Ok((wheres.join(" AND "), params))
}

fn value_at(
    change: &Change,
    image: &[Option<Val>],
    column: usize,
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> Value {
    let Some(value) = image.get(column).and_then(|v| v.as_ref()) else {
        return Value::Null;
    };
    let skipped = skip.contains(&(change.table.clone(), column));
    sql_val(&mapped(value, skipped, rewrite))
}

fn mapped(value: &Val, skip: bool, rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>) -> Val {
    if skip {
        return value.clone();
    }
    match value {
        Val::Text(text) => {
            let bytes = rewrite(text.as_bytes());
            match String::from_utf8(bytes) {
                Ok(text) => Val::Text(text),
                Err(err) => Val::Text(String::from_utf8_lossy(err.as_bytes()).into_owned()),
            }
        }
        Val::Blob(bytes) => Val::Blob(rewrite(bytes)),
        other => other.clone(),
    }
}

fn sql_val(value: &Val) -> Value {
    match value {
        Val::Null => Value::Null,
        Val::Int(i) => Value::Integer(*i),
        Val::Real(r) => Value::Real(*r),
        Val::Text(t) => Value::Text(t.clone()),
        Val::Blob(b) => Value::Blob(b.clone()),
    }
}

fn row_key(
    change: &Change,
    image: &[Option<Val>],
    skip: &BTreeSet<(String, usize)>,
    rewrite: &mut impl FnMut(&[u8]) -> Vec<u8>,
) -> String {
    let mut key = change.table.clone();
    for (i, is_pk) in change.pk.iter().enumerate() {
        if !is_pk {
            continue;
        }
        key.push('\0');
        match image.get(i).and_then(|v| v.as_ref()) {
            Some(value) => {
                let skipped = skip.contains(&(change.table.clone(), i));
                key.push_str(&format!("{:?}", mapped(value, skipped, rewrite)));
            }
            None => key.push_str("null"),
        }
    }
    key
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
