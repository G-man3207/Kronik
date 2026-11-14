//! State a replay could not verify after an erasure (ADR 0109).
//!
//! A turn that met erased data is unverifiable: it ran on what is left of
//! the erased values, so what it wrote need not be what production wrote,
//! and production turns below it may never run in the fork at all. The
//! store a later turn reads then differs from production's for reasons the
//! code did not cause. [`Taint`] remembers where: each state key, timer and
//! SQL database such a turn (or a production turn missing below one) left
//! different, from that turn's production position on. A turn that reads
//! one of them is unverifiable too, not divergent, and so on down the line.
//!
//! The marks only classify; they never change what a guest reads. A mark
//! ends when a verified turn writes the key again (both sides then hold the
//! same value), or, when every value involved belonged to one subject, at
//! that subject's erasure, which deletes them on both sides.

use std::collections::BTreeMap;

use kronik_core::ids::Lsn;
use kronik_proto::log::v1 as pb;

/// Unverified from production position `from` on. `subject`: the only
/// subject whose values are involved, when its erasure leaves both sides
/// equal; `None` when nothing but a verified write ends it. `until`: where
/// that erasure came. `untagged` (SQL): production's side was recorded by
/// an engine that let a subject's turn write a table without `_subject`,
/// whose rows survive the erasure, so in a database with such a table the
/// mark does not end there.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mark {
    from: Lsn,
    subject: Option<String>,
    until: Option<Lsn>,
    untagged: bool,
}

/// Whether a turn recorded by `engine_version` could write a subject's rows
/// to a table without `_subject`: engines before Kronik 0.5.0, which
/// refuses such a write (ADR 0005 §6, option B). A version that does not
/// parse counts as one that could.
pub(crate) fn subject_rows_may_be_untagged(engine_version: &str) -> bool {
    let release = engine_version
        .strip_prefix("kronik-")
        .and_then(|v| v.split('+').next())
        .and_then(|v| v.split('-').next());
    let mut parts = release.into_iter().flat_map(|v| v.split('.'));
    let (Some(Ok(major)), Some(Ok(minor))) = (
        parts.next().map(str::parse::<u64>),
        parts.next().map(str::parse::<u64>),
    ) else {
        return true;
    };
    (major, minor) < (0, 5)
}

/// Where a replay's store holds state it could not verify (module doc).
#[derive(Debug, Default)]
pub struct Taint {
    /// (actor, state key)
    keys: BTreeMap<(String, String), Vec<Mark>>,
    /// (actor, timer id)
    timers: BTreeMap<(String, u64), Vec<Lsn>>,
    /// actor -> its SQL database
    sql: BTreeMap<String, Vec<Mark>>,
}

/// What a turn did to one state key.
#[derive(Debug, PartialEq)]
enum Write<'a> {
    Set(&'a pb::Sealable),
    Delete,
}

fn actor_of(t: &pb::TurnRecord) -> String {
    t.actor
        .as_ref()
        .map(|a| format!("{}/{}", a.kind, a.key))
        .unwrap_or_default()
}

fn committed(t: &pb::TurnRecord) -> bool {
    t.outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
}

/// The final write of each key a committed turn wrote.
fn writes(t: &pb::TurnRecord) -> BTreeMap<&str, Write<'_>> {
    let mut out = BTreeMap::new();
    if !committed(t) {
        return out;
    }
    for w in &t.writes {
        let write = match w.value.as_ref() {
            Some(v) if w.op == pb::StateOp::Set as i32 => Write::Set(v),
            _ => Write::Delete,
        };
        out.insert(w.key.as_str(), write);
    }
    out
}

/// The timer operations of a committed turn, by timer id.
fn timers(t: &pb::TurnRecord) -> BTreeMap<u64, &pb::TimerOp> {
    if !committed(t) {
        return BTreeMap::new();
    }
    t.timers.iter().map(|op| (op.timer_id, op)).collect()
}

/// The SQL changesets of a committed turn by subject, and its schema.
#[allow(clippy::type_complexity)]
fn sql(t: &pb::TurnRecord) -> (BTreeMap<Option<&str>, Vec<&pb::Sealable>>, Vec<&str>) {
    let mut out: BTreeMap<Option<&str>, Vec<&pb::Sealable>> = BTreeMap::new();
    if !committed(t) {
        return (out, Vec::new());
    }
    for c in &t.sql_changes {
        if let Some(cs) = c.changeset.as_ref() {
            out.entry(cs.subject.as_deref()).or_default().push(cs);
        }
    }
    let schema = t.sql_schema.iter().map(|s| s.statement.as_str()).collect();
    (out, schema)
}

/// The one subject whose erasure leaves a key equal on both sides: each
/// side deleted it or set a value of that subject.
fn erased_alike(fork: Option<&Write<'_>>, prod: Option<&Write<'_>>) -> Option<String> {
    let mut subject: Option<&str> = None;
    for side in [fork, prod] {
        match side {
            // The turn did not write the key: what that side holds is
            // whatever was there before.
            None => return None,
            Some(Write::Delete) => {}
            Some(Write::Set(v)) => match (v.subject.as_deref(), subject) {
                (None, _) => return None,
                (Some(s), None) => subject = Some(s),
                (Some(s), Some(t)) if s == t => {}
                _ => return None,
            },
        }
    }
    subject.map(str::to_owned)
}

impl Taint {
    fn mark_key(&mut self, actor: &str, key: &str, from: Lsn, subject: Option<String>) {
        self.keys
            .entry((actor.to_owned(), key.to_owned()))
            .or_default()
            .push(Mark {
                from,
                subject,
                until: None,
                untagged: false,
            });
    }

    fn mark_sql(&mut self, actor: &str, from: Lsn, subject: Option<String>, untagged: bool) {
        self.sql.entry(actor.to_owned()).or_default().push(Mark {
            from,
            subject,
            until: None,
            untagged,
        });
    }

    fn mark_timer(&mut self, actor: &str, id: u64, from: Lsn) {
        self.timers
            .entry((actor.to_owned(), id))
            .or_default()
            .push(from);
    }

    /// Whether the state key holds data the replay could not verify at
    /// production position `at`.
    pub fn key(&self, actor: &str, key: &str, at: Lsn) -> bool {
        self.keys
            .get(&(actor.to_owned(), key.to_owned()))
            .is_some_and(|marks| marks.iter().any(|m| m.from <= at))
    }

    /// Whether any state key of `actor` starting with `prefix` does.
    pub fn prefix(&self, actor: &str, prefix: &str, at: Lsn) -> bool {
        self.keys
            .range((actor.to_owned(), prefix.to_owned())..)
            .take_while(|((a, k), _)| a == actor && k.starts_with(prefix))
            .any(|(_, marks)| marks.iter().any(|m| m.from <= at))
    }

    /// Whether the timer's being pending may differ from production's.
    pub fn timer(&self, actor: &str, id: u64, at: Lsn) -> bool {
        self.timers
            .get(&(actor.to_owned(), id))
            .is_some_and(|marks| marks.iter().any(|from| *from <= at))
    }

    /// Whether the actor's SQL database may hold other rows than
    /// production's. `untagged`: it has a table without `_subject`, whose
    /// rows a subject's erasure does not delete; only a mark whose
    /// production side an engine before ADR 0005 §6 option B recorded can
    /// involve such rows, and the erasure ends no such mark.
    pub fn sql(&self, actor: &str, at: Lsn, untagged: bool) -> bool {
        self.sql.get(actor).is_some_and(|marks| {
            marks.iter().any(|m| {
                m.from <= at && ((untagged && m.untagged) || m.until.is_none_or(|u| at < u))
            })
        })
    }

    /// Whether the actor's SQL database has any mark at all.
    pub fn has_sql(&self, actor: &str) -> bool {
        self.sql.contains_key(actor)
    }

    /// A turn the replay could not verify, at production position `at`:
    /// every key, timer and SQL database where its writes (`fork`) and its
    /// production counterpart's (`prod`) differ is marked. Without a
    /// counterpart, everything the fork turn wrote is.
    pub fn unverified_turn(
        &mut self,
        fork: Option<&pb::TurnRecord>,
        prod: Option<&pb::TurnRecord>,
        at: Lsn,
    ) {
        let (fa, pa) = (fork.map(actor_of), prod.map(actor_of));
        if fa.is_some() && fa == pa {
            let actor = fa.unwrap_or_default();
            let (f, p) = (
                fork.map(writes).unwrap_or_default(),
                prod.map(writes).unwrap_or_default(),
            );
            let keys: std::collections::BTreeSet<&str> =
                f.keys().chain(p.keys()).copied().collect();
            for k in keys {
                let (fw, pw) = (f.get(k), p.get(k));
                if fw != pw {
                    self.mark_key(&actor, k, at, erased_alike(fw, pw));
                }
            }
            let (ft, pt) = (
                fork.map(timers).unwrap_or_default(),
                prod.map(timers).unwrap_or_default(),
            );
            let ids: std::collections::BTreeSet<u64> =
                ft.keys().chain(pt.keys()).copied().collect();
            for id in ids {
                if ft.get(&id) != pt.get(&id) {
                    self.mark_timer(&actor, id, at);
                }
            }
            let ((fs, fschema), (ps, pschema)) = (
                fork.map(sql).unwrap_or_default(),
                prod.map(sql).unwrap_or_default(),
            );
            let subjects: std::collections::BTreeSet<Option<&str>> =
                fs.keys().chain(ps.keys()).copied().collect();
            let untagged = prod.is_some_and(|p| subject_rows_may_be_untagged(&p.engine_version));
            for s in subjects {
                if fs.get(&s) != ps.get(&s) {
                    self.mark_sql(&actor, at, s.map(str::to_owned), untagged);
                }
            }
            if fschema != pschema {
                self.mark_sql(&actor, at, None, untagged);
            }
            return;
        }
        // On different actors (a target the erased value named), each side
        // left its own actor different from what the other side holds.
        for t in [fork, prod].into_iter().flatten() {
            self.all_of(t, at);
        }
    }

    /// A production turn the fork may never run, below a turn it could not
    /// verify: from its own position on, everything it wrote is unverified.
    /// Its SQL changes of one subject are rows of that subject, which the
    /// subject's erasure deletes on both sides (ADR 0005 §6).
    pub fn missing_turn(&mut self, prod: &pb::TurnRecord, at: Lsn) {
        self.all_of(prod, at);
    }

    fn all_of(&mut self, t: &pb::TurnRecord, at: Lsn) {
        let actor = actor_of(t);
        for k in writes(t).keys() {
            self.mark_key(&actor, k, at, None);
        }
        for id in timers(t).keys() {
            self.mark_timer(&actor, *id, at);
        }
        // A fork turn's record carries this engine's version.
        let untagged = subject_rows_may_be_untagged(&t.engine_version);
        let (changes, schema) = sql(t);
        for s in changes.keys() {
            self.mark_sql(&actor, at, s.map(str::to_owned), untagged);
        }
        if !schema.is_empty() {
            self.mark_sql(&actor, at, None, untagged);
        }
    }

    /// A turn whose state both sides now share, at production position
    /// `at`: a verified fork turn, or a production record a replay applies
    /// as it is. What it writes replaces what was marked up to there.
    pub fn verified_turn(&mut self, t: &pb::TurnRecord, at: Lsn) {
        let actor = actor_of(t);
        for k in writes(t).keys() {
            let key = (actor.clone(), (*k).to_owned());
            if let Some(marks) = self.keys.get_mut(&key) {
                marks.retain(|m| m.from > at);
                if marks.is_empty() {
                    self.keys.remove(&key);
                }
            }
        }
        for id in timers(t).keys() {
            let key = (actor.clone(), *id);
            if let Some(marks) = self.timers.get_mut(&key) {
                marks.retain(|from| *from > at);
                if marks.is_empty() {
                    self.timers.remove(&key);
                }
            }
        }
    }

    /// Production's erasure of `subject` at `at`, which the replay's store
    /// follows: marks that only involved values of the subject end there.
    pub fn erasure(&mut self, subject: &str, at: Lsn) {
        let ends = |m: &Mark| m.from < at && m.subject.as_deref() == Some(subject);
        self.keys.retain(|_, marks| {
            marks.retain(|m| !ends(m));
            !marks.is_empty()
        });
        for m in self.sql.values_mut().flatten() {
            if ends(m) && m.until.is_none() {
                m.until = Some(at);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(subject: Option<&str>, v: &str) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: subject.map(str::to_owned),
            value: Some(pb::sealable::Value::Plain(v.as_bytes().to_vec())),
        })
    }

    fn turn(
        actor: &str,
        writes: &[(&str, Option<pb::Sealable>)],
        sql: &[(Option<&str>, &str)],
    ) -> pb::TurnRecord {
        let (kind, key) = actor.split_once('/').unwrap();
        pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: kind.into(),
                key: key.into(),
            }),
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            writes: writes
                .iter()
                .map(|(k, v)| pb::StateWrite {
                    key: (*k).into(),
                    op: if v.is_some() {
                        pb::StateOp::Set
                    } else {
                        pb::StateOp::Delete
                    } as i32,
                    value: v.clone(),
                })
                .collect(),
            sql_changes: sql
                .iter()
                .map(|(s, bytes)| pb::SqlChangeset {
                    changeset: val(*s, bytes),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Only where the fork turn and its counterpart differ, from the turn's
    /// position on; equal writes stay verifiable.
    #[test]
    fn an_unverified_turn_marks_what_differs() {
        let mut t = Taint::default();
        let fork = turn(
            "c/a",
            &[("s", val(Some("u:1"), "[erased]")), ("n", val(None, "1"))],
            &[],
        );
        let prod = turn(
            "c/a",
            &[("s", val(Some("u:1"), "secret")), ("n", val(None, "1"))],
            &[],
        );
        t.unverified_turn(Some(&fork), Some(&prod), 10);
        assert!(t.key("c/a", "s", 10) && t.key("c/a", "s", 11));
        assert!(!t.key("c/a", "s", 9), "before the turn");
        assert!(!t.key("c/a", "n", 11), "equal on both sides");
        assert!(t.prefix("c/a", "", 11) && !t.prefix("c/a", "x", 11));
        assert!(!t.prefix("c/b", "", 11));
        // Both values were u:1's: its erasure deletes them on both sides.
        t.erasure("u:1", 12);
        assert!(!t.key("c/a", "s", 13));
    }

    /// A key one side did not write holds what was there before: only a
    /// verified write ends that mark, not an erasure.
    #[test]
    fn a_key_one_side_did_not_write_needs_a_verified_write() {
        let mut t = Taint::default();
        let fork = turn("c/a", &[], &[]);
        let prod = turn("c/a", &[("s", val(Some("u:1"), "secret"))], &[]);
        t.unverified_turn(Some(&fork), Some(&prod), 10);
        t.erasure("u:1", 12);
        assert!(t.key("c/a", "s", 13));
        // A verified write before the mark leaves it; one after ends it.
        t.verified_turn(&turn("c/a", &[("s", val(None, "x"))], &[]), 9);
        assert!(t.key("c/a", "s", 13));
        t.verified_turn(&turn("c/a", &[("s", val(None, "x"))], &[]), 14);
        assert!(!t.key("c/a", "s", 15));
    }

    /// A production turn missing below one: its writes are unverified from
    /// its own position, so a verified write before that does not end them.
    #[test]
    fn a_missing_turn_marks_from_its_own_position() {
        let mut t = Taint::default();
        let prod = turn("c/f0", &[("last", val(Some("u:1"), "5"))], &[]);
        t.missing_turn(&prod, 20);
        assert!(!t.key("c/f0", "last", 15));
        t.verified_turn(&turn("c/f0", &[("last", val(None, "x"))], &[]), 15);
        assert!(t.key("c/f0", "last", 21));
        t.erasure("u:1", 25);
        assert!(t.key("c/f0", "last", 26), "the fork's value is not u:1's");
    }

    /// SQL: a differing changeset of one subject is that subject's rows; its
    /// erasure ends the mark, an untagged one's never does. Rows the erasure
    /// does not delete (a table without `_subject`) can only come from a
    /// production side an engine before ADR 0005 §6 option B recorded.
    #[test]
    fn sql_marks_end_with_their_subjects_erasure() {
        let mut t = Taint::default();
        let fork = turn("n/1", &[], &[(Some("u:1"), "fork rows"), (None, "same")]);
        let mut prod = turn("n/1", &[], &[(Some("u:1"), "prod rows"), (None, "same")]);
        prod.engine_version = "kronik-0.4.1+wasmtime-50.0.1".into();
        t.unverified_turn(Some(&fork), Some(&prod), 10);
        assert!(t.sql("n/1", 11, false) && !t.sql("n/1", 9, false) && !t.sql("n/2", 11, false));
        t.erasure("u:1", 12);
        assert!(t.sql("n/1", 11, false), "before the erasure");
        assert!(!t.sql("n/1", 13, false));
        // A table without `_subject` keeps rows the erasure does not delete.
        assert!(t.sql("n/1", 13, true));
        // Recorded by an engine that refuses a subject's untagged write: the
        // erasure ends the mark whatever tables the database has (#73).
        let mut t = Taint::default();
        prod.engine_version = "kronik-0.5.0-dev+wasmtime-50.0.1".into();
        t.unverified_turn(Some(&fork), Some(&prod), 10);
        t.erasure("u:1", 12);
        assert!(t.sql("n/1", 11, true), "before the erasure");
        assert!(!t.sql("n/1", 13, true));
        let fork = turn("n/1", &[], &[(None, "fork rows")]);
        let prod = turn("n/1", &[], &[(None, "prod rows")]);
        t.unverified_turn(Some(&fork), Some(&prod), 20);
        t.erasure("u:1", 22);
        assert!(t.sql("n/1", 23, false));
    }

    #[test]
    fn engines_before_0_5_could_write_a_subjects_untagged_rows() {
        for (version, untagged) in [
            ("kronik-0.1.0-dev+wasmtime-50.0.0", true),
            ("kronik-0.3.0+wasmtime-50.0.0", true),
            ("kronik-0.4.1+wasmtime-50.0.1", true),
            ("kronik-0.5.0-dev+wasmtime-50.0.1", false),
            ("kronik-0.5.0+wasmtime-51.0.0", false),
            ("kronik-1.2.3+wasmtime-60.0.0", false),
            (kronik_runtime::ENGINE_VERSION, false),
            ("", true),
            ("something else", true),
        ] {
            assert_eq!(subject_rows_may_be_untagged(version), untagged, "{version}");
        }
    }

    /// The erased value named the target: each side changed its own actor.
    #[test]
    fn turns_on_different_actors_mark_both() {
        let mut t = Taint::default();
        let fork = turn("c/[erased]", &[("n", val(Some("u:1"), "1"))], &[]);
        let prod = turn("c/k2", &[("n", val(Some("u:1"), "1"))], &[]);
        t.unverified_turn(Some(&fork), Some(&prod), 10);
        assert!(t.key("c/k2", "n", 11) && t.key("c/[erased]", "n", 11));
    }
}
