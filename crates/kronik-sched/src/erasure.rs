//! What an erasure must not let through: plaintext of the subject that was
//! already in flight when its keys went (docs/design/m8-privacy.md §6.8,
//! ADR 0123).
//!
//! What is in flight: a request, a message or a call a turn sent, a re-run,
//! a mailbox row or a timer read back from `state.db`, and the turns that
//! run. Each carries where its values came from ([`Born`]): the node's
//! erasure generation for values it holds in memory, the LSN that recorded
//! them for values read back from the log or `state.db`. A value of a
//! subject erased after that point predates the erasure:
//!
//! - a queued input with one fails its turn with `SUBJECT_ERASED` before
//!   guest code runs (`Node::run_job`);
//! - a turn that runs across the erasure finishes, but every record it
//!   writes is sealed against its provenance (`Node::seal_born`): such a
//!   value becomes the erasure's tombstone, never plaintext sealed again
//!   under a key version newer than the erased ones.
//!
//! Sealing a turn's record and appending it take the node's erasure fence
//! shared; an erasure takes it exclusively from before its keys go until its
//! record is applied. So a turn's record is either in the log before the
//! `Erasure` record, sealed under the version it erases, or sealed knowing
//! of the erasure. Until the record is applied the subject's rows are still
//! in `state.db` and the actor databases, so whatever a turn starts with
//! then counts as born before the erasure too ([`Marks::now`]).

use std::collections::{BTreeSet, HashMap};

use kronik_core::ids::Lsn;
use kronik_proto::log::v1 as pb;

/// Where a queued input's values came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Born {
    /// Held in memory since the node's erasure generation was this.
    Gen(u64),
    /// Read back from the record at this LSN, or from a `state.db` row it
    /// wrote.
    Lsn(Lsn),
}

/// One subject's latest erasure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mark {
    /// Its generation in this process: 0 for an erasure recorded before the
    /// process started, 1 for one whose record the start still has to
    /// commit (`Node::recover_erasures`), from 2 on for this process's.
    generation: u64,
    /// Its `Erasure` record's LSN, `None` while its keys are gone but the
    /// record is not applied yet.
    lsn: Option<Lsn>,
    /// The last key version it erased: what its tombstones name.
    key_version: u32,
}

/// The erasures queued work may predate.
#[derive(Clone, Debug, Default)]
pub(crate) struct Marks {
    generation: u64,
    subjects: HashMap<String, Mark>,
}

impl Marks {
    /// At start: `recorded` erasures (subject, key version, record LSN), and
    /// `unrecorded` ones whose keys the keystore erased but whose record a
    /// stop kept from the log (`Node::recover_erasures` commits it).
    pub(crate) fn load(recorded: Vec<(String, u32, Lsn)>, unrecorded: Vec<(String, u32)>) -> Marks {
        let mut subjects = HashMap::new();
        for (subject, key_version, lsn) in recorded {
            subjects.insert(
                subject,
                Mark {
                    generation: 0,
                    lsn: Some(lsn),
                    key_version,
                },
            );
        }
        for (subject, key_version) in unrecorded {
            subjects.insert(
                subject,
                Mark {
                    generation: 1,
                    lsn: None,
                    key_version,
                },
            );
        }
        Marks {
            generation: 1,
            subjects,
        }
    }

    /// What a value the node takes in now is born at: before every erasure
    /// whose record is not applied yet, whose subject's rows a turn could
    /// still read.
    pub(crate) fn now(&self) -> Born {
        let pending = self
            .subjects
            .values()
            .filter(|m| m.lsn.is_none())
            .map(|m| m.generation.saturating_sub(1))
            .min();
        Born::Gen(pending.map_or(self.generation, |p| p.min(self.generation)))
    }

    /// An erasure of `subject` begins: its keys go next. Returns what to
    /// put back if they do not ([`Marks::undo`]).
    pub(crate) fn begin(&mut self, subject: &str) -> Undo {
        self.generation += 1;
        let previous = self.subjects.insert(
            subject.to_owned(),
            Mark {
                generation: self.generation,
                lsn: None,
                key_version: 0,
            },
        );
        Undo {
            subject: subject.to_owned(),
            previous,
        }
    }

    /// The keystore did not erase: the subject is as it was.
    pub(crate) fn undo(&mut self, undo: Undo) {
        match undo.previous {
            Some(mark) => self.subjects.insert(undo.subject, mark),
            None => self.subjects.remove(&undo.subject),
        };
    }

    /// The keystore erased `subject` through `key_version`.
    pub(crate) fn keys_erased(&mut self, subject: &str, key_version: u32) {
        if let Some(mark) = self.subjects.get_mut(subject) {
            mark.key_version = key_version;
        }
    }

    /// The `Erasure` record of `subject` is applied at `lsn`.
    pub(crate) fn recorded(&mut self, subject: &str, key_version: u32, lsn: Lsn) {
        let generation = self.subjects.get(subject).map_or(0, |m| m.generation);
        self.subjects.insert(
            subject.to_owned(),
            Mark {
                generation,
                lsn: Some(lsn),
                key_version,
            },
        );
    }

    /// The key version of the erasure that a value of `subject` born at
    /// `born` predates, if any.
    pub(crate) fn predates(&self, subject: &str, born: Born) -> Option<u32> {
        let mark = self.subjects.get(subject)?;
        let before = match born {
            Born::Gen(generation) => mark.generation > generation,
            Born::Lsn(lsn) => mark.lsn.is_none_or(|erased| erased > lsn),
        };
        before.then_some(mark.key_version)
    }

    /// The subjects erased after `born`: what a turn born then may still
    /// hold in memory.
    pub(crate) fn erased_after(&self, born: Born) -> impl Iterator<Item = &String> {
        self.subjects
            .keys()
            .filter(move |subject| self.predates(subject, born).is_some())
    }

    /// Whether any value `visit` walks predates an erasure.
    pub(crate) fn any_predating(
        &self,
        born: Born,
        visit: impl FnOnce(&mut dyn FnMut(&mut pb::Sealable)),
    ) -> bool {
        if self.subjects.is_empty() {
            return false;
        }
        let mut found = false;
        visit(&mut |s: &mut pb::Sealable| {
            found |= s
                .subject
                .as_deref()
                .is_some_and(|subject| self.predates(subject, born).is_some());
        });
        found
    }

    /// The subjects of the values `visit` walks that predate their erasure.
    pub(crate) fn predating_subjects(
        &self,
        born: Born,
        visit: impl FnOnce(&mut dyn FnMut(&mut pb::Sealable)),
        into: &mut BTreeSet<String>,
    ) {
        if self.subjects.is_empty() {
            return;
        }
        visit(&mut |s: &mut pb::Sealable| {
            if let Some(subject) = s.subject.as_deref()
                && self.predates(subject, born).is_some()
                && matches!(s.value, Some(pb::sealable::Value::Plain(_)))
            {
                into.insert(subject.to_owned());
            }
        });
    }

    /// Replaces every value `visit` walks that predates its subject's
    /// erasure with that erasure's tombstone; returns how many it replaced.
    pub(crate) fn tombstone(
        &self,
        born: Born,
        visit: impl FnOnce(&mut dyn FnMut(&mut pb::Sealable)),
    ) -> usize {
        if self.subjects.is_empty() {
            return 0;
        }
        let mut n = 0;
        visit(&mut |s: &mut pb::Sealable| {
            let Some(version) = s
                .subject
                .as_deref()
                .and_then(|subject| self.predates(subject, born))
            else {
                return;
            };
            let tomb = pb::sealable::Value::Sealed(kronik_privacy::sealer::erased_value(version));
            if s.value.as_ref() != Some(&tomb) {
                s.value = Some(tomb);
                n += 1;
            }
        });
        n
    }

    /// [`Marks::tombstone`] over what a turn hands to its connections (M24):
    /// its frames' data and its closes' reasons.
    pub(crate) fn tombstone_connection_ops(
        &self,
        born: Born,
        ops: &mut [pb::ConnectionOp],
    ) -> usize {
        self.tombstone(born, |f| {
            kronik_proto::sealables::connection_ops_mut(ops, f);
        })
    }
}

/// What [`Marks::begin`] replaced.
pub(crate) struct Undo {
    subject: String,
    previous: Option<Mark>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(subject: &str) -> pb::Sealable {
        pb::Sealable {
            subject: Some(subject.into()),
            value: Some(pb::sealable::Value::Plain(b"personal".to_vec())),
        }
    }

    /// A value born before an erasure predates it; one born after its record
    /// was applied does not; one born while the record is pending does (the
    /// subject's rows are still there to be read); from the log, by the
    /// record's LSN, and while the record is pending every recorded value of
    /// the subject does.
    #[test]
    fn values_predate_the_erasures_after_they_were_born() {
        let mut marks = Marks::load(vec![("user:old".into(), 3, 50)], vec![]);
        let before = marks.now();
        assert_eq!(marks.predates("user:old", before), None, "erased before");
        assert_eq!(marks.predates("user:old", Born::Lsn(49)), Some(3));
        assert_eq!(marks.predates("user:old", Born::Lsn(51)), None);
        marks.begin("user:1");
        let during = marks.now();
        marks.keys_erased("user:1", 2);
        assert_eq!(marks.predates("user:1", before), Some(2));
        assert_eq!(marks.predates("user:1", during), Some(2), "pending");
        assert_eq!(marks.predates("user:1", Born::Lsn(1_000)), Some(2));
        assert_eq!(
            marks.erased_after(during).collect::<Vec<_>>(),
            [&"user:1".to_owned()]
        );
        marks.recorded("user:1", 2, 60);
        let after = marks.now();
        assert_eq!(marks.predates("user:1", before), Some(2));
        assert_eq!(marks.predates("user:1", during), Some(2));
        assert_eq!(marks.predates("user:1", after), None);
        assert_eq!(marks.predates("user:1", Born::Lsn(59)), Some(2));
        assert_eq!(marks.predates("user:1", Born::Lsn(61)), None);
        assert_eq!(marks.predates("user:2", before), None);
        assert_eq!(marks.erased_after(after).count(), 0);
    }

    /// An erasure whose record a stop kept from the log: everything the new
    /// process holds predates it until the start commits the record.
    #[test]
    fn an_unrecorded_erasure_is_pending_until_its_record_is_applied() {
        let mut marks = Marks::load(vec![], vec![("user:1".into(), 4)]);
        let early = marks.now();
        assert_eq!(marks.predates("user:1", early), Some(4));
        assert_eq!(marks.predates("user:1", Born::Lsn(u64::MAX)), Some(4));
        marks.recorded("user:1", 4, 70);
        assert_eq!(marks.predates("user:1", marks.now()), None);
        assert_eq!(marks.predates("user:1", early), Some(4));
    }

    /// The keystore refused: the mark goes, and an earlier one comes back.
    #[test]
    fn an_erasure_that_did_not_happen_leaves_no_mark() {
        let mut marks = Marks::load(vec![("user:1".into(), 1, 10)], vec![]);
        let undo = marks.begin("user:1");
        marks.undo(undo);
        assert_eq!(marks.predates("user:1", Born::Lsn(9)), Some(1));
        assert_eq!(marks.predates("user:1", marks.now()), None);
        let undo = marks.begin("user:2");
        marks.undo(undo);
        assert_eq!(marks.predates("user:2", Born::Gen(0)), None);
        assert_eq!(marks.now(), Born::Gen(3), "no erasure pending");
    }

    /// Tombstones replace only the predating values, and name the version.
    #[test]
    fn tombstones_replace_the_predating_values() {
        let mut marks = Marks::default();
        let born = marks.now();
        marks.begin("user:1");
        marks.keys_erased("user:1", 4);
        let mut values = [value("user:1"), value("user:2")];
        let n = marks.tombstone(born, |f| values.iter_mut().for_each(f));
        assert_eq!(n, 1);
        assert_eq!(
            values[0].value,
            Some(pb::sealable::Value::Sealed(
                kronik_privacy::sealer::erased_value(4)
            ))
        );
        assert_eq!(values[1], value("user:2"));
        let mut subjects = BTreeSet::new();
        let mut again = [value("user:1")];
        marks.predating_subjects(born, |f| again.iter_mut().for_each(f), &mut subjects);
        assert_eq!(subjects, ["user:1".to_owned()].into());
        assert!(marks.any_predating(born, |f| again.iter_mut().for_each(f)));
    }

    /// What a turn sends to its connections is tombstoned like the messages
    /// it sends: the data of its frames and the reasons of its closes, of a
    /// subject erased while it ran, and nothing else (M24, §6.8).
    #[test]
    fn tombstones_replace_the_predating_values_of_connection_operations() {
        let mut marks = Marks::default();
        let born = marks.now();
        marks.begin("user:1");
        marks.keys_erased("user:1", 4);
        let send = |subject: &str| pb::ConnectionOp {
            connections: vec!["c-1".into()],
            seqs: vec![0],
            op: Some(pb::connection_op::Op::Send(pb::Frame {
                kind: pb::frame::Kind::Text as i32,
                data: Some(value(subject)),
                ..Default::default()
            })),
            dropped: vec![],
        };
        let mut ops = [
            send("user:1"),
            send("user:2"),
            pb::ConnectionOp {
                connections: vec!["c-1".into()],
                seqs: vec![],
                op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
                    code: 4000,
                    reason: Some(value("user:1")),
                })),
                dropped: vec![],
            },
        ];
        assert_eq!(marks.tombstone_connection_ops(born, &mut ops), 2);
        let tomb = Some(pb::sealable::Value::Sealed(
            kronik_privacy::sealer::erased_value(4),
        ));
        let data = |op: &pb::ConnectionOp| match &op.op {
            Some(pb::connection_op::Op::Send(f)) => f.data.clone().unwrap(),
            Some(pb::connection_op::Op::Close(c)) => c.reason.clone().unwrap(),
            None => unreachable!(),
        };
        assert_eq!(data(&ops[0]).value, tomb);
        assert_eq!(data(&ops[1]), value("user:2"));
        assert_eq!(data(&ops[2]).value, tomb);
        // A turn born after the erasure's record keeps its values.
        marks.recorded("user:1", 4, 9);
        let mut later = [send("user:1")];
        assert_eq!(marks.tombstone_connection_ops(marks.now(), &mut later), 0);
    }
}

#[cfg(test)]
#[path = "erasure/node_tests.rs"]
mod node_tests;
