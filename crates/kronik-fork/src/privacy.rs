//! What a fork may see of production's user data (docs/design/m8-privacy.md
//! §5, §9).
//!
//! A fork reads production through its recordings: root inputs, recorded
//! effect results and state. [`ForkPrivacy::reveal`] turns one recorded
//! value into what the fork's guests and its diff see:
//!
//! - in an ordinary fork, the plaintext (sealed values are unsealed);
//! - in a `--no-pii` fork, every value with a subject becomes its pseudonym
//!   (`pii:` + 12 hex), so equal values stay equal and nothing real reaches
//!   the guests or the diff;
//! - values of an erased subject become `[erased]` in both.
//!
//! A fork turn that read such a value is *masked*: if it differs from
//! production, the diff calls it `pii-masked`, not divergent. A `--no-pii`
//! fork pseudonymizes text and blob cells of a subject-tagged SQL changeset
//! before the store applies it, so the actor database the guest queries does
//! not hold that plaintext. A turn that used SQL (or called a turn that did,
//! or was sent a message by one) is still masked
//! ([`crate::ForkTurn::sql`]): the diff shows its values like a subject's
//! (hashed), and its reply and record are [`conceal_turn`]ed before any
//! caller or file sees them. A value copied into a name, key or URL is not
//! tracked.

/// What every value of a `--no-pii` fork turn that used SQL reads as
/// outside the fork's memory (replies, fork log, isolated trees).
pub const SQL_CONCEALED: &str = "[sql]";

/// Replaces every value of `t` (input, effects, writes, messages, timers,
/// SQL changes, output) and its outcome message with [`SQL_CONCEALED`].
pub fn conceal_turn(t: &mut pb::TurnRecord) {
    kronik_proto::sealables::turn_mut(t, &mut |s| {
        s.value = Some(pb::sealable::Value::Plain(SQL_CONCEALED.into()));
    });
    if let Some(o) = t.outcome.as_mut().filter(|o| !o.message.is_empty()) {
        o.message = SQL_CONCEALED.into();
    }
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kronik_core::ids::{ActorRef, Lsn};
use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::log::v1 as pb;
use kronik_runtime::StateView;
use kronik_store::Store;

use crate::taint::Taint;

/// A fork's view of production values.
#[derive(Clone, Debug)]
pub struct ForkPrivacy {
    pub sealer: Arc<Sealer>,
    /// Set for `--no-pii` forks.
    pub no_pii: bool,
}

/// Whether `v` has the shape of a pseudonym (`pii:` + 12 lowercase hex).
/// Only a value the fork itself wrote may be taken for one (a revealed
/// record's, or a guest's): a production value of that shape is still
/// production data and is pseudonymized like any other (issue #69).
fn is_pseudonym(v: &[u8]) -> bool {
    v.len() == 16
        && v.starts_with(b"pii:")
        && v[4..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

impl ForkPrivacy {
    /// No keystore, no pseudonyms: values are shown as recorded.
    pub fn plain() -> ForkPrivacy {
        ForkPrivacy {
            sealer: Arc::new(Sealer::plain()),
            no_pii: false,
        }
    }

    /// Replaces a recorded production value in place with what the fork
    /// sees. Returns whether it was masked (pseudonymized or erased). Values
    /// this keystore cannot open stay as they are. In a `--no-pii` fork every
    /// tagged value becomes its pseudonym, also one that already has the
    /// shape of a pseudonym: production data is never taken for the fork's
    /// own (issue #69).
    pub fn reveal(&self, s: &mut pb::Sealable) -> bool {
        self.reveal_as(s, false)
    }

    /// [`ForkPrivacy::reveal`] of a value the fork itself wrote (a revealed
    /// record or a guest did): one that already is a pseudonym stays as it
    /// is, so equal values stay equal when they are read back.
    pub fn reveal_written(&self, s: &mut pb::Sealable) -> bool {
        self.reveal_as(s, true)
    }

    fn reveal_as(&self, s: &mut pb::Sealable, written: bool) -> bool {
        let (shown, masked) = match self.sealer.open(s) {
            Opened::Value(v) => match (&s.subject, self.no_pii) {
                (Some(_), true) if written && is_pseudonym(&v) => (v.into_owned(), true),
                (Some(subject), true) => match self.sealer.pseudonym(subject, &v) {
                    Some(p) => (p.into_bytes(), true),
                    None => (b"[pii]".to_vec(), true),
                },
                _ => (v.into_owned(), false),
            },
            Opened::Erased { .. } => (b"[erased]".to_vec(), true),
            Opened::Unreadable { .. } => return false,
        };
        s.value = Some(pb::sealable::Value::Plain(shown));
        masked
    }

    /// Whether `s` was erased: its subject's key is gone, so the recorded
    /// value cannot be re-opened by anyone (ADR 0108, amendment on erased
    /// requests). An identity replay cannot verify what the guest did with
    /// it, only compare it with the recording (S-16, ADR 0109).
    pub fn opens_erased(&self, s: &pb::Sealable) -> bool {
        matches!(self.sealer.open(s), Opened::Erased { .. })
    }

    /// [`ForkPrivacy::reveal`] over a turn record. SQL changesets are
    /// unsealed so the store can apply them. In a `--no-pii` fork a
    /// subject-tagged changeset's text and blob cells are pseudonymized
    /// first (integer and real values, and the `_subject` column, stay).
    /// An erased subject's changeset stays sealed so the store skips it,
    /// and so does an erased state value: the store keeps it sealed, and a
    /// fork turn that reads it gets nothing and is marked as one that met
    /// erased data ([`ForkState`]; issue #49) instead of reading the bytes
    /// `[erased]` as if they were the value. Returns whether any value was
    /// masked.
    pub fn reveal_turn(&self, t: &mut pb::TurnRecord) -> bool {
        let mut sql = std::mem::take(&mut t.sql_changes);
        let mut writes = std::mem::take(&mut t.writes);
        let mut masked = false;
        kronik_proto::sealables::turn_mut(t, &mut |s| masked |= self.reveal(s));
        for v in writes.iter_mut().filter_map(|w| w.value.as_mut()) {
            if self.opens_erased(v) {
                masked = true;
            } else {
                masked |= self.reveal(v);
            }
        }
        for c in &mut sql {
            if let Some(cs) = c.changeset.as_mut() {
                self.reveal_changeset(cs);
            }
        }
        t.writes = writes;
        t.sql_changes = sql;
        masked
    }

    /// Unseals one SQL changeset. On the `--no-pii` path, replaces text and
    /// blob cells of a subject-tagged changeset with their pseudonym before
    /// the fork store applies the bytes. An erased or unreadable changeset
    /// is left sealed. A rewrite that fails does not leave plaintext for
    /// the store to apply.
    fn reveal_changeset(&self, cs: &mut pb::Sealable) {
        let subject = cs.subject.clone();
        let _ = self.sealer.unseal_value(cs);
        if !self.no_pii {
            return;
        }
        let Some(subject) = subject else {
            return;
        };
        let Some(pb::sealable::Value::Plain(bytes)) = cs.value.as_mut() else {
            return;
        };
        if bytes.is_empty() {
            return;
        }
        match kronik_store::sql::pseudonymize_changeset(bytes, &subject, |value| {
            Self::sql_cell(&self.sealer, &subject, value)
        }) {
            Ok(rewritten) => *bytes = rewritten,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "refusing to apply a subject-tagged SQL changeset that could not be pseudonymized"
                );
                // Not a changeset: apply fails closed instead of writing plaintext.
                bytes.clear();
                bytes.push(0);
            }
        }
    }

    /// The pseudonym of one SQL cell of production's (a revealed changeset,
    /// a snapshot row), or `[pii]` when this sealer has no pseudonym key.
    /// Every cell is replaced, also one that has the shape of a pseudonym
    /// (issue #69): each is rewritten once, before the fork applies it.
    pub(crate) fn sql_cell(sealer: &Sealer, subject: &str, value: &[u8]) -> Vec<u8> {
        match sealer.pseudonym(subject, value) {
            Some(pseudonym) => pseudonym.into_bytes(),
            None => b"[pii]".to_vec(),
        }
    }

    /// Over an input. Returns whether any value was masked.
    pub fn reveal_input(&self, i: &mut pb::Input) -> bool {
        let mut masked = false;
        kronik_proto::sealables::input_mut(Some(i), &mut |s| masked |= self.reveal(s));
        masked
    }

    /// Over an effect record. Returns whether any value was masked.
    pub fn reveal_effect(&self, e: &mut pb::EffectRecord) -> bool {
        let mut masked = false;
        kronik_proto::sealables::effect_mut(e, &mut |s| masked |= self.reveal(s));
        masked
    }
}

/// Whether an input carries a value with a subject.
pub fn tagged_input(input: Option<&pb::Input>) -> bool {
    let mut tagged = false;
    let mut copy = input.cloned();
    kronik_proto::sealables::input_mut(copy.as_mut(), &mut |s| tagged |= s.subject.is_some());
    tagged
}

/// A fork turn's state: production's (or the fork's) committed values, as
/// [`ForkPrivacy::reveal`] shows them; remembers whether a read was masked,
/// and whether it read state the replay could not verify after an erasure.
pub struct ForkState {
    store: Arc<Store>,
    actor: ActorRef,
    privacy: ForkPrivacy,
    /// Values written at or below this LSN are the base snapshot's, that is
    /// production's; the others the replay wrote (a revealed record, a fork
    /// turn).
    base_lsn: Lsn,
    /// Where the store holds state the replay could not verify, and the
    /// turn's production position (ADR 0109).
    taint: Option<(Arc<Mutex<Taint>>, Lsn)>,
    masked: AtomicBool,
    /// The turn read a state value whose subject was erased (S-16), or one
    /// that erased data shaped ([`Taint`]).
    erased: AtomicBool,
    /// The turn read a state value with a subject (M12: the model
    /// simulator then declines).
    saw_subject: AtomicBool,
}

impl ForkState {
    pub fn new(store: Arc<Store>, actor: ActorRef, privacy: ForkPrivacy) -> ForkState {
        ForkState {
            store,
            actor,
            privacy,
            base_lsn: 0,
            taint: None,
            masked: AtomicBool::new(false),
            erased: AtomicBool::new(false),
            saw_subject: AtomicBool::new(false),
        }
    }

    /// The store continues the base snapshot at `lsn`: values at or below
    /// it are production's own, never taken for the fork's pseudonyms.
    pub fn with_base(mut self, lsn: Lsn) -> ForkState {
        self.base_lsn = lsn;
        self
    }

    /// The turn at production position `at` reads state that `taint`
    /// says may differ from production's: a read of it marks the turn.
    pub fn with_taint(mut self, taint: Arc<Mutex<Taint>>, at: Lsn) -> ForkState {
        self.taint = Some((taint, at));
        self
    }

    /// Whether the turn read a pseudonym or an erased value.
    pub fn masked(&self) -> bool {
        self.masked.load(Ordering::Relaxed)
    }

    /// Whether the turn read an erased state value, or state that erased
    /// data shaped.
    pub fn erased(&self) -> bool {
        self.erased.load(Ordering::Relaxed)
    }

    /// Whether the turn read a state value with a subject.
    pub fn saw_subject(&self) -> bool {
        self.saw_subject.load(Ordering::Relaxed)
    }

    fn actor_name(&self) -> String {
        format!("{}/{}", self.actor.kind, self.actor.key)
    }

    /// Marks the turn when `unverified` says what it reads may differ.
    fn check(&self, unverified: impl FnOnce(&Taint, &str, Lsn) -> bool) {
        if let Some((taint, at)) = &self.taint {
            let taint = taint.lock().unwrap_or_else(|e| e.into_inner());
            if unverified(&taint, &self.actor_name(), *at) {
                self.erased.store(true, Ordering::Relaxed);
            }
        }
    }
}

impl StateView for ForkState {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.check(|t, actor, at| t.key(actor, key, at));
        let value = self
            .store
            .db()
            .kv_get_written(&self.actor.kind, &self.actor.key, key)
            .map_err(|e| e.to_string())?;
        let Some((mut value, written)) = value else {
            return Ok(None);
        };
        if value.subject.is_some() {
            self.saw_subject.store(true, Ordering::Relaxed);
        }
        // An erased value reads as absent (docs/design/m8-privacy.md §5),
        // and the replay cannot verify a turn that read it (ADR 0109).
        if matches!(self.privacy.sealer.open(&value), Opened::Erased { .. }) {
            self.masked.store(true, Ordering::Relaxed);
            self.erased.store(true, Ordering::Relaxed);
            return Ok(None);
        }
        let masked = if written > self.base_lsn {
            self.privacy.reveal_written(&mut value)
        } else {
            self.privacy.reveal(&mut value)
        };
        if masked {
            self.masked.store(true, Ordering::Relaxed);
        }
        match value.value {
            Some(pb::sealable::Value::Plain(b)) => Ok(Some(b)),
            _ => Err(format!("state value {key:?} cannot be unsealed")),
        }
    }

    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        self.check(|t, actor, at| t.prefix(actor, prefix, at));
        self.store
            .db()
            .kv_keys(&self.actor.kind, &self.actor.key, prefix)
            .map_err(|e| e.to_string())
    }

    fn timer_pending(&self, id: u64) -> Result<bool, String> {
        self.check(|t, actor, at| t.timer(actor, id, at));
        self.store
            .db()
            .timer_pending(&self.actor.kind, &self.actor.key, id)
            .map_err(|e| e.to_string())
    }

    /// M24: the connections table of the state the replay runs on
    /// (production's at the input in isolated replay, the fork's own in
    /// continuous replay).
    fn connection(&self, id: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        kronik_sched::host::connection_view(&self.store, &self.actor, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_recognized() {
        assert!(is_pseudonym(b"pii:0123456789ab"));
        assert!(!is_pseudonym(b"pii:0123456789AB"));
        assert!(!is_pseudonym(b"alice"));
    }

    fn no_pii() -> ForkPrivacy {
        let master = kronik_privacy::MasterKey::from_bytes([9; 32]).unwrap();
        ForkPrivacy {
            sealer: Arc::new(
                Sealer::plain()
                    .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master).unwrap()),
            ),
            no_pii: true,
        }
    }

    const SHAPED: &[u8] = b"pii:0123456789ab";

    /// Issue #69: a production value that has the shape of a pseudonym is
    /// still production data. A `--no-pii` fork replaces it like any other
    /// tagged value, in records and in SQL cells; only what the fork itself
    /// wrote is read back as it is.
    #[test]
    fn production_values_shaped_like_pseudonyms_are_replaced() {
        let p = no_pii();
        let tagged = || pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Plain(SHAPED.to_vec())),
        };
        let pseudonym = p.sealer.pseudonym("user:1", SHAPED).unwrap();
        assert_ne!(pseudonym.as_bytes(), SHAPED);
        let mut v = tagged();
        assert!(p.reveal(&mut v));
        assert_eq!(
            v.value,
            Some(pb::sealable::Value::Plain(pseudonym.clone().into_bytes()))
        );
        let mut v = tagged();
        assert!(p.reveal_written(&mut v));
        assert_eq!(v.value, Some(pb::sealable::Value::Plain(SHAPED.to_vec())));
        assert_eq!(
            ForkPrivacy::sql_cell(&p.sealer, "user:1", SHAPED),
            pseudonym.into_bytes()
        );
    }

    /// Issue #69 through a fork turn's state reads: a value the base
    /// snapshot holds (written at or below its LSN) is production's and is
    /// replaced; one the replay wrote is the fork's and is read back as is.
    #[test]
    fn state_reads_replace_production_values_by_provenance() {
        use kronik_log::{Committed, Position};
        use kronik_proto::Record;
        let store = crate::replay::memory_store().unwrap();
        store
            .apply(&[Committed {
                lsn: 1,
                pos: Position {
                    segment: 0,
                    offset: 0,
                },
                record: Record::TurnRecord(pb::TurnRecord {
                    actor: Some(pb::ActorRef {
                        kind: "counter".into(),
                        key: "a".into(),
                    }),
                    causal_key: Some(kronik_core::causal::root("r1".to_owned())),
                    input: Some(pb::Input {
                        kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
                    }),
                    outcome: Some(pb::Outcome {
                        kind: pb::OutcomeKind::Committed as i32,
                        ..Default::default()
                    }),
                    writes: vec![pb::StateWrite {
                        key: "k".into(),
                        op: pb::StateOp::Set as i32,
                        value: Some(pb::Sealable {
                            subject: Some("user:1".into()),
                            value: Some(pb::sealable::Value::Plain(SHAPED.to_vec())),
                        }),
                    }],
                    ..Default::default()
                }),
            }])
            .unwrap();
        let p = no_pii();
        let actor = ActorRef::parse("counter/a").unwrap();
        let read = |base: Lsn| {
            let state = ForkState::new(store.clone(), actor.clone(), p.clone()).with_base(base);
            let v = state.get("k").unwrap().unwrap();
            assert!(state.masked());
            v
        };
        let pseudonym = p.sealer.pseudonym("user:1", SHAPED).unwrap();
        assert_eq!(read(1), pseudonym.into_bytes(), "the snapshot's value");
        assert_eq!(read(0), SHAPED, "a value the replay wrote");
    }

    /// Issue #49: an erased state value the replayed log wrote stays sealed
    /// in the fork's store, reads as absent and marks the turn that read it
    /// (before, it was the 8 bytes `[erased]`, read as the value).
    #[test]
    fn an_erased_state_value_stays_sealed_and_reads_as_absent() {
        let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
        let keystore = kronik_privacy::keystore::Keystore::open_memory(&master).unwrap();
        let sealer = Arc::new(Sealer::new(Arc::new(keystore)));
        sealer.set_on(true);
        let privacy = ForkPrivacy {
            sealer: sealer.clone(),
            no_pii: false,
        };
        let write = |key: &str, value: &[u8]| {
            let mut v = pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Plain(value.to_vec())),
            };
            sealer
                .seal_value(&mut v, &|b: &mut [u8]| b.fill(3), 1)
                .unwrap();
            pb::StateWrite {
                key: key.into(),
                op: pb::StateOp::Set as i32,
                value: Some(v),
            }
        };
        let mut t = pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "counter".into(),
                key: "a".into(),
            }),
            causal_key: Some(kronik_core::causal::root("r1".to_owned())),
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
            }),
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            writes: vec![write("s", b"personal")],
            ..Default::default()
        };
        sealer.erase("user:1", 2).unwrap();
        assert!(privacy.reveal_turn(&mut t));
        assert!(
            matches!(
                t.writes[0].value.as_ref().and_then(|v| v.value.as_ref()),
                Some(pb::sealable::Value::Sealed(_))
            ),
            "an erased state value must stay sealed: {:?}",
            t.writes[0]
        );
        let store = crate::replay::memory_store().unwrap();
        store
            .apply(&[kronik_log::Committed {
                lsn: 1,
                pos: kronik_log::Position {
                    segment: 0,
                    offset: 0,
                },
                record: kronik_proto::Record::TurnRecord(t),
            }])
            .unwrap();
        let actor = ActorRef::parse("counter/a").unwrap();
        let state = ForkState::new(store.clone(), actor.clone(), privacy.clone());
        assert_eq!(
            state.get("s").unwrap(),
            None,
            "an erased value reads as absent"
        );
        assert!(state.erased() && state.masked());
    }

    /// Issue #29: a read of state the taint marks (here `n`, from position
    /// 10 on) marks the turn as one that met erased data, whatever it reads;
    /// a turn before that position is not marked.
    #[test]
    fn a_read_of_unverified_state_marks_the_turn() {
        let store = crate::replay::memory_store().unwrap();
        let privacy = ForkPrivacy::plain();
        let actor = ActorRef::parse("counter/a").unwrap();
        let taint = Arc::new(Mutex::new(Taint::default()));
        taint.lock().unwrap().missing_turn(
            &pb::TurnRecord {
                actor: Some(pb::ActorRef {
                    kind: "counter".into(),
                    key: "a".into(),
                }),
                outcome: Some(pb::Outcome {
                    kind: pb::OutcomeKind::Committed as i32,
                    ..Default::default()
                }),
                writes: vec![pb::StateWrite {
                    key: "n".into(),
                    op: pb::StateOp::Set as i32,
                    value: None,
                }],
                ..Default::default()
            },
            10,
        );
        let at = |pos: Lsn| {
            ForkState::new(store.clone(), actor.clone(), privacy.clone())
                .with_taint(taint.clone(), pos)
        };
        let before = at(9);
        assert_eq!(before.get("n").unwrap(), None);
        assert!(!before.erased());
        let after = at(10);
        assert_eq!(after.get("n").unwrap(), None);
        assert!(after.erased() && !after.masked());
        let listing = at(11);
        listing.keys("").unwrap();
        assert!(listing.erased());
    }

    #[test]
    fn plain_forks_see_recorded_values() {
        let p = ForkPrivacy::plain();
        let mut v = pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Plain(b"alice".to_vec())),
        };
        assert!(!p.reveal(&mut v));
        assert_eq!(v.value, Some(pb::sealable::Value::Plain(b"alice".to_vec())));
    }

    /// A `--no-pii` replay's actor database must not hold production text or
    /// blob values from a subject-tagged SQL row. The database itself is
    /// inspected, not only a redacted reply. Integer and real cells are left
    /// as production recorded them (m8-privacy §9, #70): this test proves
    /// text and blob cells only.
    #[test]
    fn no_pii_replay_actor_database_has_no_subject_text_or_blob_plaintext() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        use kronik_log::{Committed, Position};
        use kronik_privacy::MasterKey;
        use kronik_privacy::keystore::Pseudonyms;
        use kronik_proto::Record;
        use kronik_store::sql::{Limits, MemOpener, SqlActor, TurnOpts};

        const ROW: &str = "ROW-u1-5e2c";
        const NEXT: &str = "ROW-u1-5e2c-next";
        const BLOB: &[u8] = b"BLOB-u1-5e2c";
        const SCHEMA: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
             payload BLOB, _subject TEXT DEFAULT (kronik_subject()))";

        let mut live = SqlActor::open(&MemOpener, "notes/n", Limits::default()).unwrap();
        let opts = |seed: u8, migrate: bool| TurnOpts {
            seed: [seed; 32],
            time_ms: 1_000,
            default_subject: Some("user:1".into()),
            migrate,
            sql_budget: 50_000_000,
            max_bytes: 0,
        };
        live.begin_turn(&opts(1, true)).unwrap();
        live.query(SCHEMA, &[]).unwrap();
        let schema_turn = live.end_turn(true).unwrap();
        live.apply(&schema_turn, 1, &BTreeSet::new()).unwrap();
        let blob = BLOB.iter().map(|b| format!("{b:02x}")).collect::<String>();
        live.begin_turn(&opts(2, false)).unwrap();
        live.query(
            &format!("INSERT INTO notes(body, payload) VALUES ('{ROW}', x'{blob}')"),
            &[],
        )
        .unwrap();
        live.query(
            &format!("INSERT INTO notes(body, payload) VALUES ('{ROW}', x'{blob}')"),
            &[],
        )
        .unwrap();
        live.query(
            &format!("UPDATE notes SET body = '{NEXT}' WHERE id = 1"),
            &[],
        )
        .unwrap();
        let dml = live.end_turn(true).unwrap();
        assert_eq!(dml.changesets.len(), 1);

        let replay = |no_pii: bool| {
            let master = MasterKey::from_bytes([9; 32]).unwrap();
            let sealer =
                Arc::new(Sealer::plain().with_pseudonyms(Pseudonyms::new(&master).unwrap()));
            let turn =
                |lsn: u64, ddl: Vec<String>, changes: Vec<(Option<String>, Vec<u8>)>| Committed {
                    lsn,
                    pos: Position {
                        segment: 0,
                        offset: 0,
                    },
                    record: Record::TurnRecord(pb::TurnRecord {
                        actor: Some(pb::ActorRef {
                            kind: "notes".into(),
                            key: "n".into(),
                        }),
                        causal_key: Some(kronik_core::causal::root(format!("r{lsn}"))),
                        input: Some(pb::Input {
                            kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
                        }),
                        outcome: Some(pb::Outcome {
                            kind: pb::OutcomeKind::Committed as i32,
                            ..Default::default()
                        }),
                        sql_schema: ddl
                            .into_iter()
                            .map(|statement| pb::SqlSchemaChange { statement })
                            .collect(),
                        sql_changes: changes
                            .into_iter()
                            .map(|(subject, cs)| pb::SqlChangeset {
                                changeset: Some(pb::Sealable {
                                    subject,
                                    value: Some(pb::sealable::Value::Plain(cs)),
                                }),
                            })
                            .collect(),
                        ..Default::default()
                    }),
                };
            let records = vec![
                turn(1, vec![SCHEMA.into()], Vec::new()),
                turn(2, Vec::new(), dml.changesets.clone()),
            ];
            let mut index = crate::ProductionIndex::from_records(records, 0, 2);
            index.reveal(&ForkPrivacy {
                sealer: sealer.clone(),
                no_pii,
            });
            let store = crate::replay::cursor(&index).unwrap();
            crate::replay::advance(&store, &index, 2).unwrap();
            (store, sealer)
        };

        let (masked, sealer) = replay(true);
        let bytes = actor_image(&masked);
        for needle in [ROW.as_bytes(), NEXT.as_bytes(), BLOB] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "actor database contains plaintext {}",
                String::from_utf8_lossy(needle)
            );
        }
        let rows = actor_rows(&masked);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].0, 1, "integer primary key was rewritten");
        assert_eq!(rows[1].0, 2, "integer primary key was rewritten");
        assert_eq!(rows[0].3, "user:1");
        assert_eq!(rows[1].3, "user:1");
        let updated = sealer.pseudonym("user:1", NEXT.as_bytes()).unwrap();
        let same = sealer.pseudonym("user:1", ROW.as_bytes()).unwrap();
        let blob = sealer.pseudonym("user:1", BLOB).unwrap().into_bytes();
        assert_eq!(rows[0].1, updated);
        assert_eq!(rows[1].1, same, "equal values must stay equal");
        assert_eq!(rows[0].2, blob);
        assert_eq!(rows[1].2, blob, "equal blobs must stay equal");

        let (plain, _) = replay(false);
        let plain_bytes = actor_image(&plain);
        assert!(
            plain_bytes
                .windows(NEXT.len())
                .any(|w| w == NEXT.as_bytes()),
            "ordinary fork lost the production row, so the scan cannot see plaintext"
        );
    }

    /// ADR 0005 §6 in a fork. One production turn on behalf of `user:1`
    /// wrote a row of its own and one that names `user:2`; each changeset
    /// of its record is sealed under its own subject. A `--no-pii` replay
    /// gives each row the pseudonyms of its own subject. Once `user:2` is
    /// erased, its changeset stays sealed and its row is not in the fork,
    /// with or without `--no-pii`, while `user:1`'s is. Filing both rows
    /// under the turn's default subject would give `user:2`'s row
    /// `user:1`'s pseudonyms and keep it after the erasure.
    #[test]
    fn a_replay_treats_each_row_of_a_turn_under_its_own_subject() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        use kronik_log::{Committed, Position};
        use kronik_privacy::MasterKey;
        use kronik_privacy::keystore::{Keystore, Pseudonyms};
        use kronik_proto::Record;
        use kronik_store::sql::{Limits, MemOpener, SqlActor, TurnOpts};

        const MINE: &str = "ROW-u1-3b7d";
        const THEIRS: &str = "ROW-u2-8e05";
        const SCHEMA: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
             payload BLOB, _subject TEXT DEFAULT (kronik_subject()))";

        let mut live = SqlActor::open(&MemOpener, "notes/n", Limits::default()).unwrap();
        let opts = |seed: u8, subject: Option<&str>, migrate: bool| TurnOpts {
            seed: [seed; 32],
            time_ms: 1_000,
            default_subject: subject.map(str::to_owned),
            migrate,
            sql_budget: 50_000_000,
            max_bytes: 0,
        };
        live.begin_turn(&opts(1, None, true)).unwrap();
        live.query(SCHEMA, &[]).unwrap();
        let schema_turn = live.end_turn(true).unwrap();
        live.apply(&schema_turn, 1, &BTreeSet::new()).unwrap();
        live.begin_turn(&opts(2, Some("user:1"), false)).unwrap();
        live.query(
            &format!("INSERT INTO notes(body, payload) VALUES ('{MINE}', x'01')"),
            &[],
        )
        .unwrap();
        live.query(
            &format!(
                "INSERT INTO notes(body, payload, _subject) VALUES ('{THEIRS}', x'02', 'user:2')"
            ),
            &[],
        )
        .unwrap();
        let dml = live.end_turn(true).unwrap();

        let master = MasterKey::from_bytes([9; 32]).unwrap();
        let sealer = Arc::new(
            Sealer::new(Arc::new(Keystore::open_memory(&master).unwrap()))
                .with_pseudonyms(Pseudonyms::new(&master).unwrap()),
        );
        sealer.set_on(true);
        // As the node records them: each changeset sealed under its subject.
        let sealed: Vec<pb::SqlChangeset> = dml
            .changesets
            .iter()
            .map(|(subject, cs)| {
                let mut value = pb::Sealable {
                    subject: subject.clone(),
                    value: Some(pb::sealable::Value::Plain(cs.clone())),
                };
                sealer
                    .seal_value(&mut value, &|b: &mut [u8]| b.fill(3), 2)
                    .unwrap();
                pb::SqlChangeset {
                    changeset: Some(value),
                }
            })
            .collect();
        let turn = |lsn: u64, ddl: &[String], sql_changes: Vec<pb::SqlChangeset>| Committed {
            lsn,
            pos: Position {
                segment: 0,
                offset: 0,
            },
            record: Record::TurnRecord(pb::TurnRecord {
                actor: Some(pb::ActorRef {
                    kind: "notes".into(),
                    key: "n".into(),
                }),
                causal_key: Some(kronik_core::causal::root(format!("r{lsn}"))),
                input: Some(pb::Input {
                    kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
                }),
                outcome: Some(pb::Outcome {
                    kind: pb::OutcomeKind::Committed as i32,
                    ..Default::default()
                }),
                sql_schema: ddl
                    .iter()
                    .map(|statement| pb::SqlSchemaChange {
                        statement: statement.clone(),
                    })
                    .collect(),
                sql_changes,
                ..Default::default()
            }),
        };
        let replay = |no_pii: bool| {
            let records = vec![
                turn(1, &schema_turn.ddl, Vec::new()),
                turn(2, &[], sealed.clone()),
            ];
            let mut index = crate::ProductionIndex::from_records(records, 0, 2);
            index.reveal(&ForkPrivacy {
                sealer: sealer.clone(),
                no_pii,
            });
            let store = crate::replay::cursor(&index).unwrap();
            crate::replay::advance(&store, &index, 2).unwrap();
            store
        };
        let pseudonym = |subject: &str, value: &[u8]| sealer.pseudonym(subject, value).unwrap();
        let mine = (
            1,
            pseudonym("user:1", MINE.as_bytes()),
            pseudonym("user:1", &[1]).into_bytes(),
            "user:1".to_owned(),
        );

        let masked = replay(true);
        assert_eq!(
            actor_rows(&masked),
            [
                mine.clone(),
                (
                    2,
                    pseudonym("user:2", THEIRS.as_bytes()),
                    pseudonym("user:2", &[2]).into_bytes(),
                    "user:2".to_owned(),
                ),
            ],
            "each row carries its own subject's pseudonyms"
        );
        let image = actor_image(&masked);
        for needle in [MINE, THEIRS] {
            assert!(
                !image.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "the fork's actor database holds {needle}"
            );
        }

        sealer.erase("user:2", 3).unwrap();
        assert_eq!(
            actor_rows(&replay(true)),
            [mine],
            "a --no-pii fork after the erasure"
        );
        assert_eq!(
            actor_rows(&replay(false)),
            [(1, MINE.to_owned(), vec![1], "user:1".to_owned())],
            "an ordinary fork after the erasure"
        );
    }

    fn actor_image(store: &kronik_store::Store) -> Vec<u8> {
        let db = store.sql.get("notes/n").unwrap();
        let actor = db.lock().unwrap();
        actor.set_host();
        let file = tempfile::NamedTempFile::new().unwrap();
        actor
            .conn
            .backup(
                rusqlite::MAIN_DB,
                file.path(),
                None::<fn(rusqlite::backup::Progress)>,
            )
            .unwrap();
        std::fs::read(file.path()).unwrap()
    }

    fn actor_rows(store: &kronik_store::Store) -> Vec<(i64, String, Vec<u8>, String)> {
        let db = store.sql.get("notes/n").unwrap();
        let actor = db.lock().unwrap();
        actor.set_host();
        let mut st = actor
            .conn
            .prepare("SELECT id, body, payload, _subject FROM notes ORDER BY id")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}
