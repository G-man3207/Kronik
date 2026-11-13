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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kronik_core::ids::ActorRef;
use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::log::v1 as pb;
use kronik_runtime::StateView;
use kronik_store::Store;

/// A fork's view of production values.
#[derive(Clone, Debug)]
pub struct ForkPrivacy {
    pub sealer: Arc<Sealer>,
    /// Set for `--no-pii` forks.
    pub no_pii: bool,
}

/// Whether `v` already is a pseudonym (`pii:` + 12 lowercase hex): state
/// written by a revealed production record is not pseudonymized twice.
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

    /// Replaces a recorded value in place with what the fork sees. Returns
    /// whether it was masked (pseudonymized or erased). Values this keystore
    /// cannot open stay as they are.
    pub fn reveal(&self, s: &mut pb::Sealable) -> bool {
        let (shown, masked) = match self.sealer.open(s) {
            Opened::Value(v) => match (&s.subject, self.no_pii) {
                (Some(subject), true) if !is_pseudonym(&v) => {
                    match self.sealer.pseudonym(subject, &v) {
                        Some(p) => (p.into_bytes(), true),
                        None => (b"[pii]".to_vec(), true),
                    }
                }
                (Some(_), true) => (v.into_owned(), true),
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
    /// An erased subject's changeset stays sealed so the store skips it.
    /// Returns whether any value was masked.
    pub fn reveal_turn(&self, t: &mut pb::TurnRecord) -> bool {
        let mut sql = std::mem::take(&mut t.sql_changes);
        let mut masked = false;
        kronik_proto::sealables::turn_mut(t, &mut |s| masked |= self.reveal(s));
        for c in &mut sql {
            if let Some(cs) = c.changeset.as_mut() {
                self.reveal_changeset(cs);
            }
        }
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

    /// The pseudonym of one SQL cell, or `[pii]` when this sealer has no
    /// pseudonym key. A value that is already a pseudonym is left as it is.
    pub(crate) fn sql_cell(sealer: &Sealer, subject: &str, value: &[u8]) -> Vec<u8> {
        if is_pseudonym(value) {
            return value.to_vec();
        }
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
/// [`ForkPrivacy::reveal`] shows them; remembers whether a read was masked.
pub struct ForkState {
    store: Arc<Store>,
    actor: ActorRef,
    privacy: ForkPrivacy,
    masked: AtomicBool,
    /// The turn read a state value whose subject was erased (S-16).
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
            masked: AtomicBool::new(false),
            erased: AtomicBool::new(false),
            saw_subject: AtomicBool::new(false),
        }
    }

    /// Whether the turn read a pseudonym or an erased value.
    pub fn masked(&self) -> bool {
        self.masked.load(Ordering::Relaxed)
    }

    /// Whether the turn read an erased state value.
    pub fn erased(&self) -> bool {
        self.erased.load(Ordering::Relaxed)
    }

    /// Whether the turn read a state value with a subject.
    pub fn saw_subject(&self) -> bool {
        self.saw_subject.load(Ordering::Relaxed)
    }
}

impl StateView for ForkState {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let value = self
            .store
            .db()
            .kv_get_sealable(&self.actor.kind, &self.actor.key, key)
            .map_err(|e| e.to_string())?;
        let Some(mut value) = value else {
            return Ok(None);
        };
        if value.subject.is_some() {
            self.saw_subject.store(true, Ordering::Relaxed);
        }
        if matches!(self.privacy.sealer.open(&value), Opened::Erased { .. }) {
            self.masked.store(true, Ordering::Relaxed);
            self.erased.store(true, Ordering::Relaxed);
            return Ok(None);
        }
        if self.privacy.reveal(&mut value) {
            self.masked.store(true, Ordering::Relaxed);
        }
        match value.value {
            Some(pb::sealable::Value::Plain(b)) => Ok(Some(b)),
            _ => Err(format!("state value {key:?} cannot be unsealed")),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_recognized() {
        assert!(is_pseudonym(b"pii:0123456789ab"));
        assert!(!is_pseudonym(b"pii:0123456789AB"));
        assert!(!is_pseudonym(b"alice"));
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

    /// A `--no-pii` replay's actor database must not hold production plaintext
    /// from a subject-tagged SQL row. The database itself is inspected, not
    /// only a redacted reply.
    #[test]
    fn no_pii_replay_actor_database_has_no_subject_plaintext() {
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
