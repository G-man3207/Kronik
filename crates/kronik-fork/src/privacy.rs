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
//! production, the diff calls it `pii-masked`, not divergent. SQL changesets
//! are binary and stay as recorded (the store opens them); SQL rows are not
//! pseudonymized in v0.1. So in a `--no-pii` fork a turn that used SQL (or
//! called a turn that did, or was sent a message by one) is masked too
//! ([`crate::ForkTurn::sql`]): the diff shows its values like a subject's
//! (hashed), and its reply and record are [`conceal_turn`]ed before any
//! caller or file sees them.

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

    /// [`ForkPrivacy::reveal`] over a turn record. SQL changesets are
    /// binary: they are unsealed (never pseudonymized), and an erased
    /// subject's stay sealed so the store skips them; the diff redacts the
    /// row values of every changeset with a subject. Returns whether any
    /// value was masked.
    pub fn reveal_turn(&self, t: &mut pb::TurnRecord) -> bool {
        let mut sql = std::mem::take(&mut t.sql_changes);
        let mut masked = false;
        kronik_proto::sealables::turn_mut(t, &mut |s| masked |= self.reveal(s));
        for c in &mut sql {
            if let Some(cs) = c.changeset.as_mut() {
                let _ = self.sealer.unseal_value(cs);
            }
        }
        t.sql_changes = sql;
        masked
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
            saw_subject: AtomicBool::new(false),
        }
    }

    /// Whether the turn read a pseudonym or an erased value.
    pub fn masked(&self) -> bool {
        self.masked.load(Ordering::Relaxed)
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
}
