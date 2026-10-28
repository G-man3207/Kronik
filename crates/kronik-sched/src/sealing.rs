//! Where the node seals and unseals (docs/design/m8-privacy.md §4, §5).
//!
//! - Every record the node appends goes through [`Node::seal`]: while the
//!   mode is `on`, each tagged plain value is sealed; `off` costs one
//!   relaxed atomic load.
//! - A guest only ever sees plaintext: inputs, recorded effect results on a
//!   re-run, saved call replies and saved ingress responses are unsealed on
//!   the way in. An input of an erased subject cannot run: its turn fails
//!   with `SUBJECT_ERASED` and becomes a dead letter.

use kronik_core::error::{ApiError, ErrorCode};
use kronik_privacy::sealer::Unreadable;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use crate::node::Node;

fn is_sealed(s: Option<&pb::Sealable>) -> bool {
    matches!(
        s.and_then(|s| s.value.as_ref()),
        Some(pb::sealable::Value::Sealed(_))
    )
}

fn message_sealed(m: Option<&pb::Message>) -> bool {
    is_sealed(m.and_then(|m| m.body.as_ref()))
}

/// Whether an input holds a sealed value (no allocation).
pub(crate) fn input_sealed(input: &pb::Input) -> bool {
    use pb::input::Kind;
    match &input.kind {
        Some(Kind::Http(h)) => {
            is_sealed(h.sealed_path.as_ref())
                || is_sealed(h.sealed_query.as_ref())
                || h.params.iter().any(|p| is_sealed(p.sealed_value.as_ref()))
                || h.headers.iter().any(|h| is_sealed(h.value.as_ref()))
                || matches!(
                    h.body.as_ref().and_then(|b| b.value.as_ref()),
                    Some(pb::body::Value::Inline(s)) if is_sealed(Some(s))
                )
        }
        Some(Kind::Message(m)) => message_sealed(m.msg.as_ref()),
        Some(Kind::Timer(t)) => message_sealed(t.msg.as_ref()),
        Some(Kind::Migrate(_)) | None => false,
    }
}

impl Node {
    /// The node's sealer: the mode, the keystore and the pseudonym key.
    pub fn sealer(&self) -> &std::sync::Arc<kronik_privacy::sealer::Sealer> {
        &self.sealer
    }

    /// Seals a record before it is appended (no-op while the mode is off).
    /// Forks seal what they write to disk with it, too.
    pub fn seal(&self, record: &mut Record) -> Result<(), ApiError> {
        if !self.sealer.is_on() {
            return Ok(());
        }
        let entropy = self.env.entropy.clone();
        self.sealer
            .seal_record(
                record,
                &|b: &mut [u8]| entropy.fill(b),
                self.env.clock.wall_ms(),
            )
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("sealing: {e}")))
    }

    /// The error of a turn whose input cannot be unsealed.
    pub(crate) fn unreadable_input(e: &Unreadable) -> (ErrorCode, String) {
        match e {
            Unreadable::Erased(_) => (
                ErrorCode::SubjectErased,
                "the input belongs to an erased subject".into(),
            ),
            Unreadable::Missing { .. } => (ErrorCode::Internal, e.to_string()),
        }
    }

    /// Checks that an input can be unsealed for its guest.
    pub(crate) fn check_input(&self, input: &pb::Input) -> Result<(), Unreadable> {
        if !input_sealed(input) {
            return Ok(());
        }
        let mut probe = input.clone();
        self.sealer.unseal_input(&mut probe)
    }

    /// The input as its guest sees it: plaintext.
    pub(crate) fn guest_input(&self, input: &pb::Input) -> pb::Input {
        let mut guest = input.clone();
        if input_sealed(input) {
            // Checked by `check_input` before the turn started.
            let _ = self.sealer.unseal_input(&mut guest);
        }
        guest
    }

    /// Unseals recorded effects for a re-run in place; unreadable values
    /// stay sealed, and the guest gets what decoding them gives.
    pub(crate) fn unseal_effects(&self, effects: &mut [pb::EffectRecord]) {
        for e in effects {
            kronik_proto::sealables::effect_mut(e, &mut |s| {
                let _ = self.sealer.unseal_value(s);
            });
        }
    }

    /// Unseals a saved outcome (a call's reply, an ingress response) in
    /// place before a caller sees it.
    pub(crate) fn unseal_outcome(&self, outcome: &mut pb::Outcome) {
        kronik_proto::sealables::outcome_mut(Some(outcome), &mut |s| {
            let _ = self.sealer.unseal_value(s);
        });
    }
}
