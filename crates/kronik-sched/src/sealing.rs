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
use kronik_core::sync::lock;
use kronik_privacy::sealer::Unreadable;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use crate::erasure::Born;
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

fn http_sealed(h: &pb::HttpInput) -> bool {
    is_sealed(h.sealed_path.as_ref())
        || is_sealed(h.sealed_query.as_ref())
        || h.params.iter().any(|p| is_sealed(p.sealed_value.as_ref()))
        || h.headers.iter().any(|h| is_sealed(h.value.as_ref()))
        || matches!(
            h.body.as_ref().and_then(|b| b.value.as_ref()),
            Some(pb::body::Value::Inline(s)) if is_sealed(Some(s))
        )
}

/// Whether an input holds a sealed value (no allocation).
pub(crate) fn input_sealed(input: &pb::Input) -> bool {
    use pb::connection_input::Event;
    use pb::input::Kind;
    match &input.kind {
        Some(Kind::Http(h)) => http_sealed(h),
        Some(Kind::Message(m)) => message_sealed(m.msg.as_ref()),
        Some(Kind::Timer(t)) => message_sealed(t.msg.as_ref()),
        Some(Kind::Connection(c)) => match &c.event {
            Some(Event::Open(o)) => o.request.as_ref().is_some_and(http_sealed),
            Some(Event::Frame(f)) => is_sealed(f.frame.as_ref().and_then(|f| f.data.as_ref())),
            Some(Event::Close(close)) => is_sealed(close.reason.as_ref()),
            None => false,
        },
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

    /// Replaces every value of `record` that predates its subject's erasure
    /// with that erasure's tombstone, as [`Node::seal_born`] does for
    /// production's records. `born` is the record's provenance: the
    /// production LSN it was recorded at, or the node's erasure generation
    /// for a fork-computed turn. Returns how many values it replaced.
    ///
    /// A fork's log, its samples and the turns a rebase stages into main's
    /// log call this before [`Node::seal`], so that a value of an erased
    /// subject never seals under a key version newer than the erased ones
    /// (ADR 0123 §6, docs/design/m8-privacy.md §6.8).
    pub fn tombstone_fork_record(&self, record: &mut Record, born: Born) -> usize {
        lock(&self.erasure_marks).tombstone(born, |f| {
            kronik_proto::sealables::record_mut(record, f);
        })
    }

    /// Seals a record a fork writes to disk (its log, its samples): like
    /// [`Node::seal`], except that a value of a subject erased after the
    /// record's provenance `born` becomes the erasure's tombstone instead of
    /// being sealed under a new key version, and a fork never creates a key
    /// version for an erased subject (`keep_erased_without_keys`). A fork's
    /// turns hold what it revealed or computed; none of it may bring an
    /// erased subject back (docs/design/m8-privacy.md §6.8).
    ///
    /// Takes the erasure fence before the tombstone check and returns it:
    /// no erasure begins between that check and the key version this seal
    /// creates (ADR 0123 §7). Hold the guard until the record is written;
    /// for a turn a rebase stages into main's log, until it is applied.
    /// Whoever seals several records takes [`Node::fork_seal_fence`] once
    /// and calls [`Node::seal_fork_record_fenced`], because acquiring a
    /// second read guard behind a waiting erasure would deadlock (the lock
    /// is write-preferring).
    ///
    /// A copied production turn passes its production LSN; a fork-computed
    /// turn passes [`Node::born_now`].
    pub async fn seal_fork_record(
        &self,
        record: &mut Record,
        born: Born,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, ()>, ApiError> {
        let fence = self.fork_seal_fence().await;
        self.seal_fork_record_fenced(&fence, record, born).await?;
        Ok(fence)
    }

    /// The erasure fence [`Node::seal_fork_record`] takes: an erasure waits
    /// until every fork record sealed and written under it is done (ADR
    /// 0123 §7).
    pub async fn fork_seal_fence(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.erase_lock.read().await
    }

    /// [`Node::seal_fork_record`] for a caller that already holds the
    /// erasure fence `_fence`: one fence covers a batch, so sealing does not
    /// acquire a second read guard behind a waiting erasure (deadlock).
    pub async fn seal_fork_record_fenced(
        &self,
        _fence: &tokio::sync::RwLockReadGuard<'_, ()>,
        record: &mut Record,
        born: Born,
    ) -> Result<(), ApiError> {
        if !self.sealer.is_on() {
            return Ok(());
        }
        self.tombstone_fork_record(record, born);
        self.sealer
            .keep_erased_without_keys(record)
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("sealing: {e}")))?;
        #[cfg(test)]
        self.hold_fork_seal().await;
        self.seal(record)
    }

    /// The test hook `NodeConfig::test_hold_fork_seal`: parks a fork's seal
    /// after its erasure checks and before it loads a sealing key, while it
    /// holds the erasure fence.
    #[cfg(test)]
    async fn hold_fork_seal(&self) {
        if let Some(hold) = &self.cfg.test_hold_fork_seal {
            hold.arrived
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Ok(permit) = hold.release.acquire().await {
                permit.forget();
            }
        }
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

    /// Whether a re-run's recorded effects hold a value that opens as
    /// erased: the erasure's tombstone, or a value sealed under a key that
    /// is gone. They count as the turn's input (§6.8): such a value cannot
    /// be handed to the guest again. A turn whose provenance predates an
    /// erasure records the tombstone in place of the subject's values even
    /// when its `TurnBegin` is in the log after the erasure's record, which
    /// the re-run's provenance (that `TurnBegin`'s LSN) does not predate.
    pub(crate) fn recorded_erased(&self, effects: &[pb::EffectRecord]) -> bool {
        effects
            .iter()
            .flat_map(|e| [e.request.as_ref(), e.response.as_ref()])
            .flatten()
            .any(|s| {
                matches!(
                    self.sealer.open(s),
                    kronik_privacy::sealer::Opened::Erased { .. }
                )
            })
    }

    /// Unseals recorded effects for a re-run in place; unreadable values
    /// stay sealed, and the guest gets what decoding them gives (a value of
    /// an erased subject does not get here: [`Node::recorded_erased`]).
    pub(crate) fn unseal_effects(&self, effects: &mut [pb::EffectRecord]) {
        for e in effects {
            kronik_proto::sealables::effect_mut(e, &mut |s| {
                let _ = self.sealer.unseal_value(s);
            });
        }
    }

    /// Unseals a saved outcome in place for whoever asked for it: an
    /// ingress response that an idempotent retry gets back, or a callee's
    /// answer that its caller's call gets. A value of an erased subject,
    /// sealed under a key that is gone, becomes the erasure's tombstone, as
    /// in the live answer of a turn that ran across the erasure (ADR 0123).
    /// The gateway answers either with `SUBJECT_ERASED`, and a call gets the
    /// call error `SUBJECT_ERASED` (`effects::map_call_outcome`).
    pub(crate) fn unseal_response(&self, outcome: &mut pb::Outcome) {
        self.sealer.unseal_answer(outcome);
    }
}
