//! Recorded successful reveals are prerequisites, not new guest-visible effects.
//! The caller runs preflight before opening SQL or taking an execution permit.
use std::sync::Mutex;
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::causal;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, TurnId};
use kronik_effects::Config;
use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::{Record, log::v1 as pb};
use prost::Message;
use zeroize::Zeroizing;

use crate::{Node, TurnResult};

pub(crate) const RETRY_INITIAL: Duration = Duration::from_millis(100);
pub(crate) const RETRY_MAX: Duration = Duration::from_secs(5);
/// How many times a re-run that meets `Unavailable` (not a secret) is tried
/// again by the worker: about 36 s at the backoff above.
pub(crate) const RERUN_UNAVAILABLE_ATTEMPTS: u32 = 12;
/// A waiting re-run says so on its first wait and then every this many.
pub(crate) const RERUN_WARN_EVERY: u32 = 12;

/// Whether the worker waits and tries a re-run again after it failed with
/// `code`; `unavailable_waits` is how often it has waited for a plain
/// `Unavailable` already.
///
/// A re-run must not end open while what it waits for can still come: a
/// secret, without bound (the recorded value is needed again, design m23
/// 5.3), and a prerequisite that is unavailable for a while, for a few
/// attempts. The latter is the call machinery and the recorded call results,
/// which can also be permanent (an erased subject, a record that cannot be
/// projected): the actor must not be held for ever behind one of those, so
/// after `RERUN_UNAVAILABLE_ATTEMPTS` the job ends, as before, and the next
/// start runs the turn again. Nothing is retried on a node that has failed.
pub(crate) fn rerun_waits(code: ErrorCode, unavailable_waits: u32, node_failed: bool) -> bool {
    match code {
        ErrorCode::SecretUnavailable => true,
        ErrorCode::Unavailable => unavailable_waits < RERUN_UNAVAILABLE_ATTEMPTS && !node_failed,
        _ => false,
    }
}
const STALL_METRIC: &str = "kronik_secret_recovery_stalled";
static STALLED: Mutex<u64> = Mutex::new(0);

pub(crate) struct Stalled(());
impl Stalled {
    pub(crate) fn new() -> Self {
        let mut count = super::lock(&STALLED);
        *count += 1;
        kronik_metrics::set(STALL_METRIC, &[], *count as f64);
        Self(())
    }
}
impl Drop for Stalled {
    fn drop(&mut self) {
        let mut count = super::lock(&STALLED);
        *count -= 1;
        kronik_metrics::set(STALL_METRIC, &[], *count as f64);
    }
}

async fn wait_for_availability(env: &Env, stalled: &mut Option<Stalled>, delay: &mut Duration) {
    stalled.get_or_insert_with(Stalled::new);
    env.clock.sleep(*delay).await;
    *delay = delay.saturating_mul(2).min(RETRY_MAX);
}

fn gone() -> ApiError {
    ApiError::new(
        ErrorCode::SecretVersionGone,
        "A recorded successful secret reveal cannot recover its immutable identity",
    )
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::SecretUnavailable,
        "A recorded request required for recovery cannot be opened",
    )
}
fn corrupt() -> ApiError {
    ApiError::new(
        ErrorCode::StorageCorrupt,
        "Invalid canonical recorded request in secret recovery",
    )
}

enum RequestBytes<'a> {
    Plain(&'a [u8]),
    Open(Zeroizing<Vec<u8>>),
}
impl AsRef<[u8]> for RequestBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Plain(bytes) => bytes,
            Self::Open(bytes) => bytes,
        }
    }
}
fn request_bytes<'a>(
    sealer: &Sealer,
    request: Option<&'a pb::Sealable>,
) -> Result<RequestBytes<'a>, ApiError> {
    let request = request.ok_or_else(corrupt)?;
    match &request.value {
        Some(pb::sealable::Value::Plain(bytes)) => Ok(RequestBytes::Plain(bytes)),
        Some(pb::sealable::Value::Sealed(_)) => match sealer.open(request) {
            Opened::Value(bytes) => Ok(RequestBytes::Open(Zeroizing::new(bytes.into_owned()))),
            Opened::Erased { .. } | Opened::Unreadable { .. } => Err(unavailable()),
        },
        None => Err(corrupt()),
    }
}

/// The one causal identity formula used by live calls and recovery.
pub(crate) fn compensation(
    actor: &ActorRef,
    key: &pb::CausalKey,
    ordinal: u32,
    to: &ActorRef,
    msg: pb::Message,
) -> pb::OutboundMessage {
    let key = causal::compensation(key, actor, ordinal, to);
    pb::OutboundMessage {
        to: Some(to.to_pb()),
        msg: Some(msg),
        ordinal,
        message_id: causal::causal_id(&key),
    }
}

impl Node {
    /// `begin` is already durable. Only this actor waits for availability;
    /// matched HTTP and crypto outcomes require no value and are not examined.
    pub(crate) async fn prepare_recorded_secrets(
        &self,
        begin: &pb::TurnBegin,
        effects: &[pb::EffectRecord],
        config: &Config,
        original: AuthLease,
    ) -> Result<(), ApiError> {
        original.check()?;
        let mut checked: Vec<(String, u64, [u8; 16])> = Vec::new();
        let mut stalled = None;
        for effect in effects.iter().filter(|effect| {
            effect.kind == "secret.reveal" && effect.status == pb::EffectStatus::Ok as i32
        }) {
            if config.epoch != begin.config_epoch {
                return Err(gone());
            }
            let mut delay = RETRY_INITIAL;
            let reference = loop {
                original.check()?;
                match request_bytes(self.sealer(), effect.request.as_ref()) {
                    Ok(bytes) => {
                        break pb::RevealEffectRequest::decode(bytes.as_ref())
                            .map_err(|_| gone())?
                            .secret
                            .ok_or_else(gone)?;
                    }
                    Err(error) if error.code == ErrorCode::SecretUnavailable => {
                        wait_for_availability(&self.env, &mut stalled, &mut delay).await;
                    }
                    Err(_) => return Err(gone()),
                }
            };
            let version = reference.resolved_version().map_err(|_| gone())?;
            let hash: [u8; 16] = reference
                .version_hash
                .as_slice()
                .try_into()
                .map_err(|_| gone())?;
            if !reference.template.is_empty()
                || effect.target.strip_prefix("secret-reveal:") != Some(reference.name.as_str())
            {
                return Err(gone());
            }
            if let Some((_, _, verified)) = checked
                .iter()
                .find(|(name, seen, _)| *name == reference.name && *seen == version)
            {
                if *verified != hash {
                    return Err(gone());
                }
                continue;
            }
            loop {
                original.check()?;
                match self
                    .resolve_secret(&reference.name, Some(version), config, original.clone())
                    .await
                {
                    Ok(Some(value)) => {
                        let matches = value.meta.name == reference.name
                            && value.meta.version == version
                            && value.meta.version_hash == hash;
                        let _value = Zeroizing::new(value.value);
                        if !matches {
                            return Err(gone());
                        }
                        break;
                    }
                    Ok(None) => {
                        return Err(gone());
                    }
                    Err(error) if error.code == ErrorCode::SecretUnavailable => {
                        wait_for_availability(&self.env, &mut stalled, &mut delay).await;
                    }
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::SecretVersionGone
                                | ErrorCode::SecretNotFound
                                | ErrorCode::SecretRefNotAllowed
                                | ErrorCode::SecretExternal
                                | ErrorCode::BadRequest
                        ) =>
                    {
                        return Err(gone());
                    }
                    Err(error) => return Err(error),
                }
            }
            checked.push((reference.name, version, hash));
        }
        Ok(())
    }

    /// Closes the original open turn without executing guest code. The source
    /// journal is untouched; normal sealing may protect a new copy of old plain
    /// tagged payloads, but never changes their logical recorded outcomes.
    pub(crate) async fn fail_recorded_secret(
        &self,
        begin: pb::TurnBegin,
        effects: Vec<pb::EffectRecord>,
        code: ErrorCode,
    ) -> Result<TurnResult, ApiError> {
        if code != ErrorCode::SecretVersionGone {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "Only definitive recorded secret loss can terminate recovery",
            ));
        }
        let actor_pb = begin.actor.as_ref().ok_or_else(corrupt)?;
        let actor =
            ActorRef::new(actor_pb.kind.clone(), actor_pb.key.clone()).map_err(|_| corrupt())?;
        let key = begin.causal_key.as_ref().ok_or_else(corrupt)?;
        let mut compensations = Vec::new();
        for effect in effects.iter().filter(|effect| {
            effect.kind == "actor.call" && effect.status == pb::EffectStatus::Ok as i32
        }) {
            let bytes = request_bytes(self.sealer(), effect.request.as_ref())?;
            let request = pb::CallEffectRequest::decode(bytes.as_ref()).map_err(|_| corrupt())?;
            let target = request.to.ok_or_else(corrupt)?;
            let to = ActorRef::new(target.kind, target.key).map_err(|_| corrupt())?;
            if request.message_id != causal::message_id(key, effect.ordinal)
                || effect
                    .target
                    .strip_prefix("actor:")
                    .and_then(|target| ActorRef::parse(target).ok())
                    .as_ref()
                    != Some(&to)
            {
                return Err(corrupt());
            }
            if let Some(message) = request.compensate {
                compensations.push(compensation(&actor, key, effect.ordinal, &to, message));
            }
        }
        let outcome = pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            error_code: code.as_str().into(),
            message: "A secret version that the turn recorded is no longer recoverable".into(),
            output: None,
        };
        let time = begin.logical_time_ms;
        let key = begin.causal_key.ok_or_else(corrupt)?;
        let record = pb::TurnRecord {
            execution_id: begin.execution_id,
            actor: begin.actor,
            code_hash: begin.code_hash,
            engine_version: begin.engine_version,
            causal_key: Some(key.clone()),
            logical_time_ms: time,
            random_seed: begin.random_seed,
            input: begin.input,
            effects,
            outcome: Some(outcome.clone()),
            compensations: compensations.clone(),
            config_epoch: begin.config_epoch,
            ..Default::default()
        };
        let lsn = self.commit(Record::TurnRecord(record)).await?;
        for message in compensations {
            let compensates = causal::message_id(&key, message.ordinal);
            self.deliver(
                &actor,
                &key,
                time,
                message,
                pb::MessageSource::Compensation,
                &compensates,
            );
        }
        Ok(TurnResult {
            turn_id: TurnId {
                branch: self.branch().to_owned(),
                lsn,
            },
            outcome,
            scrubbed_with: None,
        })
    }
}

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;
