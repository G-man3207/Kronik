//! The per-turn effect gate (docs/design/m2-effects.md §3-§5): capability
//! checks at the turn's epoch, `TurnBegin` before the first external effect,
//! call or secret use, `EffectResult` fsynced before the guest sees a
//! result, replay of recorded results in re-runs, and re-execution by
//! delivery class.

use std::sync::{Arc, Mutex};

use kronik_core::authority::AuthLease;
use kronik_core::causal;
use kronik_core::env::{BoxFuture, HttpRequest, NetError};
use kronik_core::error::ErrorCode;
use kronik_core::ids::{ActorRef, TurnId};
use kronik_effects::http::{
    CompiledScrubber, ScrubError, fingerprint as legacy_http_fingerprint, fingerprint_v2,
    parse_request_url,
};
use kronik_effects::simulator::{EffectRequest, RecordedMatch, ReplayContext};
use kronik_effects::{Config, Delivery, KindLimits};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, FetchResponse, GateError,
};
use prost::Message as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::node::{Node, OperationOrigin};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A recorded value of `subject` (the guest's default subject at the
/// effect); sealed when the record is appended in privacy mode.
fn tagged(subject: &Option<String>, bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.clone(),
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn plain(bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn not_granted(cap: &str) -> String {
    format!("{}: {cap}", ErrorCode::CapabilityNotGranted.as_str())
}

pub fn secret_ref(
    meta: kronik_privacy::SecretMeta,
    template: String,
) -> Result<pb::SecretRef, GateError> {
    let mut reference = pb::SecretRef {
        name: meta.name,
        template,
        version_hash: meta.version_hash,
        ..Default::default()
    };
    reference
        .set_resolved_version(meta.version)
        .map_err(|e| GateError::Host(e.to_string()))?;
    Ok(reference)
}

pub fn header_reference(reference: &pb::SecretRef, template: &str) -> pb::SecretRef {
    pb::SecretRef {
        name: reference.name.clone(),
        template: template.to_owned(),
        version: reference.version,
        wide_version: reference.wide_version,
        version_hash: reference.version_hash.clone(),
    }
}

pub fn saved_header_reference<'a>(
    source: &'a pb::HttpEffectRequest,
    index: usize,
    header_name: &str,
    secret: &str,
) -> Result<Option<&'a pb::SecretRef>, GateError> {
    if !matches!(source.fingerprint_version, 0 | 2) {
        return Err(GateError::Host(
            "The recorded HTTP fingerprint version is invalid".into(),
        ));
    }
    if source.fingerprint_version == 0
        && let Some(header) = source.headers.get(index)
        && header.name.eq_ignore_ascii_case(header_name)
        && let Some(pb::http_effect_header::Value::Secret(reference)) = &header.value
        && reference.name == secret
    {
        return Ok(Some(reference));
    }
    let mut selected: Option<&pb::SecretRef> = None;
    for header in &source.headers {
        let Some(pb::http_effect_header::Value::Secret(reference)) = &header.value else {
            continue;
        };
        if reference.name != secret {
            continue;
        }
        if let Some(previous) = selected {
            if previous.version != reference.version
                || previous.wide_version != reference.wide_version
                || previous.version_hash != reference.version_hash
            {
                return Err(GateError::Host(
                    "The recorded header reference is ambiguous".into(),
                ));
            }
        } else {
            selected = Some(reference);
        }
    }
    Ok(selected)
}

/// Fixed host disclosure data, never a replacement HTTP success body.
pub const WITHHELD_EFFECT_BODY: &[u8] = b"[withheld: redaction could not be completed]";
pub const LEGACY_REDACTION_CODE: &str = "LEGACY_REDACTION_INCOMPATIBLE";

fn effect_plain_payload(payload: Option<&pb::Sealable>) -> Result<&[u8], GateError> {
    match payload.and_then(|payload| payload.value.as_ref()) {
        Some(pb::sealable::Value::Plain(bytes)) => Ok(bytes),
        Some(pb::sealable::Value::Sealed(_)) => {
            Err(GateError::Prerequisite(ErrorCode::SecretUnavailable))
        }
        None => Err(GateError::Host(
            "A recorded effect payload is missing".into(),
        )),
    }
}

/// The actual inline-response producer, shared with replay. It processes
/// structured fields once, then records the exact bytes returned to the guest.
/// The caller MUST fsync `rec` before returning the outcome, including status 11.
pub fn prepare_inline_fetch_response(
    rec: &mut pb::EffectRecord,
    subject: &Option<String>,
    mut response: pb::HttpEffectResponse,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<FetchOutcome, GateError> {
    let status = u16::try_from(response.status)
        .map_err(|_| GateError::Host("The HTTP response status is invalid".into()))?;
    let redacted =
        crate::scrub::http_response(&mut response, matcher, output_bytes).and_then(|()| {
            if response.encoded_len() > kronik_log::MAX_RECORD as usize {
                Err(ScrubError::OutputLimit)
            } else {
                Ok(())
            }
        });
    if let Err(error) = redacted {
        response.body.zeroize();
        for header in &mut response.headers {
            header.name.zeroize();
            header.value.zeroize();
        }
        rec.status = pb::EffectStatus::HostRedactionFailure as i32;
        rec.error = error.to_string();
        rec.response = tagged(
            subject,
            pb::HttpEffectResponse {
                status: u32::from(status),
                headers: Vec::new(),
                body: WITHHELD_EFFECT_BODY.to_vec(),
            }
            .encode_to_vec(),
        );
        return Ok(FetchOutcome::HostRedactionFailure);
    }
    rec.status = pb::EffectStatus::Ok as i32;
    rec.response = tagged(subject, response.encode_to_vec());
    Ok(FetchOutcome::Ok(FetchResponse {
        status,
        headers: response
            .headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect(),
        body: response.body,
    }))
}

/// A successful reply must already be resolved through the gate's actual
/// source/key path. Opaque protected data and closed cleanup references are
/// not empty successful replies or ordinary call arguments.
pub fn validate_call_reply(reply: Option<&pb::Message>) -> Result<(), GateError> {
    if let Some(reply) = reply {
        if reply.retained_compensation_source.is_some() {
            return Err(GateError::Host(
                "A retained cleanup reference is not a call reply".into(),
            ));
        }
        if !matches!(
            reply.body.as_ref().and_then(|body| body.value.as_ref()),
            Some(pb::sealable::Value::Plain(_))
        ) {
            return Err(GateError::Prerequisite(ErrorCode::Unavailable));
        }
    }
    Ok(())
}

/// Observe an ALREADY PREPARED callee outcome without replacing its markers.
/// A genuine strict source scope proves the unchanged result; otherwise a
/// matching field cannot be safely disclosed. A qualified callee MUST have
/// its withheld FX11 fsynced before the runtime receives the typed failure.
pub fn prepare_call_outcome(
    record: &mut pb::EffectRecord,
    outcome: CallOutcome,
    turn_id: String,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
    current_scope: Option<&[pb::SecretRef]>,
    prepared_scope: Option<&[pb::SecretRef]>,
) -> Result<CallOutcome, GateError> {
    record.observed_callee_status = None;
    let mut response = None;
    let (observed, prepared) = match outcome {
        CallOutcome::Ok(reply) => {
            validate_call_reply(reply.as_ref())?;
            let value = pb::CallEffectResponse { reply, turn_id };
            let fields = value.reply.iter().flat_map(|message| {
                let Some(pb::sealable::Value::Plain(bytes)) =
                    message.body.as_ref().and_then(|body| body.value.as_ref())
                else {
                    unreachable!("the gate validated the reply body")
                };
                [
                    message.name.as_bytes(),
                    message.content_type.as_bytes(),
                    bytes.as_slice(),
                ]
            });
            let prepared =
                crate::scrub::prepared_fields_safe(current_scope, prepared_scope, matcher, fields)
                    .and_then(|()| {
                        if value.encoded_len() <= output_bytes.min(kronik_log::MAX_RECORD as usize)
                        {
                            Ok(())
                        } else {
                            Err(ScrubError::OutputLimit)
                        }
                    });
            response = Some(value);
            (
                pb::EffectStatus::Ok,
                prepared.map(|()| CallOutcome::Ok(None)),
            )
        }
        CallOutcome::Rejected(mut error) => {
            let prepared = crate::scrub::prepared_fields_safe(
                current_scope,
                prepared_scope,
                matcher,
                std::iter::once(error.as_bytes()),
            )
            .and({
                if error.len() <= output_bytes {
                    Ok(())
                } else {
                    Err(ScrubError::OutputLimit)
                }
            });
            let result = prepared.map(|()| CallOutcome::Rejected(std::mem::take(&mut error)));
            error.zeroize();
            (pb::EffectStatus::Rejected, result)
        }
        CallOutcome::Failed(mut error) => {
            let prepared = crate::scrub::prepared_fields_safe(
                current_scope,
                prepared_scope,
                matcher,
                std::iter::once(error.as_bytes()),
            )
            .and({
                if error.len() <= output_bytes {
                    Ok(())
                } else {
                    Err(ScrubError::OutputLimit)
                }
            });
            let result = prepared.map(|()| CallOutcome::Failed(std::mem::take(&mut error)));
            error.zeroize();
            (pb::EffectStatus::Failed, result)
        }
        CallOutcome::NotFound => {
            record.status = pb::EffectStatus::NotFound as i32;
            record.error = ErrorCode::ActorNotFound.as_str().into();
            return Ok(CallOutcome::NotFound);
        }
        CallOutcome::Reentrant => {
            record.status = pb::EffectStatus::Reentrant as i32;
            record.error = "CALL_REENTRANT".into();
            return Ok(CallOutcome::Reentrant);
        }
        CallOutcome::Timeout => {
            record.status = pb::EffectStatus::Timeout as i32;
            record.error = "CALL_TIMEOUT".into();
            return Ok(CallOutcome::Timeout);
        }
    };
    if let Err(error) = prepared {
        if let Some(response) = &mut response
            && let Some(reply) = &mut response.reply
        {
            crate::scrub::wipe_message(reply);
            reply.name = "WITHHELD".into();
            reply.content_type = "application/octet-stream".into();
            if let Some(body) = &mut reply.body {
                body.value = Some(pb::sealable::Value::Plain(WITHHELD_EFFECT_BODY.to_vec()));
            }
        }
        if record.callee_source.is_none() {
            return Err(GateError::Prerequisite(ErrorCode::Unavailable));
        }
        record.status = pb::EffectStatus::HostRedactionFailure as i32;
        record.observed_callee_status = Some(observed as i32);
        record.error = error.to_string();
        if let Some(response) = response {
            let subject = response
                .reply
                .as_ref()
                .and_then(|reply| reply.body.as_ref())
                .and_then(|body| body.subject.clone());
            record.response = tagged(&subject, response.encode_to_vec());
        }
        return Err(GateError::HostRedactionFailure);
    }
    record.status = observed as i32;
    let prepared = match prepared {
        // The redaction plan already handled every failure class that could
        // carry callee content; a bare Ok without a response is a host bug
        // surfaced as an explicit gate error instead of a panic.
        Ok(outcome) => outcome,
        Err(_) => {
            return Err(GateError::Host(
                "the call outcome's redaction plan did not resolve to a known outcome".into(),
            ));
        }
    };
    match prepared {
        CallOutcome::Ok(_outcome) => {
            let mut response = response.ok_or_else(|| {
                GateError::Host(
                    "the call outcome reported success without a response to redact".into(),
                )
            })?;
            let subject = response
                .reply
                .as_ref()
                .and_then(|reply| reply.body.as_ref())
                .and_then(|body| body.subject.clone());
            record.response = tagged(&subject, response.encode_to_vec());
            Ok(CallOutcome::Ok(response.reply.take()))
        }
        CallOutcome::Rejected(error) => {
            record.error = error.clone();
            Ok(CallOutcome::Rejected(error))
        }
        CallOutcome::Failed(error) => {
            record.error = error.clone();
            Ok(CallOutcome::Failed(error))
        }
        _ => unreachable!("the prepared callee result"),
    }
}

/// After an EXACT, verified legacy fingerprint match, determine whether the
/// historical guest result can still be disclosed. This never rewrites the
/// original EffectResult. Only the NEW terminal turn receives a safe explicit
/// host-disclosure projection; its original fingerprint remains an identity,
/// not the fingerprint of the deliberately withheld payload.
pub fn legacy_http_disclosure(
    mut record: pb::EffectRecord,
    source: &pb::HttpEffectRequest,
    matcher: &CompiledScrubber<'_>,
) -> Result<pb::EffectRecord, GateError> {
    if source.fingerprint_version == 2
        || record.status == pb::EffectStatus::HostRedactionFailure as i32
    {
        return Ok(record);
    }
    if source.fingerprint_version != 0 {
        return Err(GateError::Host(
            "The recorded HTTP fingerprint version is invalid".into(),
        ));
    }
    effect_plain_payload(record.request.as_ref())?;
    let mut response = record
        .response
        .as_ref()
        .map(|payload| {
            pb::HttpEffectResponse::decode(effect_plain_payload(Some(payload))?)
                .map_err(|_| GateError::Host("The legacy HTTP response is invalid".into()))
        })
        .transpose()?;
    if record.status == pb::EffectStatus::Ok as i32 && response.is_none() {
        return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
    }
    let changed = (|| -> Result<bool, ScrubError> {
        let remaining = std::cell::Cell::new(kronik_log::MAX_RECORD as usize);
        let error = std::cell::Cell::new(None);
        let changes = |bytes: &[u8]| {
            let Some(left) = remaining.get().checked_sub(bytes.len()) else {
                error.set(Some(ScrubError::OutputLimit));
                return true;
            };
            remaining.set(left);
            // A true ORIGINAL match includes byte-identical literal markers;
            // no replacement buffer or second matcher is needed for proof.
            matcher.is_match(bytes)
        };
        let (target, raw_host) =
            parse_request_url(&source.url).map_err(|_| ScrubError::InvalidText)?;
        let request_changed = crate::scrub::http_url_contains(&target, raw_host, &changes)?
            || (!crate::scrub::protocol_method(&source.method)
                && changes(source.method.as_bytes()))
            || changes(&source.body)
            || source.headers.iter().any(|header| {
                changes(header.name.as_bytes())
                    || match &header.value {
                        Some(pb::http_effect_header::Value::Text(text)) => changes(text.as_bytes()),
                        Some(pb::http_effect_header::Value::Secret(reference)) => reference
                            .template
                            .split("{}")
                            .any(|part| changes(part.as_bytes())),
                        None => false,
                    }
            });
        if let Some(cause) = error.take() {
            return Err(cause);
        }
        if request_changed {
            return Ok(true);
        }
        let error_changed = changes(record.error.as_bytes());
        if let Some(cause) = error.take() {
            return Err(cause);
        }
        if error_changed {
            return Ok(true);
        }
        if let Some(response) = &response {
            let response_changed = response
                .headers
                .iter()
                .flat_map(|header| [header.name.as_bytes(), header.value.as_bytes()])
                .chain(std::iter::once(response.body.as_slice()))
                .any(&changes);
            if let Some(cause) = error.take() {
                return Err(cause);
            }
            if response_changed {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    let status = response.as_ref().map(|response| response.status);
    if let Some(response) = &mut response {
        response.body.zeroize();
        for header in &mut response.headers {
            header.name.zeroize();
            header.value.zeroize();
        }
    }
    // Resource/unknown inventory is NOT proof of an unsafe historical result.
    let changed = changed.map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
    if !changed {
        return Ok(record);
    }
    let headers = source
        .headers
        .iter()
        .filter_map(|header| {
            let Some(pb::http_effect_header::Value::Secret(reference)) = &header.value else {
                return None;
            };
            Some(pb::HttpEffectHeader {
                name: "x-kronik-withheld-secret".into(),
                value: Some(pb::http_effect_header::Value::Secret(pb::SecretRef {
                    name: reference.name.clone(),
                    template: "{}".into(),
                    version: reference.version,
                    wide_version: reference.wide_version,
                    version_hash: reference.version_hash.clone(),
                })),
            })
        })
        .collect();
    let request = pb::HttpEffectRequest {
        method: if crate::scrub::protocol_method(&source.method) {
            source.method.clone()
        } else {
            "WITHHELD".into()
        },
        url: "[withheld]".into(),
        headers,
        body: WITHHELD_EFFECT_BODY.to_vec(),
        fingerprint_version: 0,
    };
    let response = status.map(|status| pb::HttpEffectResponse {
        status,
        headers: Vec::new(),
        body: WITHHELD_EFFECT_BODY.to_vec(),
    });
    for (payload, bytes) in [
        (&mut record.request, Some(request.encode_to_vec())),
        (
            &mut record.response,
            response.map(|response| response.encode_to_vec()),
        ),
    ] {
        let Some(bytes) = bytes else { continue };
        let payload = payload
            .as_mut()
            .ok_or_else(|| GateError::Host("The legacy payload is missing".into()))?;
        match payload.value.as_mut() {
            Some(pb::sealable::Value::Plain(old)) => old.zeroize(),
            _ => return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable)),
        }
        // Keep the ORIGINAL subject; never invent an encryption namespace.
        payload.value = Some(pb::sealable::Value::Plain(bytes));
    }
    // The original capability target included FREE host data, not merely a
    // closed protocol identifier. Keep the old receipt's binding immutable;
    // the NEW observation must not copy that unsafe host into its target.
    record.target.zeroize();
    record.target = if record.kind == "foreign.http" {
        "foreign:[withheld]"
    } else {
        "http:[withheld]"
    }
    .into();
    record.status = pb::EffectStatus::HostRedactionFailure as i32;
    record.error.zeroize();
    record.error = LEGACY_REDACTION_CODE.into();
    Ok(record)
}

/// Disclosure of an EXACT verified v0 call. `retained_source` is supplied
/// only by the private genuine-EffectResult witness path, never a locator
/// taken from guest data. The old receipt is not appended or rewritten.
pub fn legacy_call_disclosure(
    mut record: pb::EffectRecord,
    mut source: pb::CallEffectRequest,
    matcher: &CompiledScrubber<'_>,
    retained_source: Option<pb::ActorSource>,
) -> Result<(pb::EffectRecord, Option<pb::Message>), GateError> {
    fn withhold(message: &mut pb::Message) -> Result<(), GateError> {
        crate::scrub::wipe_message(message);
        let body = message
            .body
            .as_mut()
            .ok_or(GateError::Prerequisite(ErrorCode::Unavailable))?;
        body.value = Some(pb::sealable::Value::Plain(WITHHELD_EFFECT_BODY.to_vec()));
        message.name = "WITHHELD".into();
        message.content_type = "application/octet-stream".into();
        message.blobs.clear();
        Ok(())
    }
    let mut response = None;
    let result = (|| {
        if source.fingerprint_version != 0 || record.kind != "actor.call" {
            return Err(GateError::Host(
                "The legacy call identity is invalid".into(),
            ));
        }
        let status = pb::EffectStatus::try_from(record.status)
            .map_err(|_| GateError::Host("The legacy call status is invalid".into()))?;
        response = record
            .response
            .as_ref()
            .map(|payload| {
                pb::CallEffectResponse::decode(effect_plain_payload(Some(payload))?)
                    .map_err(|_| GateError::Host("The legacy call response is invalid".into()))
            })
            .transpose()?;
        if status == pb::EffectStatus::Ok && response.is_none() {
            return Err(GateError::Prerequisite(ErrorCode::Unavailable));
        }
        if let Some(response) = &response {
            validate_call_reply(response.reply.as_ref())?;
        }
        let unsafe_compensation = source
            .compensate
            .as_ref()
            .is_some_and(|message| crate::scrub::message_contains_sensitive(message, matcher));
        let changed = unsafe_compensation
            || source
                .msg
                .as_ref()
                .is_some_and(|message| crate::scrub::message_contains_sensitive(message, matcher))
            || matcher.is_match(record.error.as_bytes())
            || response
                .as_ref()
                .and_then(|response| response.reply.as_ref())
                .is_some_and(|message| crate::scrub::message_contains_sensitive(message, matcher));
        if changed
            && record.callee_source.is_some()
            && !matches!(
                status,
                pb::EffectStatus::Ok | pb::EffectStatus::Rejected | pb::EffectStatus::Failed
            )
        {
            return Err(GateError::Prerequisite(ErrorCode::Unavailable));
        }
        if status == pb::EffectStatus::Ok && unsafe_compensation && retained_source.is_none() {
            return Err(GateError::Prerequisite(ErrorCode::Unavailable));
        }
        let cleanup = if status == pb::EffectStatus::Ok {
            source.compensate.take().map(|mut message| {
                if unsafe_compensation {
                    crate::scrub::wipe_message(&mut message);
                    pb::Message {
                        retained_compensation_source: retained_source,
                        ..Default::default()
                    }
                } else {
                    message
                }
            })
        } else {
            None
        };
        if changed {
            if let Some(message) = &mut source.msg {
                withhold(message)?;
            }
            // A retained cleanup reference is a whole OUTBOUND Message, never
            // an ordinary CallRequest argument or a reply selector.
            let request = pb::CallEffectRequest {
                to: source.to.take(),
                msg: source.msg.take(),
                compensate: None,
                message_id: std::mem::take(&mut source.message_id),
                ..Default::default()
            };
            if let Some(response) = &mut response
                && let Some(reply) = &mut response.reply
            {
                withhold(reply)?;
            }
            for (payload, bytes) in [
                (&mut record.request, Some(request.encode_to_vec())),
                (
                    &mut record.response,
                    response.as_ref().map(|response| response.encode_to_vec()),
                ),
            ] {
                let Some(bytes) = bytes else { continue };
                let payload = payload
                    .as_mut()
                    .ok_or(GateError::Prerequisite(ErrorCode::Unavailable))?;
                match payload.value.as_mut() {
                    Some(pb::sealable::Value::Plain(old)) => old.zeroize(),
                    _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
                }
                payload.value = Some(pb::sealable::Value::Plain(bytes));
            }
            record.status = pb::EffectStatus::HostRedactionFailure as i32;
            record.observed_callee_status = record.callee_source.as_ref().map(|_| status as i32);
            record.error.zeroize();
            record.error = LEGACY_REDACTION_CODE.into();
        }
        Ok((std::mem::take(&mut record), cleanup))
    })();
    for message in [&mut source.msg, &mut source.compensate]
        .into_iter()
        .flatten()
    {
        crate::scrub::wipe_message(message);
    }
    if let Some(response) = &mut response
        && let Some(reply) = &mut response.reply
    {
        crate::scrub::wipe_message(reply);
    }
    if result.is_err() {
        for payload in [&mut record.request, &mut record.response]
            .into_iter()
            .flatten()
        {
            if let Some(pb::sealable::Value::Plain(bytes)) = &mut payload.value {
                bytes.zeroize();
            }
        }
    }
    result
}

/// What the turn needs to know to record its effects.
pub(crate) struct TurnSpec {
    pub origin: OperationOrigin,
    pub actor: ActorRef,
    pub execution_id: String,
    pub causal_key: pb::CausalKey,
    pub time: u64,
    /// The turn's start on the monotonic clock: effects record their
    /// `offset_us` from it (m28-otel §3.3).
    pub started: std::time::Duration,
    pub config: Arc<Config>,
    pub limits: KindLimits,
    pub call_chain: Vec<ActorRef>,
    /// The `TurnBegin` written before the first external effect.
    pub begin: pb::TurnBegin,
    /// Recorded results of an earlier execution (re-runs only).
    pub recorded: Option<Vec<pb::EffectRecord>>,
}

#[derive(Default)]
pub(crate) struct FxState {
    pub begun: bool,
    /// Every effect of the turn, denied ones included.
    pub records: Vec<pb::EffectRecord>,
    pub last_result_lsn: u64,
    /// Compensations of successful calls, delivered if the turn fails.
    pub compensations: Vec<pb::OutboundMessage>,
    /// A guest received `outcome-unknown`.
    pub outcome_unknown: bool,
    /// Revealed or used secret values, scrubbed from guest logs.
    pub secrets: Vec<(String, Arc<Zeroizing<Vec<u8>>>)>,
    /// Identity-only metadata of exactly the same acquired values, in order.
    /// A different count/name means the whole preparation scope is UNKNOWN.
    pub secret_refs: Vec<pb::SecretRef>,
    pub secret_scope_unknown: bool,
}

impl FxState {
    /// Seed privacy matching only. These cache-held bytes never become an
    /// operational credential, a provider fallback, or an actor grant.
    // Unused since the certified-snapshot rework; kept for the M23 track.
    #[allow(dead_code)]
    pub(crate) fn seed_scrub_snapshot(
        &mut self,
        snapshot: &crate::secrets::CertifiedSecretSnapshot,
    ) -> Result<(), GateError> {
        self.secrets
            .try_reserve(snapshot.values.len())
            .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        if let Some(references) = &snapshot.references {
            self.secret_refs
                .try_reserve(references.len())
                .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        }
        self.secrets.extend(
            snapshot
                .values
                .iter()
                .map(|(name, bytes)| (name.clone(), bytes.clone())),
        );
        match &snapshot.references {
            Some(references) => self.secret_refs.extend(
                references
                    .iter()
                    .map(|reference| header_reference(reference, "")),
            ),
            None => self.secret_scope_unknown = true,
        }
        Ok(())
    }

    fn scope_complete(&self) -> bool {
        !self.secret_scope_unknown && scope_covers_values(&self.secrets, &self.secret_refs)
    }

    fn empty_scope() -> Arc<[pb::SecretRef]> {
        static EMPTY: std::sync::LazyLock<Arc<[pb::SecretRef]>> =
            std::sync::LazyLock::new(|| Arc::from([]));
        EMPTY.clone()
    }

    pub(crate) fn secret_scope(&self) -> Option<Arc<[pb::SecretRef]>> {
        self.scope_complete().then(|| {
            if self.secret_refs.is_empty() {
                Self::empty_scope()
            } else {
                Arc::from(self.secret_refs.as_slice())
            }
        })
    }

    pub(crate) fn take_secret_scope(&mut self) -> Option<Arc<[pb::SecretRef]>> {
        self.scope_complete().then(|| {
            if self.secret_refs.is_empty() {
                Self::empty_scope()
            } else {
                Arc::from(std::mem::take(&mut self.secret_refs))
            }
        })
    }
}

/// A temporary borrowed index, never a second allocation of secret bytes.
pub fn secret_patterns(secrets: &[(String, Arc<Zeroizing<Vec<u8>>>)]) -> Vec<(&str, &[u8])> {
    secrets
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect()
}

fn scope_covers_values(
    values: &[(String, Arc<Zeroizing<Vec<u8>>>)],
    references: &[pb::SecretRef],
) -> bool {
    references.len() == values.len()
        && references.iter().zip(values).all(|(reference, (name, _))| {
            reference.name == *name && crate::scrub::scope_identity(reference).is_ok()
        })
}

/// Certify the exact combined matcher input without copying its value bytes.
/// The snapshot and held identities must come from their genuine host
/// acquisition paths; this checks metadata coverage, not authority or a new
/// hash-of-data proof. Unknown metadata remains UNKNOWN even for empty values.
pub fn combined_secret_scope(
    snapshot: &crate::secrets::CertifiedSecretSnapshot,
    held_values: &[(String, Arc<Zeroizing<Vec<u8>>>)],
    held_references: Option<&[pb::SecretRef]>,
) -> Result<Option<Arc<[pb::SecretRef]>>, ScrubError> {
    let (Some(original), Some(held)) = (&snapshot.references, held_references) else {
        return Ok(None);
    };
    if !scope_covers_values(&snapshot.values, original) || !scope_covers_values(held_values, held) {
        return Ok(None);
    }
    if held.is_empty() {
        return Ok(Some(original.clone()));
    }
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(original.len())
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    for reference in original.iter() {
        identities.push(crate::scrub::scope_identity(reference)?);
    }
    identities.sort_unstable();
    let mut additional = Vec::new();
    additional
        .try_reserve_exact(held.len())
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    for reference in held {
        let identity = crate::scrub::scope_identity(reference)?;
        if identities.binary_search(&identity).is_err() {
            additional.push((identity, reference));
        }
    }
    if additional.is_empty() {
        return Ok(Some(original.clone()));
    }
    additional.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    additional.dedup_by(|a, b| a.0 == b.0);
    let count = original
        .len()
        .checked_add(additional.len())
        .ok_or(ScrubError::MatcherUnavailable)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(count)
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    merged.extend(original.iter().cloned());
    merged.extend(
        additional
            .into_iter()
            .map(|(_, reference)| reference.clone()),
    );
    Ok(Some(Arc::from(merged)))
}

pub(crate) struct TurnFx {
    node: Arc<Node>,
    spec: TurnSpec,
    original_execution: AuthLease,
    pub state: Mutex<FxState>,
}

/// The `EffectGate` handed to the runtime.
pub(crate) struct Gate(pub Arc<TurnFx>);

impl TurnFx {
    fn remember_secret(&self, reference: &pb::SecretRef, value: Arc<Zeroizing<Vec<u8>>>) {
        let mut state = lock(&self.state);
        state.secret_refs.push(header_reference(reference, ""));
        state.secrets.push((reference.name.clone(), value));
    }
    /// Scrub-only hydration of an admitted identity. No provider I/O and no
    /// value is returned for a reveal, wire header, resend, or fork.
    fn remember_recorded_secret(&self, reference: &pb::SecretRef) -> Result<(), GateError> {
        let cache = self
            .node
            .secret_cache()
            .ok_or(GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        let bytes = cache.scrub_reference(reference).map_err(|error| {
            if error.code == ErrorCode::SecretUnavailable {
                GateError::Prerequisite(error.code)
            } else {
                GateError::Host(error.code.as_str().into())
            }
        })?;
        self.remember_secret(reference, bytes);
        Ok(())
    }

    pub fn new(node: Arc<Node>, spec: TurnSpec, original_execution: AuthLease) -> Arc<TurnFx> {
        let begun = spec.recorded.is_some();
        Arc::new(TurnFx {
            node,
            spec,
            original_execution,
            state: Mutex::new(FxState {
                begun,
                ..FxState::default()
            }),
        })
    }

    pub(crate) fn admitted_begin(&self) -> &pb::TurnBegin {
        &self.spec.begin
    }

    fn kind(&self) -> &str {
        &self.spec.actor.kind
    }

    fn rerun(&self) -> bool {
        self.spec.recorded.is_some()
    }

    fn recorded(&self, req: &EffectRequest) -> Result<Option<pb::EffectRecord>, GateError> {
        let Some(recorded) = &self.spec.recorded else {
            return Ok(None);
        };
        let m = RecordedMatch {
            grounding: pb::Grounding::Live,
        };
        match m.lookup(req, &ReplayContext { recorded }) {
            Ok(r) => Ok(r.map(|r| r.record)),
            Err(d) => Err(GateError::Diverged(format!(
                "effect {} ({}) differs from the recorded request",
                d.ordinal, req.kind
            ))),
        }
    }

    /// [`Self::recorded`] for an effect whose fingerprint is keyed for its
    /// subject (`Sealer::effect_fingerprint`): a record written before
    /// keyed fingerprints, with the plain fingerprint `plain`, matches too.
    fn recorded_keyed(
        &self,
        req: &EffectRequest,
        plain: &[u8],
    ) -> Result<Option<pb::EffectRecord>, GateError> {
        match self.recorded(req) {
            Err(_)
                if self
                    .recorded_raw(req.ordinal)
                    .is_some_and(|r| r.kind == req.kind && r.fingerprint == plain) =>
            {
                Ok(self.recorded_raw(req.ordinal).cloned().map(|mut r| {
                    r.grounding = pb::Grounding::Live as i32;
                    r
                }))
            }
            other => other,
        }
    }

    fn recorded_raw(&self, ordinal: u32) -> Option<&pb::EffectRecord> {
        self.spec
            .recorded
            .as_ref()
            .and_then(|r| r.iter().find(|e| e.ordinal == ordinal))
    }

    /// Appends and fsyncs the `TurnBegin` once (I14).
    async fn begin(&self) -> Result<(), GateError> {
        if lock(&self.state).begun {
            return Ok(());
        }
        self.node
            .append_origin(
                Record::TurnBegin(self.spec.begin.clone()),
                self.spec.origin.clone(),
            )
            .await
            .map_err(|e| GateError::Host(e.to_string()))?;
        lock(&self.state).begun = true;
        Ok(())
    }

    /// Microseconds since the turn started.
    fn since_start(&self) -> u64 {
        self.node
            .env
            .clock
            .monotonic()
            .saturating_sub(self.spec.started)
            .as_micros() as u64
    }

    /// Appends and fsyncs the result before the guest sees it, without the
    /// values of the secrets the turn used or revealed so far (I8).
    async fn record(&self, mut rec: pb::EffectRecord) -> Result<(), GateError> {
        // From the effect's start (`base`) unless the effect timed itself.
        if rec.duration_us == 0 {
            rec.duration_us = self.since_start().saturating_sub(rec.offset_us);
        }
        let status = pb::EffectStatus::try_from(rec.status)
            .map(|s| kronik_metrics::enum_label(s.as_str_name(), "EFFECT_STATUS_"))
            .unwrap_or_default();
        kronik_metrics::inc(
            "kronik_effects_total",
            &[("kind", &rec.kind), ("status", &status)],
        );
        let lsn = self
            .node
            .append(Record::EffectResult(pb::EffectResult {
                execution_id: self.spec.execution_id.clone(),
                effect: Some(rec.clone()),
            }))
            .await
            .map_err(|e| GateError::Host(e.to_string()))?;
        let mut state = lock(&self.state);
        state.last_result_lsn = state.last_result_lsn.max(lsn);
        state.records.push(rec);
        Ok(())
    }

    /// A deterministic result that needs no fsync (denied by configuration).
    fn note(&self, rec: pb::EffectRecord) {
        lock(&self.state).records.push(rec);
    }

    fn base(&self, ordinal: u32, kind: &str, target: String, fp: Vec<u8>) -> pb::EffectRecord {
        pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target,
            fingerprint: fp,
            grounding: pb::Grounding::Live as i32,
            offset_us: self.since_start(),
            ..Default::default()
        }
    }

    fn denied(&self, ordinal: u32, kind: &str, target: String, error: String) -> pb::EffectRecord {
        let mut r = self.base(ordinal, kind, target, Vec::new());
        r.status = pb::EffectStatus::Denied as i32;
        r.error = error;
        r
    }

    async fn secret_value(
        &self,
        name: &str,
        version: Option<u64>,
    ) -> Result<Option<kronik_privacy::SecretValue>, GateError> {
        self.begin().await?;
        self.node
            .resolve_secret(
                name,
                version,
                &self.spec.config,
                self.original_execution.clone(),
            )
            .await
            .map_err(|error| GateError::Prerequisite(error.code))
    }

    async fn fetch(&self, ordinal: u32, req: FetchRequest) -> Result<FetchOutcome, GateError> {
        if let Some(record) = self.recorded_raw(ordinal)
            && matches!(record.kind.as_str(), "http.fetch" | "foreign.http")
            && record.status == pb::EffectStatus::HostRedactionFailure as i32
        {
            // A durable failure, including a prior safe terminal disclosure
            // projection, never becomes OK when an inventory later improves.
            lock(&self.state).records.push(record.clone());
            return Ok(FetchOutcome::HostRedactionFailure);
        }
        let subject = req.subject.clone();
        let (target, raw_host) = match parse_request_url(&req.url) {
            Ok(t) => t,
            Err(_) => {
                let error = ErrorCode::BadRequest.as_str().to_owned();
                self.note(self.denied(
                    ordinal,
                    "http.fetch",
                    "http:[withheld]".into(),
                    error.clone(),
                ));
                return Ok(FetchOutcome::Denied(error));
            }
        };
        // foreign:// reaches a foreign actor (docs/design/m7-foreign.md §8):
        // the same pipeline as http.fetch with its own kind, capability and
        // transport.
        let foreign = target.scheme == "foreign";
        let kind = if foreign {
            "foreign.http"
        } else {
            "http.fetch"
        };
        let cap_target = if foreign {
            format!("foreign:{}", target.host)
        } else {
            format!("http:{}", target.host)
        };
        let grant = if foreign {
            self.spec.config.grant(self.kind(), &cap_target).cloned()
        } else {
            self.spec
                .config
                .http_grant(self.kind(), &target.host)
                .cloned()
        };
        let Some(grant) = grant else {
            let e = not_granted(&cap_target);
            let withheld = if foreign {
                "foreign:[withheld]"
            } else {
                "http:[withheld]"
            };
            self.note(self.denied(ordinal, kind, withheld.into(), e.clone()));
            return Ok(FetchOutcome::Denied(e));
        };
        if foreign && self.spec.config.foreign(&target.host).is_none() {
            let e = ErrorCode::ForeignNotFound.as_str().to_owned();
            self.note(self.denied(ordinal, kind, "foreign:[withheld]".into(), e.clone()));
            return Ok(FetchOutcome::Denied(e));
        }
        for (header, value) in &req.headers {
            if header.eq_ignore_ascii_case("idempotency-key") {
                continue;
            }
            if let FetchHeader::Secret { name, .. } = value {
                let cap = format!("secret:{name}");
                if self.spec.config.grant(self.kind(), &cap).is_none() {
                    let error = not_granted(&cap);
                    self.note(self.denied(ordinal, kind, cap, error.clone()));
                    return Ok(FetchOutcome::Denied(error));
                }
            }
        }
        // Legacy missing-secret denials had no request, and never went on the wire.
        if let Some(record) = self.recorded_raw(ordinal)
            && record.kind == kind
            && record.status == pb::EffectStatus::Denied as i32
            && record.request.is_none()
            && req.headers.iter().any(|(header, value)| !header.eq_ignore_ascii_case("idempotency-key")
                && matches!(value, FetchHeader::Secret { name, .. } if record.target == format!("secret:{name}")))
        {
            lock(&self.state).records.push(record.clone());
            return Ok(FetchOutcome::Denied(record.error.clone()));
        }
        let recorded_req = self
            .recorded_raw(ordinal)
            .map(|record| {
                match record
                    .request
                    .as_ref()
                    .and_then(|request| request.value.as_ref())
                {
                    Some(pb::sealable::Value::Plain(bytes)) => {
                        pb::HttpEffectRequest::decode(bytes.as_slice())
                            .map_err(|_| GateError::Host("Invalid recorded HTTP request".into()))
                    }
                    _ => Err(GateError::Host(
                        "The recorded HTTP request cannot be opened".into(),
                    )),
                }
            })
            .transpose()?;
        let delivery = grant
            .delivery
            .unwrap_or_else(|| Delivery::default_for(&req.method));
        let unsafe_unrecorded =
            self.rerun() && delivery == Delivery::Unsafe && self.recorded_raw(ordinal).is_none();
        let mut failure = None;
        let mut headers: Vec<pb::HttpEffectHeader> = Vec::new();
        let mut wire_secrets: Vec<(String, Arc<Zeroizing<Vec<u8>>>)> = Vec::new();
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("idempotency-key") {
                continue;
            }
            let value = match value {
                FetchHeader::Text(text) => pb::http_effect_header::Value::Text(text.clone()),
                FetchHeader::Secret {
                    name: secret,
                    template,
                } => {
                    let recorded_ref = recorded_req
                        .as_ref()
                        .map(|request| saved_header_reference(request, headers.len(), name, secret))
                        .transpose()?
                        .flatten();
                    let mut reference = match recorded_ref {
                        Some(reference) => header_reference(reference, template),
                        None => pb::SecretRef {
                            name: secret.clone(),
                            template: template.clone(),
                            ..Default::default()
                        },
                    };
                    if recorded_ref.is_some() && !reference.is_unresolved() {
                        // Scrub-only bytes normalize an ALREADY recorded
                        // identity; they NEVER enter wire_secrets or authorize
                        // a fresh effect, resend, reveal, or fork.
                        let cache = self
                            .node
                            .secret_cache()
                            .ok_or(GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
                        let bytes = cache.scrub_reference(&reference).map_err(|error| {
                            if error.code == ErrorCode::SecretUnavailable {
                                GateError::Prerequisite(error.code)
                            } else {
                                GateError::Host(error.code.as_str().into())
                            }
                        })?;
                        self.remember_secret(&reference, bytes);
                    }
                    if !reference.is_unresolved() {
                        reference
                            .resolved_version()
                            .map_err(|error| GateError::Host(error.to_string()))?;
                    } else if self
                        .recorded_raw(ordinal)
                        .is_some_and(|record| record.status == pb::EffectStatus::Ok as i32)
                    {
                        return Err(GateError::Host(
                            "A successful recorded HTTP effect has an unresolved secret".into(),
                        ));
                    }
                    if recorded_req.is_none() && !unsafe_unrecorded && failure.is_none() {
                        if let Some(previous) =
                            headers.iter().find_map(|header| match &header.value {
                                Some(pb::http_effect_header::Value::Secret(previous))
                                    if previous.name == *secret =>
                                {
                                    Some(previous)
                                }
                                _ => None,
                            })
                        {
                            reference = header_reference(previous, template);
                        } else {
                            match self.secret_value(secret, None).await {
                                Ok(Some(value)) => {
                                    reference = secret_ref(value.meta, template.clone())?;
                                    let bytes = Arc::new(Zeroizing::new(value.value));
                                    self.remember_secret(&reference, bytes.clone());
                                    wire_secrets.push((secret.clone(), bytes));
                                }
                                Ok(None) => {
                                    failure = Some((
                                        pb::EffectStatus::Denied,
                                        ErrorCode::SecretNotFound.as_str().to_owned(),
                                    ))
                                }
                                Err(GateError::Prerequisite(code)) => {
                                    return Err(GateError::Prerequisite(code));
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    pb::http_effect_header::Value::Secret(reference)
                }
            };
            headers.push(pb::HttpEffectHeader {
                name: name.clone(),
                value: Some(value),
            });
        }
        let mut request = pb::HttpEffectRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers,
            body: req.body.clone(),
            fingerprint_version: 2,
        };
        // Recorded and fingerprinted without the values of secrets revealed
        // so far (I8), so a fork's placeholder (`[secret:<name>]`) matches
        // the recording exactly; `request` itself goes on the wire.
        let (matcher, legacy) = {
            let state = lock(&self.state);
            let patterns = secret_patterns(&state.secrets);
            let matcher = CompiledScrubber::new(&patterns, crate::scrub::MAX_SECRET_PATTERN_BYTES)
                .map_err(|error| GateError::Host(error.to_string()))?
                .into_owned();
            let legacy = match recorded_req.as_ref() {
                Some(source) if source.fingerprint_version == 0 => Some((
                    source,
                    crate::scrub::legacy_verification_fingerprint(&mut request, source, &patterns)
                        .map_err(|error| GateError::Host(error.to_string()))?,
                )),
                Some(source) if source.fingerprint_version == 2 => None,
                Some(_) => {
                    return Err(GateError::Host(
                        "The recorded HTTP fingerprint version is invalid".into(),
                    ));
                }
                None => None,
            };
            (matcher, legacy)
        };
        if let Some((source, plain_fp)) = legacy {
            let saved = self
                .recorded_raw(ordinal)
                .ok_or_else(|| GateError::Host("The legacy result is missing".into()))?;
            let source_plain = legacy_http_fingerprint(source)
                .map_err(|_| GateError::Host("The legacy request fingerprint is invalid".into()))?;
            let source_subject = saved
                .request
                .as_ref()
                .and_then(|payload| payload.subject.as_deref());
            let source_keyed = self
                .node
                .sealer()
                .effect_fingerprint(source_subject, source_plain.clone());
            if saved.fingerprint != source_plain && saved.fingerprint != source_keyed {
                return Err(GateError::Host(
                    "The legacy result fingerprint is invalid".into(),
                ));
            }
            // Retained inventory may contain values not known to the old
            // writer. A different normalization is not proof of a different
            // request and must never authorize a resend or a hash alias.
            if plain_fp != source_plain {
                return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
            }
            let fingerprint = self
                .node
                .sealer()
                .effect_fingerprint(subject.as_deref(), plain_fp.clone());
            let expected = EffectRequest {
                ordinal,
                kind: kind.into(),
                target: cap_target.clone(),
                fingerprint,
                http: None,
            };
            let record = self
                .recorded_keyed(&expected, &plain_fp)?
                .ok_or_else(|| GateError::Host("The verified legacy result is missing".into()))?;
            let record = legacy_http_disclosure(record, source, &matcher)?;
            let outcome = outcome_of_fetch(&record);
            lock(&self.state).records.push(record);
            return outcome;
        }
        let body = std::mem::take(&mut request.body);
        let mut recorded = pb::HttpEffectRequest {
            body,
            ..request.clone()
        };
        let recorded_target = crate::scrub::http_request(
            &mut recorded,
            &target,
            raw_host,
            &matcher,
            kronik_log::MAX_RECORD as usize,
        )
        .map_err(|error| GateError::Host(error.to_string()))?;
        if recorded.encoded_len() > kronik_log::MAX_RECORD as usize {
            return Err(GateError::Host(ScrubError::OutputLimit.to_string()));
        }
        let plain_fp = fingerprint_v2(&recorded, &recorded_target).map_err(GateError::Host)?;
        let recorded_cap = format!(
            "{}:{}",
            if foreign { "foreign" } else { "http" },
            recorded_target.host
        );
        let fp = self
            .node
            .sealer()
            .effect_fingerprint(subject.as_deref(), plain_fp.clone());
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: recorded_cap.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded_keyed(&ereq, &plain_fp)? {
            let outcome = outcome_of_fetch(&rec);
            lock(&self.state).records.push(rec);
            return outcome;
        }
        let idem = causal::idempotency_key(&self.spec.causal_key, ordinal);
        let mut rec = self.base(ordinal, kind, recorded_cap, fp);
        rec.request = tagged(&subject, recorded.encode_to_vec());
        rec.idempotency_key = idem.clone();
        rec.delivery = delivery.as_str().into();
        if let Some((status, error)) = failure {
            rec.status = status as i32;
            rec.error = error.clone();
            self.record(rec).await?;
            return Ok(if status == pb::EffectStatus::Denied {
                FetchOutcome::Denied(error)
            } else {
                FetchOutcome::Network(error)
            });
        }
        if self.rerun() && delivery == Delivery::Unsafe {
            // I17: an unsafe effect without a recorded result is not
            // performed again.
            rec.status = pb::EffectStatus::OutcomeUnknown as i32;
            rec.error = "outcome unknown: the daemon stopped before the result was recorded".into();
            self.record(rec).await?;
            lock(&self.state).outcome_unknown = true;
            return Ok(FetchOutcome::OutcomeUnknown);
        }
        self.begin().await?;
        if let Some(rate) = grant.rate {
            let key = format!("{}|{}|{}", grant.kind, grant.capability, target.host);
            self.node.rates.acquire(&self.node.env, &key, rate).await;
        }
        // The values of secrets taken from the recording are needed on the
        // wire again (replay-safe or idempotency-keyed re-execution).
        for h in &request.headers {
            if let Some(pb::http_effect_header::Value::Secret(s)) = &h.value
                && !wire_secrets.iter().any(|(name, _)| *name == s.name)
            {
                let version = s
                    .resolved_version()
                    .map_err(|e| GateError::Host(e.to_string()))?;
                let Some(v) = self.secret_value(&s.name, Some(version)).await? else {
                    return Err(GateError::Prerequisite(ErrorCode::SecretVersionGone));
                };
                if v.meta.version_hash != s.version_hash {
                    return Err(GateError::Prerequisite(ErrorCode::SecretVersionGone));
                }
                let bytes = Arc::new(Zeroizing::new(v.value));
                self.remember_secret(s, bytes.clone());
                wire_secrets.push((s.name.clone(), bytes));
            }
        }
        let mut wire_headers: Vec<(String, String)> = Vec::new();
        for h in &request.headers {
            match &h.value {
                Some(pb::http_effect_header::Value::Text(t)) => {
                    wire_headers.push((h.name.clone(), t.clone()))
                }
                Some(pb::http_effect_header::Value::Secret(s)) => {
                    if let Some((_, value)) = wire_secrets.iter().find(|(name, _)| *name == s.name)
                    {
                        let value = std::str::from_utf8(value).map_err(|_| {
                            GateError::Host(
                                "The credential cannot be used as an HTTP text header".into(),
                            )
                        })?;
                        let rendered = if s.template.contains("{}") {
                            s.template.replace("{}", value)
                        } else {
                            value.to_owned()
                        };
                        wire_headers.push((h.name.clone(), rendered));
                    }
                }
                None => {}
            }
        }
        wire_headers.push(("idempotency-key".into(), idem));
        let started = self.node.env.clock.monotonic();
        rec.offset_us = started.saturating_sub(self.spec.started).as_micros() as u64;
        let wire = HttpRequest {
            method: req.method,
            url: req.url,
            headers: wire_headers,
            body: bytes::Bytes::from(req.body),
            max_response_bytes: self.spec.limits.effect_response_bytes,
        };
        let call: BoxFuture<'static, Result<kronik_core::env::HttpResponse, NetError>> =
            match (foreign, &self.node.foreign) {
                (false, _) => self
                    .node
                    .env
                    .net
                    .http_authorized(wire, self.original_execution.clone()),
                (true, Some(host)) => host.http(&target.host, wire),
                (true, None) => {
                    let e = kronik_effects::foreign::unavailable(
                        &target.host,
                        "foreign actors are not available in this process",
                    );
                    Box::pin(std::future::ready(Err(e)))
                }
            };
        let res = self
            .node
            .env
            .timeout(self.spec.limits.effect_timeout, call)
            .await;
        rec.duration_us = self
            .node
            .env
            .clock
            .monotonic()
            .saturating_sub(started)
            .as_micros() as u64;
        // The guest sees the answer as a re-run will (from the scrubbed
        // recording): without the values of every secret known so far,
        // inserted or revealed (I8, I1).
        let outcome = match res {
            Err(_) => {
                rec.status = pb::EffectStatus::Timeout as i32;
                rec.error = format!(
                    "no response within {} ms",
                    self.spec.limits.effect_timeout.as_millis()
                );
                FetchOutcome::Timeout
            }
            Ok(Err(NetError::TooLarge)) => {
                rec.status = pb::EffectStatus::TooLarge as i32;
                rec.error = format!(
                    "the response exceeds {} bytes",
                    self.spec.limits.effect_response_bytes
                );
                FetchOutcome::TooLarge
            }
            Ok(Err(NetError::Connect(mut error) | NetError::Io(mut error))) => {
                match crate::scrub::text(&mut error, &matcher, kronik_log::MAX_RECORD as usize) {
                    Ok(()) => {
                        rec.status = pb::EffectStatus::Network as i32;
                        rec.error = error.clone();
                        FetchOutcome::Network(error)
                    }
                    Err(_) => {
                        error.zeroize();
                        rec.status = pb::EffectStatus::Network as i32;
                        rec.error = "network diagnostic withheld by host policy".into();
                        FetchOutcome::Network(rec.error.clone())
                    }
                }
            }
            Ok(Ok(response)) => prepare_inline_fetch_response(
                &mut rec,
                &subject,
                pb::HttpEffectResponse {
                    status: u32::from(response.status),
                    headers: response
                        .headers
                        .into_iter()
                        .map(|(name, value)| pb::HeaderPair { name, value })
                        .collect(),
                    body: Vec::from(response.body),
                },
                &matcher,
                self.spec
                    .limits
                    .effect_response_bytes
                    .min(u64::from(kronik_log::MAX_RECORD)) as usize,
            )?,
        };
        self.record(rec).await?;
        Ok(outcome)
    }

    fn remember_compensation(&self, ordinal: u32, to: &ActorRef, message: Option<pb::Message>) {
        if let Some(message) = message {
            lock(&self.state)
                .compensations
                .push(crate::secrets::recovery::compensation(
                    &self.spec.actor,
                    &self.spec.causal_key,
                    ordinal,
                    to,
                    message,
                ));
        }
    }

    async fn validate_call_carriers(
        &self,
        request: pb::CallEffectRequest,
    ) -> Result<pb::CallEffectRequest, GateError> {
        let protected = [&request.msg, &request.compensate]
            .into_iter()
            .flatten()
            .any(|message| {
                !matches!(
                    message.body.as_ref().and_then(|body| body.value.as_ref()),
                    Some(pb::sealable::Value::Plain(_))
                )
            });
        if !protected {
            return Ok(request);
        }
        self.begin().await?;
        let node = self.node.clone();
        self.node
            .env
            .blocking("validate original call protection", move || {
                for message in [&request.msg, &request.compensate].into_iter().flatten() {
                    let body = message.body.as_ref().ok_or_else(|| {
                        GateError::Host("The call message body is missing".into())
                    })?;
                    match &body.value {
                        Some(pb::sealable::Value::Plain(_)) => {}
                        Some(pb::sealable::Value::Sealed(envelope))
                            if envelope.key_version > 0 && body.subject.is_some() =>
                        {
                            match node.sealer().open(body) {
                                kronik_privacy::sealer::Opened::Value(bytes) => {
                                    let _plaintext = Zeroizing::new(bytes.into_owned());
                                }
                                _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
                            }
                        }
                        _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
                    }
                }
                Ok(request)
            })
            .await
            .ok_or_else(|| GateError::Host("The call protection worker stopped".into()))?
    }

    async fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> Result<CallOutcome, GateError> {
        let kind = "actor.call";
        let target = format!("actor:{to}");
        let message_id = causal::message_id(&self.spec.causal_key, ordinal);
        if let Some(record) = self.recorded_raw(ordinal)
            && record.kind == kind
            && record.status == pb::EffectStatus::HostRedactionFailure as i32
        {
            if record.successful_call() {
                let mut request =
                    pb::CallEffectRequest::decode(effect_plain_payload(record.request.as_ref())?)
                        .map_err(|_| {
                        GateError::Host("The recorded successful call request is invalid".into())
                    })?;
                if request.compensate.is_some() && request.fingerprint_version != 2 {
                    return Err(GateError::Prerequisite(ErrorCode::Unavailable));
                }
                self.remember_compensation(ordinal, &to, request.compensate.take());
            }
            lock(&self.state).records.push(record.clone());
            return Err(GateError::HostRedactionFailure);
        }
        let source = self
            .recorded_raw(ordinal)
            .map(|record| {
                pb::CallEffectRequest::decode(effect_plain_payload(record.request.as_ref())?)
                    .map_err(|_| GateError::Host("The recorded call request is invalid".into()))
            })
            .transpose()?;
        let mut request = pb::CallEffectRequest {
            to: Some(to.to_pb()),
            msg: Some(msg),
            compensate,
            message_id: message_id.clone(),
            fingerprint_version: 2,
        };
        let (matcher, legacy, current_scope) = {
            let state = lock(&self.state);
            let patterns = secret_patterns(&state.secrets);
            let matcher = CompiledScrubber::new(&patterns, crate::scrub::MAX_SECRET_PATTERN_BYTES)
                .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?
                .into_owned();
            let legacy = match source.as_ref() {
                Some(source) if source.fingerprint_version == 0 => Some(
                    crate::scrub::legacy_call_verification_fingerprint(
                        &mut request,
                        source,
                        &patterns,
                    )
                    .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?,
                ),
                Some(source) if source.fingerprint_version == 2 => None,
                Some(_) => {
                    return Err(GateError::Host(
                        "The recorded call fingerprint version is invalid".into(),
                    ));
                }
                None => None,
            };
            (matcher, legacy, state.secret_scope())
        };
        if let Some(candidate_plain) = legacy {
            let source = source.ok_or_else(|| {
                GateError::Host("the legacy re-run's recorded source is missing".into())
            })?;
            if source.to.as_ref() != Some(&to.to_pb())
                || source.message_id != message_id
                || source.msg.is_none()
            {
                return Err(GateError::Host(
                    "The legacy call destination or causal identity is invalid".into(),
                ));
            }
            let source_plain =
                crate::scrub::legacy_call_source_fingerprint(&source).map_err(|_| {
                    GateError::Host("The legacy call source fingerprint is invalid".into())
                })?;
            let raw = self.recorded_raw(ordinal).ok_or_else(|| {
                GateError::Host("the legacy re-run's recorded result is missing".into())
            })?;
            let original_subject = raw
                .request
                .as_ref()
                .and_then(|payload| payload.subject.as_deref());
            let original_keyed = self
                .node
                .sealer()
                .effect_fingerprint(original_subject, source_plain.clone());
            if raw.fingerprint != source_plain && raw.fingerprint != original_keyed {
                return Err(GateError::Host(
                    "The legacy call result fingerprint is invalid".into(),
                ));
            }
            if candidate_plain != source_plain {
                return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
            }
            let expected = EffectRequest {
                ordinal,
                kind: kind.into(),
                target: target.clone(),
                fingerprint: original_keyed,
                http: None,
            };
            let record = self
                .recorded_keyed(&expected, &source_plain)?
                .ok_or_else(|| {
                    GateError::Host("The verified legacy call result is missing".into())
                })?;
            // The genuine retained-source pin is a prerequisite for an
            // unsafe successful legacy cleanup, not a fresh effect fallback.
            let (record, cleanup) = legacy_call_disclosure(record, source, &matcher, None)?;
            self.remember_compensation(ordinal, &to, cleanup);
            let outcome = outcome_of_call(&record);
            lock(&self.state).records.push(record);
            return outcome;
        }
        match crate::scrub::call_request(&mut request, &matcher, kronik_log::MAX_RECORD as usize) {
            Ok(()) => {}
            Err(
                crate::scrub::CallRequestError::UnsafeCompensation
                | crate::scrub::CallRequestError::UnsafeMessage,
            ) => {
                for message in [&mut request.msg, &mut request.compensate]
                    .into_iter()
                    .flatten()
                {
                    crate::scrub::wipe_message(message);
                }
                if self.recorded_raw(ordinal).is_some() {
                    return Err(GateError::Prerequisite(ErrorCode::Unavailable));
                }
                let error = ErrorCode::PolicyDenied.as_str().to_owned();
                self.note(self.denied(ordinal, kind, target, error.clone()));
                return Ok(CallOutcome::Failed(error));
            }
            Err(crate::scrub::CallRequestError::Redaction(error)) => {
                return Err(if error == ScrubError::InvalidText {
                    GateError::Host("The call request contains an invalid protected field".into())
                } else {
                    GateError::Prerequisite(ErrorCode::SecretUnavailable)
                });
            }
        }
        request = self.validate_call_carriers(request).await?;
        let subject = request
            .msg
            .as_ref()
            .and_then(|message| message.body.as_ref())
            .and_then(|body| body.subject.clone());
        let encoded = request.encode_to_vec();
        let cleanup = request.compensate.take();
        let msg = request
            .msg
            .take()
            .ok_or_else(|| GateError::Host("The call message is missing".into()))?;
        let plain = blake3::hash(&encoded).as_bytes().to_vec();
        let fingerprint = self
            .node
            .sealer()
            .effect_fingerprint(subject.as_deref(), plain.clone());
        let expected = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: target.clone(),
            fingerprint: fingerprint.clone(),
            http: None,
        };
        if let Some(record) = self.recorded_keyed(&expected, &plain)? {
            if record.successful_call() {
                self.remember_compensation(ordinal, &to, cleanup);
            }
            let outcome = outcome_of_call(&record);
            lock(&self.state).records.push(record);
            return outcome;
        }
        self.begin().await?;
        let mut record = self.base(ordinal, kind, target, fingerprint);
        record.request = tagged(&subject, encoded);
        let (outcome, source, prepared_scope) =
            self.perform_call(ordinal, &to, msg, &message_id).await?;
        if self.node.hold_after_call() {
            std::future::pending::<()>().await;
        }
        let turn_id = match source {
            Some((source, turn_id)) => {
                record.callee_source = Some(source);
                turn_id
            }
            None => String::new(),
        };
        let prepared = prepare_call_outcome(
            &mut record,
            outcome,
            turn_id,
            &matcher,
            self.spec
                .limits
                .effect_response_bytes
                .min(u64::from(kronik_log::MAX_RECORD)) as usize,
            current_scope.as_deref(),
            prepared_scope.as_deref(),
        );
        if prepared
            .as_ref()
            .is_err_and(|error| !matches!(error, GateError::HostRedactionFailure))
        {
            return prepared;
        }
        if record.successful_call() {
            self.remember_compensation(ordinal, &to, cleanup);
        }
        self.record(record).await?;
        prepared
    }

    /// Runs the callee's turn (or returns its saved outcome).
    async fn qualified_call_source(
        &self,
        ordinal: u32,
        to: &ActorRef,
        message_id: &str,
        lsn: u64,
    ) -> Result<pb::ActorSource, GateError> {
        let key = causal::child(&self.spec.causal_key, &self.spec.actor, ordinal);
        let callee = to.to_pb();
        let caller = self.spec.actor.to_pb();
        self.node.actor_source(lsn, |record| {
            let Record::TurnRecord(turn) = record else { return false };
            turn.actor.as_ref() == Some(&callee) && turn.causal_key.as_ref() == Some(&key)
                && matches!(turn.input.as_ref().and_then(|input| input.kind.as_ref()),
                    Some(pb::input::Kind::Message(input)) if input.source == pb::MessageSource::Call as i32
                        && input.sender.as_ref() == Some(&caller) && input.message_id == message_id)
        }).await.map_err(|_| GateError::Prerequisite(ErrorCode::Unavailable))
    }

    async fn perform_call(
        &self,
        ordinal: u32,
        to: &ActorRef,
        msg: pb::Message,
        message_id: &str,
    ) -> Result<
        (
            CallOutcome,
            Option<(pb::ActorSource, String)>,
            Option<Arc<[pb::SecretRef]>>,
        ),
        GateError,
    > {
        if *to == self.spec.actor || self.spec.call_chain.contains(to) {
            return Ok((CallOutcome::Reentrant, None, None));
        }
        if !self.node.kind_exists(&to.kind) {
            return Ok((CallOutcome::NotFound, None, None));
        }
        let node = self.node.clone();
        let saved_id = message_id.to_owned();
        let saved = self
            .node
            .env
            .blocking("read saved call outcome", move || {
                let saved = node
                    .store()
                    .db()
                    .call_outcome(&saved_id)
                    .map_err(|_| GateError::Prerequisite(ErrorCode::Unavailable))?;
                saved
                    .map(|(lsn, mut outcome)| {
                        node.unseal_outcome(&mut outcome);
                        Ok((lsn, map_call_outcome(outcome)?))
                    })
                    .transpose()
            })
            .await
            .ok_or_else(|| GateError::Host("The saved call worker stopped".into()))??;
        if let Some((lsn, outcome)) = saved {
            let source = self
                .qualified_call_source(ordinal, to, message_id, lsn)
                .await?;
            let turn_id = TurnId {
                branch: source.branch.clone(),
                lsn,
            }
            .to_string();
            // No version string or current inventory proves the historical
            // publisher's exact normalization scope.
            return Ok((outcome, Some((source, turn_id)), None));
        }
        let mut chain = self.spec.call_chain.clone();
        chain.push(self.spec.actor.clone());
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Call as i32,
                sender: Some(self.spec.actor.to_pb()),
                msg: Some(msg),
                message_id: message_id.to_owned(),
                sent_logical_time_ms: self.spec.time,
                call_chain: chain.iter().map(ActorRef::to_pb).collect(),
                ..Default::default()
            })),
        };
        let key = causal::child(&self.spec.causal_key, &self.spec.actor, ordinal);
        let rx = self
            .node
            .enqueue_call(to.clone(), input, key, self.spec.time);
        match self
            .node
            .env
            .timeout(self.spec.limits.effect_timeout, rx)
            .await
        {
            Err(_) => Ok((CallOutcome::Timeout, None, None)),
            Ok(Err(_)) => Err(GateError::Prerequisite(ErrorCode::Unavailable)),
            Ok(Ok(Err(error))) => Err(GateError::Host(error.code.as_str().into())),
            Ok(Ok(Ok(result))) => {
                let source = self
                    .qualified_call_source(ordinal, to, message_id, result.turn_id.lsn)
                    .await?;
                let turn_id = TurnId {
                    branch: source.branch.clone(),
                    lsn: source.lsn,
                }
                .to_string();
                Ok((
                    map_call_outcome(result.outcome)?,
                    Some((source, turn_id)),
                    result.scrubbed_with,
                ))
            }
        }
    }

    async fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> Result<CryptoOutcome, GateError> {
        let (kind, alg) = match algorithm {
            CryptoAlgorithm::HmacSha256 => ("crypto.hmac-sha256", "hmac-sha256"),
            CryptoAlgorithm::SignEd25519 => ("crypto.sign-ed25519", "sign-ed25519"),
        };
        let cap = format!("secret:{secret}");
        if self.spec.config.grant(self.kind(), &cap).is_none() {
            let e = not_granted(&cap);
            self.note(self.denied(ordinal, kind, cap, e.clone()));
            return Ok(CryptoOutcome::Denied(e));
        }
        let data_hash = blake3::hash(&data).as_bytes().to_vec();
        let mut h = blake3::Hasher::new();
        h.update(alg.as_bytes());
        h.update(b"\0");
        h.update(secret.as_bytes());
        h.update(b"\0");
        h.update(&data_hash);
        let fp = h.finalize().as_bytes().to_vec();
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: cap.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded(&ereq)? {
            if rec.request.is_some() {
                let request =
                    pb::CryptoEffectRequest::decode(effect_plain_payload(rec.request.as_ref())?)
                        .map_err(|_| {
                            GateError::Host("The recorded crypto request is invalid".into())
                        })?;
                if request.algorithm != alg || request.data_hash != data_hash {
                    return Err(GateError::Host(
                        "The recorded crypto request identity is invalid".into(),
                    ));
                }
                if let Some(reference) = request.secret {
                    if reference.name != secret {
                        return Err(GateError::Host(
                            "The recorded crypto secret identity is invalid".into(),
                        ));
                    }
                    if !reference.is_unresolved() {
                        self.remember_recorded_secret(&reference)?;
                    }
                } else if rec.status == pb::EffectStatus::Ok as i32 {
                    return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
                }
            } else if rec.status == pb::EffectStatus::Ok as i32 {
                return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
            }
            lock(&self.state).records.push(rec.clone());
            return Ok(if rec.status == pb::EffectStatus::Ok as i32 {
                CryptoOutcome::Ok(effect_plain_payload(rec.response.as_ref())?.to_vec())
            } else if rec.status == pb::EffectStatus::Denied as i32 {
                CryptoOutcome::Denied(rec.error)
            } else {
                CryptoOutcome::Unsupported(rec.error)
            });
        }
        self.begin().await?;
        let mut rec = self.base(ordinal, kind, cap, fp);
        let outcome = match self.secret_value(&secret, None).await {
            Ok(None) => {
                rec.status = pb::EffectStatus::Denied as i32;
                rec.error = format!("SECRET_NOT_FOUND: {secret}");
                CryptoOutcome::Denied(rec.error.clone())
            }
            Ok(Some(v)) => {
                let reference = secret_ref(v.meta, String::new())?;
                rec.request = plain(
                    pb::CryptoEffectRequest {
                        algorithm: alg.into(),
                        secret: Some(reference.clone()),
                        data_hash,
                    }
                    .encode_to_vec(),
                );
                let result = match algorithm {
                    CryptoAlgorithm::HmacSha256 => {
                        Ok(kronik_effects::crypto::hmac_sha256(&v.value, &data))
                    }
                    CryptoAlgorithm::SignEd25519 => {
                        kronik_effects::crypto::sign_ed25519(&v.value, &data)
                    }
                };
                self.remember_secret(&reference, Arc::new(Zeroizing::new(v.value)));
                match result {
                    Ok(out) => {
                        rec.status = pb::EffectStatus::Ok as i32;
                        rec.response = plain(out.clone());
                        CryptoOutcome::Ok(out)
                    }
                    Err(e) => {
                        rec.status = pb::EffectStatus::Failed as i32;
                        rec.error = e.clone();
                        CryptoOutcome::Unsupported(e)
                    }
                }
            }
            Err(GateError::Prerequisite(code)) => return Err(GateError::Prerequisite(code)),
            Err(error) => return Err(error),
        };
        self.record(rec).await?;
        Ok(outcome)
    }

    async fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> Result<Result<String, String>, GateError> {
        let kind = "secret.reveal";
        let cap = format!("secret-reveal:{name}");
        if self.spec.config.grant(self.kind(), &cap).is_none() {
            let e = not_granted(&cap);
            self.note(self.denied(ordinal, kind, cap, e.clone()));
            return Ok(Err(e));
        }
        let fp = blake3::hash(format!("reveal\0{name}").as_bytes())
            .as_bytes()
            .to_vec();
        let ereq = EffectRequest {
            ordinal,
            kind: kind.into(),
            target: cap.clone(),
            fingerprint: fp.clone(),
            http: None,
        };
        if let Some(rec) = self.recorded(&ereq)? {
            lock(&self.state).records.push(rec.clone());
            if rec.status != pb::EffectStatus::Ok as i32 {
                return Ok(Err(rec.error));
            }
            let req = pb::RevealEffectRequest::decode(effect_plain_payload(rec.request.as_ref())?)
                .map_err(|_| GateError::Host("The recorded reveal request is invalid".into()))?;
            let reference = req
                .secret
                .ok_or_else(|| GateError::Host("missing recorded secret reference".into()))?;
            let version = reference
                .resolved_version()
                .map_err(|e| GateError::Host(e.to_string()))?;
            if reference.name != name {
                return Err(GateError::Host("recorded secret name mismatch".into()));
            }
            return Ok(match self.secret_value(&name, Some(version)).await? {
                Some(v) => {
                    if v.meta.version_hash != reference.version_hash {
                        return Err(GateError::Prerequisite(ErrorCode::SecretVersionGone));
                    }
                    let bytes = Arc::new(Zeroizing::new(v.value));
                    self.remember_secret(&reference, bytes.clone());
                    let revealed = std::str::from_utf8(bytes.as_slice())
                        .map_err(|_| GateError::Prerequisite(ErrorCode::Unavailable))?
                        .to_owned();
                    Ok(revealed)
                }
                None => return Err(GateError::Prerequisite(ErrorCode::SecretVersionGone)),
            });
        }
        self.begin().await?;
        let mut rec = self.base(ordinal, kind, cap, fp);
        let out = match self.secret_value(&name, None).await {
            Ok(None) => {
                rec.status = pb::EffectStatus::Denied as i32;
                rec.error = format!("SECRET_NOT_FOUND: {name}");
                Err(rec.error.clone())
            }
            Ok(Some(v)) => {
                let reference = secret_ref(v.meta, String::new())?;
                rec.request = plain(
                    pb::RevealEffectRequest {
                        secret: Some(reference.clone()),
                    }
                    .encode_to_vec(),
                );
                let bytes = Arc::new(Zeroizing::new(v.value));
                self.remember_secret(&reference, bytes.clone());
                match std::str::from_utf8(bytes.as_slice()) {
                    Ok(value) => {
                        rec.status = pb::EffectStatus::Ok as i32;
                        Ok(value.to_owned())
                    }
                    Err(_) => {
                        rec.status = pb::EffectStatus::Denied as i32;
                        rec.error = ErrorCode::BadRequest.as_str().into();
                        Err(rec.error.clone())
                    }
                }
            }
            Err(GateError::Prerequisite(code)) => return Err(GateError::Prerequisite(code)),
            Err(error) => return Err(error),
        };
        self.record(rec).await?;
        Ok(out)
    }
}

/// The guest-visible result of a recorded fetch.
/// Decode a recorded outcome without turning corrupt/unopenable data into
/// an empty success. Status 11 never reaches any guest HTTP error variant.
pub fn outcome_of_fetch(rec: &pb::EffectRecord) -> Result<FetchOutcome, GateError> {
    Ok(
        match pb::EffectStatus::try_from(rec.status)
            .map_err(|_| GateError::Host("The recorded effect status is invalid".into()))?
        {
            pb::EffectStatus::Ok => {
                let response =
                    pb::HttpEffectResponse::decode(effect_plain_payload(rec.response.as_ref())?)
                        .map_err(|_| {
                            GateError::Host("The recorded HTTP response is invalid".into())
                        })?;
                FetchOutcome::Ok(FetchResponse {
                    status: u16::try_from(response.status).map_err(|_| {
                        GateError::Host("The recorded HTTP status is invalid".into())
                    })?,
                    headers: response
                        .headers
                        .into_iter()
                        .map(|header| (header.name, header.value))
                        .collect(),
                    body: response.body,
                })
            }
            pb::EffectStatus::HostRedactionFailure => FetchOutcome::HostRedactionFailure,
            pb::EffectStatus::Timeout => FetchOutcome::Timeout,
            pb::EffectStatus::TooLarge => FetchOutcome::TooLarge,
            pb::EffectStatus::OutcomeUnknown => FetchOutcome::OutcomeUnknown,
            pb::EffectStatus::Network => FetchOutcome::Network(rec.error.clone()),
            _ => FetchOutcome::Denied(rec.error.clone()),
        },
    )
}

pub fn outcome_of_call(rec: &pb::EffectRecord) -> Result<CallOutcome, GateError> {
    Ok(
        match pb::EffectStatus::try_from(rec.status)
            .map_err(|_| GateError::Host("The recorded call status is invalid".into()))?
        {
            pb::EffectStatus::HostRedactionFailure => return Err(GateError::HostRedactionFailure),
            pb::EffectStatus::Ok => {
                let response =
                    pb::CallEffectResponse::decode(effect_plain_payload(rec.response.as_ref())?)
                        .map_err(|_| {
                            GateError::Host("The recorded call response is invalid".into())
                        })?;
                validate_call_reply(response.reply.as_ref())?;
                CallOutcome::Ok(response.reply)
            }
            pb::EffectStatus::NotFound => CallOutcome::NotFound,
            pb::EffectStatus::Rejected => CallOutcome::Rejected(rec.error.clone()),
            pb::EffectStatus::Reentrant => CallOutcome::Reentrant,
            pb::EffectStatus::Timeout => CallOutcome::Timeout,
            _ => CallOutcome::Failed(rec.error.clone()),
        },
    )
}

/// The callee's turn outcome as the caller sees it.
pub fn map_call_outcome(outcome: pb::Outcome) -> Result<CallOutcome, GateError> {
    let kind = pb::OutcomeKind::try_from(outcome.kind)
        .map_err(|_| GateError::Host("The committed callee outcome kind is invalid".into()))?;
    Ok(match kind {
        pb::OutcomeKind::Committed => CallOutcome::Ok(match outcome.output {
            Some(pb::outcome::Output::Reply(message)) => {
                validate_call_reply(Some(&message))?;
                Some(message)
            }
            Some(pb::outcome::Output::Http(response)) => {
                let Some(pb::body::Value::Inline(body)) = response.body.and_then(|body| body.value)
                else {
                    return Err(GateError::Prerequisite(ErrorCode::Unavailable));
                };
                let message = pb::Message {
                    name: format!("http {}", response.status),
                    content_type: String::new(),
                    body: Some(body),
                    ..Default::default()
                };
                validate_call_reply(Some(&message))?;
                Some(message)
            }
            None => None,
        }),
        pb::OutcomeKind::Rejected => CallOutcome::Rejected(outcome.message),
        pb::OutcomeKind::Unspecified => {
            return Err(GateError::Host(
                "The committed callee outcome kind is missing".into(),
            ));
        }
        _ if outcome.error_code == ErrorCode::ActorNotFound.as_str() => CallOutcome::NotFound,
        _ => CallOutcome::Failed(outcome.message),
    })
}

impl EffectGate for Gate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.fetch(ordinal, req).await })
    }

    fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.call(ordinal, to, msg, compensate).await })
    }

    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.crypto(ordinal, algorithm, secret, data).await })
    }

    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        let fx = self.0.clone();
        Box::pin(async move { fx.reveal(ordinal, name).await })
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn combined_scope_preserves_current_and_historical_identity_coverage() {
        let value = Arc::new(Zeroizing::new(b"credential".to_vec()));
        let identity = |version| pb::SecretRef {
            name: "key".into(),
            version,
            version_hash: vec![version as u8; 16],
            ..Default::default()
        };
        let published: Arc<[pb::SecretRef]> = Arc::from([identity(2)]);
        let snapshot = crate::secrets::CertifiedSecretSnapshot {
            values: vec![("key".into(), value.clone())],
            references: Some(published.clone()),
            fingerprint: [1; 32],
        };
        let held = vec![("key".into(), value.clone())];
        let scope = combined_secret_scope(&snapshot, &held, Some(&[identity(2)]))
            .unwrap()
            .unwrap();
        assert_eq!(scope.as_ref(), published.as_ref());
        let held = vec![("key".into(), value.clone()), ("key".into(), value)];
        let scope = combined_secret_scope(&snapshot, &held, Some(&[identity(1), identity(1)]))
            .unwrap()
            .unwrap();
        assert_eq!(scope.len(), 2);
        assert!(scope.iter().any(|reference| reference.version == 1));
        assert!(scope.iter().any(|reference| reference.version == 2));
        assert!(
            combined_secret_scope(&snapshot, &held, None)
                .unwrap()
                .is_none()
        );
        assert!(
            combined_secret_scope(&snapshot, &held, Some(&[]))
                .unwrap()
                .is_none()
        );
        let unknown = crate::secrets::CertifiedSecretSnapshot {
            values: Vec::new(),
            references: None,
            fingerprint: [2; 32],
        };
        assert!(
            combined_secret_scope(&unknown, &[], Some(&[]))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cleanup_scrub_seed_keeps_values_and_unknown_metadata_cannot_certify_output() {
        let value = Arc::new(Zeroizing::new(b"old credential".to_vec()));
        let identity = pb::SecretRef {
            name: "old".into(),
            version: 1,
            version_hash: vec![1; 16],
            ..Default::default()
        };
        let snapshot = crate::secrets::CertifiedSecretSnapshot {
            values: vec![("old".into(), value.clone())],
            references: Some(Arc::from([identity])),
            fingerprint: [1; 32],
        };
        let mut state = FxState::default();
        state.seed_scrub_snapshot(&snapshot).unwrap();
        assert_eq!(state.secrets[0].1.as_slice(), b"old credential");
        assert_eq!(state.secret_scope().unwrap()[0].name, "old");
        let unknown = crate::secrets::CertifiedSecretSnapshot {
            values: Vec::new(),
            references: None,
            fingerprint: [2; 32],
        };
        state.seed_scrub_snapshot(&unknown).unwrap();
        assert!(state.secret_scope().is_none());
        assert!(state.take_secret_scope().is_none());
        let mismatched = crate::secrets::CertifiedSecretSnapshot {
            values: vec![("old".into(), value)],
            references: Some(Arc::from([])),
            fingerprint: [3; 32],
        };
        let mut state = FxState::default();
        state.seed_scrub_snapshot(&mismatched).unwrap();
        assert!(state.secret_scope().is_none());
    }

    fn test_message(bytes: &[u8]) -> pb::Message {
        pb::Message {
            name: "message".into(),
            content_type: "text/plain".into(),
            body: plain(bytes.to_vec()),
            ..Default::default()
        }
    }

    #[test]
    fn already_prepared_call_result_is_not_rescrubbed_when_scope_is_proved() {
        let secrets = [("e", b"e".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let reference = pb::SecretRef {
            name: "e".into(),
            version: 1,
            version_hash: vec![1; 16],
            ..Default::default()
        };
        let scope = [reference];
        let reply = test_message(b"[secret:e]");
        let mut record = pb::EffectRecord::default();
        let outcome = prepare_call_outcome(
            &mut record,
            CallOutcome::Ok(Some(reply.clone())),
            "turn".into(),
            &matcher,
            4096,
            Some(&scope),
            Some(&scope),
        )
        .unwrap();
        let CallOutcome::Ok(Some(actual)) = outcome else {
            panic!("expected an unchanged reply")
        };
        assert_eq!(actual, reply);
        assert_eq!(record.status, pb::EffectStatus::Ok as i32);
        assert!(record.observed_callee_status.is_none());
    }

    #[test]
    fn unknown_call_scope_with_a_match_requires_real_source_before_host_observation() {
        let secrets = [("marker", b"[secret:marker]".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let mut unqualified = pb::EffectRecord::default();
        assert!(matches!(
            prepare_call_outcome(
                &mut unqualified,
                CallOutcome::Ok(Some(test_message(b"[secret:marker]"))),
                "turn".into(),
                &matcher,
                4096,
                None,
                None
            ),
            Err(GateError::Prerequisite(ErrorCode::Unavailable))
        ));
        assert_ne!(
            unqualified.status,
            pb::EffectStatus::HostRedactionFailure as i32
        );
        let mut qualified = pb::EffectRecord {
            callee_source: Some(pb::ActorSource {
                shard: None,
                lsn: 7,
                branch: "main".into(),
            }),
            ..Default::default()
        };
        assert!(matches!(
            prepare_call_outcome(
                &mut qualified,
                CallOutcome::Ok(Some(test_message(b"[secret:marker]"))),
                "turn".into(),
                &matcher,
                4096,
                None,
                None
            ),
            Err(GateError::HostRedactionFailure)
        ));
        assert_eq!(
            qualified.status,
            pb::EffectStatus::HostRedactionFailure as i32
        );
        assert_eq!(
            qualified.observed_callee_status,
            Some(pb::EffectStatus::Ok as i32)
        );
        let response = pb::CallEffectResponse::decode(
            effect_plain_payload(qualified.response.as_ref()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            effect_plain_payload(response.reply.unwrap().body.as_ref()).unwrap(),
            WITHHELD_EFFECT_BODY
        );
    }

    #[test]
    fn successful_call_reply_requires_a_real_plain_body_not_an_empty_fallback() {
        assert!(validate_call_reply(None).is_ok());
        assert!(validate_call_reply(Some(&test_message(b""))).is_ok());
        assert!(matches!(
            validate_call_reply(Some(&pb::Message::default())),
            Err(GateError::Prerequisite(ErrorCode::Unavailable))
        ));
    }

    #[test]
    fn unsafe_legacy_cleanup_requires_pinned_original_source_and_preserves_original_receipt() {
        let secrets = [("S", b"ab".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let source = pb::CallEffectRequest {
            to: Some(pb::ActorRef {
                kind: "worker".into(),
                key: "destination".into(),
            }),
            msg: Some(test_message(b"safe")),
            compensate: Some(test_message(b"ab")),
            message_id: "original-delivery".into(),
            ..Default::default()
        };
        let original = pb::EffectRecord {
            kind: "actor.call".into(),
            ordinal: 2,
            target: "actor:worker/destination".into(),
            status: pb::EffectStatus::Ok as i32,
            fingerprint: crate::scrub::legacy_call_source_fingerprint(&source).unwrap(),
            request: plain(source.encode_to_vec()),
            response: plain(
                pb::CallEffectResponse {
                    reply: Some(test_message(b"safe reply")),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let bytes = original.encode_to_vec();
        assert!(matches!(
            legacy_call_disclosure(original.clone(), source.clone(), &matcher, None),
            Err(GateError::Prerequisite(ErrorCode::Unavailable))
        ));
        let witness = pb::ActorSource {
            shard: None,
            lsn: 12,
            branch: "main".into(),
        };
        let (projection, cleanup) =
            legacy_call_disclosure(original.clone(), source, &matcher, Some(witness.clone()))
                .unwrap();
        let cleanup = cleanup.unwrap();
        assert_eq!(cleanup.retained_compensation_source, Some(witness));
        assert!(
            cleanup.name.is_empty()
                && cleanup.content_type.is_empty()
                && cleanup.body.is_none()
                && cleanup.blobs.is_empty()
        );
        assert_eq!(
            projection.status,
            pb::EffectStatus::HostRedactionFailure as i32
        );
        assert_eq!(projection.fingerprint, original.fingerprint);
        assert!(projection.callee_source.is_none() && projection.observed_callee_status.is_none());
        let projected_request = pb::CallEffectRequest::decode(
            effect_plain_payload(projection.request.as_ref()).unwrap(),
        )
        .unwrap();
        assert!(projected_request.compensate.is_none());
        assert_eq!(original.encode_to_vec(), bytes);
    }

    fn legacy_http_record(
        source: &pb::HttpEffectRequest,
        status: pb::EffectStatus,
        response: Option<pb::HttpEffectResponse>,
    ) -> pb::EffectRecord {
        pb::EffectRecord {
            kind: "http.fetch".into(),
            status: status as i32,
            ordinal: 3,
            target: format!(
                "http:{}",
                kronik_effects::http::parse_url(&source.url).unwrap().host
            ),
            fingerprint: legacy_http_fingerprint(source).unwrap(),
            request: tagged(&None, source.encode_to_vec()),
            response: response.map(|response| tagged(&None, response.encode_to_vec()).unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn legacy_projection_withholds_the_free_capability_host_without_rewriting_source_identity() {
        let secrets = [("S", b"ab".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "https://ab.example/".into(),
            ..Default::default()
        };
        let original = legacy_http_record(
            &source,
            pb::EffectStatus::Ok,
            Some(pb::HttpEffectResponse {
                status: 200,
                body: b"ok".to_vec(),
                ..Default::default()
            }),
        );
        let original_bytes = original.encode_to_vec();
        assert_eq!(original.target, "http:ab.example");
        let projected = legacy_http_disclosure(original.clone(), &source, &matcher).unwrap();
        assert_eq!(
            projected.status,
            pb::EffectStatus::HostRedactionFailure as i32
        );
        assert_eq!(projected.target, "http:[withheld]");
        assert_eq!(projected.fingerprint, original.fingerprint);
        let response = pb::HttpEffectResponse::decode(
            effect_plain_payload(projected.response.as_ref()).unwrap(),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(original.encode_to_vec(), original_bytes);
    }

    #[test]
    fn legacy_original_uppercase_host_match_is_not_hidden_by_canonical_fingerprinting() {
        let secrets = [("host", b"ABC".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "https://ABC.example/".into(),
            ..Default::default()
        };
        let original = legacy_http_record(
            &source,
            pb::EffectStatus::Ok,
            Some(pb::HttpEffectResponse {
                status: 200,
                body: b"ok".to_vec(),
                ..Default::default()
            }),
        );
        let original_bytes = original.encode_to_vec();
        assert_eq!(original.target, "http:abc.example");
        let mut lower = source.clone();
        lower.url = "https://abc.example/".into();
        assert_eq!(
            legacy_http_fingerprint(&source).unwrap(),
            legacy_http_fingerprint(&lower).unwrap()
        );
        let projection = legacy_http_disclosure(original.clone(), &source, &matcher).unwrap();
        assert_eq!(
            projection.status,
            pb::EffectStatus::HostRedactionFailure as i32
        );
        assert_eq!(projection.target, "http:[withheld]");
        assert_eq!(projection.fingerprint, original.fingerprint);
        assert_eq!(original.encode_to_vec(), original_bytes);
    }

    #[test]
    fn legacy_literal_marker_occurrence_is_not_a_generated_marker_exemption() {
        let secrets = [("marker", b"[secret:marker]".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        for in_request in [false, true] {
            let source = pb::HttpEffectRequest {
                method: "POST".into(),
                url: "http://h/".into(),
                body: if in_request {
                    b"[secret:marker]".to_vec()
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            let original = legacy_http_record(
                &source,
                pb::EffectStatus::Ok,
                Some(pb::HttpEffectResponse {
                    status: 201,
                    body: if in_request {
                        Vec::new()
                    } else {
                        b"[secret:marker]".to_vec()
                    },
                    ..Default::default()
                }),
            );
            let original_bytes = original.encode_to_vec();
            let projected = legacy_http_disclosure(original.clone(), &source, &matcher).unwrap();
            assert_eq!(
                projected.status,
                pb::EffectStatus::HostRedactionFailure as i32
            );
            assert_eq!(projected.fingerprint, original.fingerprint);
            let response = pb::HttpEffectResponse::decode(
                effect_plain_payload(projected.response.as_ref()).unwrap(),
            )
            .unwrap();
            assert_eq!(response.status, 201);
            assert_eq!(response.body, WITHHELD_EFFECT_BODY);
            assert_eq!(original.encode_to_vec(), original_bytes);
        }
    }

    #[test]
    fn legacy_missing_ok_response_is_unknown_not_proof_or_empty_success() {
        let secrets = [("T", b"true".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "http://h/".into(),
            ..Default::default()
        };
        let original = legacy_http_record(&source, pb::EffectStatus::Ok, None);
        assert!(matches!(
            legacy_http_disclosure(original, &source, &matcher),
            Err(GateError::Prerequisite(ErrorCode::SecretUnavailable))
        ));
    }

    #[test]
    fn legacy_nonwire_error_projection_does_not_invent_an_http_response() {
        let secrets = [("T", b"true".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "http://h/".into(),
            ..Default::default()
        };
        for status in [pb::EffectStatus::Network, pb::EffectStatus::Denied] {
            let mut original = legacy_http_record(&source, status, None);
            original.error = "true".into();
            let projected = legacy_http_disclosure(original.clone(), &source, &matcher).unwrap();
            assert_eq!(
                projected.status,
                pb::EffectStatus::HostRedactionFailure as i32
            );
            assert!(projected.response.is_none());
            assert_eq!(original.status, status as i32);
            assert_eq!(original.error, "true");
        }
    }

    #[test]
    fn inline_postwire_redaction_failure_keeps_actual_status_and_original_subject() {
        let secrets = [("A", b"a".as_slice())];
        let matcher = CompiledScrubber::new(&secrets, 1024).unwrap();
        let mut record = pb::EffectRecord::default();
        let outcome = prepare_inline_fetch_response(
            &mut record,
            &Some("subject".into()),
            pb::HttpEffectResponse {
                status: 206,
                body: b"a".to_vec(),
                ..Default::default()
            },
            &matcher,
            0,
        )
        .unwrap();
        assert!(matches!(outcome, FetchOutcome::HostRedactionFailure));
        assert_eq!(record.status, pb::EffectStatus::HostRedactionFailure as i32);
        assert_eq!(
            record.response.as_ref().unwrap().subject.as_deref(),
            Some("subject")
        );
        let response =
            pb::HttpEffectResponse::decode(effect_plain_payload(record.response.as_ref()).unwrap())
                .unwrap();
        assert_eq!(response.status, 206);
        assert_eq!(response.body, WITHHELD_EFFECT_BODY);
    }

    #[test]
    fn effect_references_keep_legacy_wire_and_roundtrip_wide_versions() {
        for version in [
            kronik_proto::secret::LEGACY_SECRET_VERSION_MAX,
            kronik_proto::secret::LEGACY_SECRET_VERSION_MAX + 1,
            kronik_proto::secret::MAX_SECRET_VERSION,
        ] {
            let reference = secret_ref(
                kronik_privacy::SecretMeta {
                    name: "k".into(),
                    version,
                    version_hash: vec![7; 16],
                    created_wall_ms: 0,
                },
                String::new(),
            )
            .unwrap();
            assert_eq!(reference.resolved_version().unwrap(), version);
            if version == kronik_proto::secret::LEGACY_SECRET_VERSION_MAX {
                let mut legacy = vec![0x0a, 1, b'k', 0x18, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x22, 16];
                legacy.extend_from_slice(&[7; 16]);
                assert_eq!(reference.encode_to_vec(), legacy);
            } else {
                assert_eq!(reference.version, 0);
                assert_eq!(reference.wide_version, version);
            }
            let reveal = pb::RevealEffectRequest {
                secret: Some(reference.clone()),
            };
            let decoded =
                pb::RevealEffectRequest::decode(reveal.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded.secret.unwrap().resolved_version().unwrap(), version);
            let crypto = pb::CryptoEffectRequest {
                algorithm: "hmac-sha256".into(),
                secret: Some(reference.clone()),
                data_hash: vec![1; 32],
            };
            let decoded =
                pb::CryptoEffectRequest::decode(crypto.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded.secret.unwrap().resolved_version().unwrap(), version);
            let http = pb::HttpEffectRequest {
                method: "GET".into(),
                url: "https://example.com".into(),
                headers: vec![pb::HttpEffectHeader {
                    name: "authorization".into(),
                    value: Some(pb::http_effect_header::Value::Secret(reference)),
                }],
                body: Vec::new(),
                ..Default::default()
            };
            let decoded = pb::HttpEffectRequest::decode(http.encode_to_vec().as_slice()).unwrap();
            let Some(pb::http_effect_header::Value::Secret(reference)) = &decoded.headers[0].value
            else {
                panic!("missing HTTP secret identity");
            };
            assert_eq!(reference.resolved_version().unwrap(), version);
        }
        for version in [0, kronik_proto::secret::MAX_SECRET_VERSION + 1] {
            assert!(
                secret_ref(
                    kronik_privacy::SecretMeta {
                        name: "k".into(),
                        version,
                        version_hash: vec![7; 16],
                        created_wall_ms: 0,
                    },
                    String::new()
                )
                .is_err()
            );
        }
    }
}
