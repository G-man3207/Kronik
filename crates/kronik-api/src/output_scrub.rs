//! Concrete output policy: preserve producer-owned IDs, enum labels, schema,
//! protocol and positions; scrub display text, user header names, SQL names,
//! error codes and decoded payload bytes. Payload twins derive from one scrub.
//! All free fields share one encoded-output budget; the final bounded writer
//! additionally accounts for fixed structure and JSON escaping.

use std::ops::{Deref, DerefMut};

use kronik_effects::http::{CompiledScrubber, ScrubError};
use kronik_proto::log::v1 as pb;
use kronik_sched::scrub::{MAX_JSON_OUTPUT_BYTES, MAX_SECRET_PATTERN_BYTES};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

use crate::types::*;
use crate::{ApiError, ErrorCode, Result, internal};

pub(super) trait ScrubbedOutput: Serialize {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()>;

    fn scrub_free<N: AsRef<str>, V: AsRef<[u8]>>(&mut self, inventory: &[(N, V)]) -> Result<()> {
        let mut context = Context::new(inventory, MAX_JSON_OUTPUT_BYTES);
        self.scrub_fields(&mut context)?;
        context.finish()
    }
}

/// Only the JSON constructed by `turn_json`, not arbitrary JSON data.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct TurnJson(pub(super) Value);

impl Deref for TurnJson {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.0
    }
}

impl DerefMut for TurnJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

pub(super) struct Context<'a> {
    matcher: Option<CompiledScrubber<'a>>,
    remaining: usize,
    error: Option<ScrubError>,
}

impl<'a> Context<'a> {
    pub(super) fn new<N: AsRef<str>, V: AsRef<[u8]>>(
        inventory: &'a [(N, V)],
        remaining: usize,
    ) -> Self {
        match CompiledScrubber::new_output(inventory, MAX_SECRET_PATTERN_BYTES) {
            Ok(matcher) => Self {
                matcher: Some(matcher),
                remaining,
                error: None,
            },
            Err(error) => Self {
                matcher: None,
                remaining,
                error: Some(error),
            },
        }
    }

    pub(super) fn finish(self) -> Result<()> {
        match self.error {
            Some(error) => Err(scrub_error(error)),
            None => Ok(()),
        }
    }

    /// Validate only this original outcome's scalar phase, without replacing
    /// prepared markers. Opaque bodies and effects need their own source guards.
    /// Kept from the unbuilt WIP checkpoint: the endpoint that calls it has not
    /// landed yet.
    #[allow(dead_code)]
    pub(super) fn prepared_outcome(
        &mut self,
        value: &pb::Outcome,
        current: Option<&[pb::SecretRef]>,
        original: Option<&[pb::SecretRef]>,
    ) -> Result<()> {
        fn plaintext(value: Option<&pb::Sealable>) -> Option<&[u8]> {
            match value.and_then(|value| value.value.as_ref()) {
                Some(pb::sealable::Value::Plain(bytes)) => Some(bytes),
                _ => None,
            }
        }
        let Some(matcher) = self.matcher.as_ref() else {
            return Err(scrub_error(
                self.error.take().unwrap_or(ScrubError::MatcherUnavailable),
            ));
        };
        let host_code = value.kind == pb::OutcomeKind::Trap as i32
            && ErrorCode::parse(&value.error_code).is_some();
        let free = [
            (!host_code).then_some(value.error_code.as_bytes()),
            Some(value.message.as_bytes()),
        ]
        .into_iter()
        .flatten();
        match value.output.as_ref() {
            Some(pb::outcome::Output::Reply(message)) => kronik_sched::scrub::prepared_fields_safe(
                current,
                original,
                matcher,
                free.chain([message.name.as_bytes(), message.content_type.as_bytes()])
                    .chain(plaintext(message.body.as_ref())),
            ),
            Some(pb::outcome::Output::Http(http)) => {
                let headers = http.headers.iter().flat_map(|header| {
                    std::iter::once(header.name.as_bytes()).chain(plaintext(header.value.as_ref()))
                });
                let body = match http.body.as_ref().and_then(|body| body.value.as_ref()) {
                    Some(pb::body::Value::Inline(value)) => plaintext(Some(value)),
                    _ => None,
                };
                kronik_sched::scrub::prepared_fields_safe(
                    current,
                    original,
                    matcher,
                    free.chain(headers).chain(body),
                )
            }
            None => kronik_sched::scrub::prepared_fields_safe(current, original, matcher, free),
        }
        .map_err(scrub_error)
    }
}

pub(super) fn scrub_error(error: ScrubError) -> ApiError {
    match error {
        ScrubError::OutputLimit => ApiError::new(
            ErrorCode::PayloadTooLarge,
            "JSON response exceeds output limit",
        ),
        _ => ApiError::new(ErrorCode::SecretUnavailable, "secret output unavailable"),
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    remaining: usize,
    count: usize,
    collect: bool,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("JSON output limit"));
        }
        if self.collect {
            let required = self.count + bytes.len();
            if required > self.bytes.capacity() {
                let limit = self.count + self.remaining;
                let capacity = self
                    .bytes
                    .capacity()
                    .saturating_mul(2)
                    .max(required)
                    .min(limit);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(|_| io::Error::other("JSON output allocation unavailable"))?;
            }
            self.bytes.extend_from_slice(bytes);
        }
        self.remaining -= bytes.len();
        self.count += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn writer(limit: usize, collect: bool) -> BoundedWriter {
    BoundedWriter {
        bytes: Vec::new(),
        remaining: limit,
        count: 0,
        collect,
        exceeded: false,
    }
}

fn encoded_len<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<usize> {
    let mut output = writer(limit, false);
    if let Err(error) = serde_json::to_writer(&mut output, value) {
        return Err(if output.exceeded {
            scrub_error(ScrubError::OutputLimit)
        } else {
            internal(error)
        });
    }
    Ok(output.count)
}

pub(super) fn bounded_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut output = writer(MAX_JSON_OUTPUT_BYTES, true);
    if let Err(error) = serde_json::to_writer(&mut output, value) {
        return Err(if output.exceeded {
            scrub_error(ScrubError::OutputLimit)
        } else {
            internal(error)
        });
    }
    Ok(output.bytes)
}

fn text(value: &mut String, context: &mut Context<'_>) {
    if context.error.is_some() {
        return;
    }
    let result = context
        .matcher
        .as_ref()
        .ok_or(ScrubError::MatcherUnavailable)
        .and_then(|matcher| matcher.scrub_if_matched(value.as_bytes(), context.remaining));
    match result {
        Ok(Some(clean)) => match String::from_utf8(clean) {
            Ok(clean) => match encoded_len(&clean, context.remaining) {
                Ok(len) => {
                    context.remaining -= len;
                    *value = clean;
                }
                Err(_) => context.error = Some(ScrubError::OutputLimit),
            },
            Err(_) => context.error = Some(ScrubError::InvalidText),
        },
        Ok(None) => match encoded_len(value, context.remaining) {
            Ok(len) => context.remaining -= len,
            Err(_) => context.error = Some(ScrubError::OutputLimit),
        },
        Err(error) => context.error = Some(error),
    }
}

fn persisted_reason(value: &mut String, context: &mut Context<'_>) {
    if context.error.is_some() {
        return;
    }
    *value = kronik_sched::scrub::persisted_audit_reason(
        std::mem::take(value).into(),
        context.matcher.as_ref(),
    )
    .into_owned();
    match encoded_len(value, context.remaining) {
        Ok(len) => context.remaining -= len,
        Err(_) => context.error = Some(ScrubError::OutputLimit),
    }
}

fn optional_text(value: &mut Option<String>, secrets: &mut Context<'_>) {
    if let Some(value) = value {
        text(value, secrets);
    }
}

fn payload(value: &mut Payload, context: &mut Context<'_>) -> Result<()> {
    if let Some(error) = context.error {
        return Err(scrub_error(error));
    }
    // Reject an oversized encoded source before decoding allocates its byte buffer.
    encoded_len(value, MAX_JSON_OUTPUT_BYTES)?;
    let bytes = value
        .to_bytes()
        .map_err(|_| scrub_error(ScrubError::InvalidText))?;
    let clean = context
        .matcher
        .as_ref()
        .ok_or(ScrubError::MatcherUnavailable)
        .and_then(|matcher| matcher.scrub_if_matched(&bytes, context.remaining))
        .map_err(scrub_error)?;
    let Some(clean) = clean else {
        context.remaining -= encoded_len(value, context.remaining)?;
        return Ok(());
    };
    let text = std::str::from_utf8(&clean).ok();
    let base64_len = clean
        .len()
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or_else(|| scrub_error(ScrubError::OutputLimit))?;
    // Include both encoded twins, field names, punctuation and final JSON escaping.
    let text_len = match text {
        Some(text) => encoded_len(text, context.remaining)?,
        None => 0,
    };
    let size = base64_len
        .checked_add(text_len)
        .and_then(|n| n.checked_add(if text.is_some() { 21 } else { 13 }))
        .filter(|n| *n <= context.remaining)
        .ok_or_else(|| scrub_error(ScrubError::OutputLimit))?;
    context.remaining -= size;
    *value = Payload::from_bytes(&clean);
    Ok(())
}

fn input(value: &mut InputSummary, secrets: &mut Context<'_>) {
    let InputSummary { kind: _, summary } = value;
    text(summary, secrets);
}

fn outcome(value: &mut Outcome, secrets: &mut Context<'_>) {
    let Outcome {
        kind: _,
        error_code,
        message,
    } = value;
    optional_text(error_code, secrets);
    optional_text(message, secrets);
}

fn reply(value: &mut Reply, secrets: &mut Context<'_>) -> Result<()> {
    if !value.body_is_exclusive() {
        return Err(ApiError::new(
            ErrorCode::StorageCorrupt,
            "a reply contains both inline data and a body blob",
        ));
    }
    let Reply {
        name,
        content_type,
        body,
        blob,
        blobs: _,
    } = value;
    text(name, secrets);
    text(content_type, secrets);
    if blob.is_none() {
        payload(body, secrets)?;
    }
    Ok(())
}

fn effects(values: &mut [EffectSummary], secrets: &mut Context<'_>) {
    for EffectSummary {
        ordinal: _,
        kind: _,
        target,
        status: _,
        delivery: _,
        error,
        hint,
        request,
        grounding: _,
        simulator: _,
    } in values
    {
        text(target, secrets);
        optional_text(error, secrets);
        optional_text(hint, secrets);
        optional_text(request, secrets);
    }
}

fn summary(value: &mut TurnSummary, secrets: &mut Context<'_>) {
    let TurnSummary {
        turn_id: _,
        lsn: _,
        logical_time_ms: _,
        code_hash: _,
        input: turn_input,
        outcome: turn_outcome,
        writes,
        messages,
        sql_changes: _,
        fuel_used: _,
        effects: turn_effects,
    } = value;

    input(turn_input, secrets);
    outcome(turn_outcome, secrets);
    for WriteSummary {
        op: _,
        key,
        subject: _,
        erased: _,
    } in writes
    {
        text(key, secrets);
    }
    for MessageSummary { to: _, name } in messages {
        text(name, secrets);
    }
    effects(turn_effects, secrets);
}

fn trace_node(value: &mut TraceNode, secrets: &mut Context<'_>) {
    let TraceNode {
        turn_id: _,
        actor: _,
        input: turn_input,
        outcome: turn_outcome,
        children,
    } = value;
    input(turn_input, secrets);
    outcome(turn_outcome, secrets);
    for child in children {
        trace_node(child, secrets);
    }
}

impl ScrubbedOutput for InspectResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let InspectResponse {
            actor: _,
            state,
            sql,
        } = self;
        if let Some(sql) = sql {
            for table in &mut sql.tables {
                text(&mut table.name, secrets);
            }
        }
        for StateEntry {
            key,
            value,
            subject: _,
            lsn: _,
        } in state
        {
            text(key, secrets);
            payload(value, secrets)?;
        }
        Ok(())
    }
}

impl ScrubbedOutput for HistoryResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let HistoryResponse { turns, next: _ } = self;
        for turn in turns {
            summary(turn, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for DeadLettersResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let DeadLettersResponse { dead_letters } = self;
        for DeadLetter {
            id: _,
            actor: _,
            input: turn_input,
            error_code,
            message,
            resent_as: _,
        } in dead_letters
        {
            input(turn_input, secrets);
            text(error_code, secrets);
            text(message, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for ForkTurnResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let ForkTurnResponse {
            fork: _,
            turn_id: _,
            outcome: turn_outcome,
            reply: turn_reply,
            effects: turn_effects,
        } = self;
        outcome(turn_outcome, secrets);
        if let Some(value) = turn_reply {
            reply(value, secrets)?;
        }
        effects(turn_effects, secrets);
        Ok(())
    }
}

impl ScrubbedOutput for TraceResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let TraceResponse {
            turn,
            actor: _,
            root,
            ancestors,
            descendants,
            truncated: _,
        } = self;
        summary(turn, secrets);
        if let Some(TraceRoot {
            lsn: _,
            root_id: _,
            input: turn_input,
        }) = root
        {
            input(turn_input, secrets);
        }
        for turn in ancestors {
            summary(turn, secrets);
        }
        for node in descendants {
            trace_node(node, secrets);
        }
        Ok(())
    }
}

fn json_text(value: &mut Value, secrets: &mut Context<'_>) {
    if let Value::String(value) = value {
        text(value, secrets);
    }
}

fn text_fields(value: &mut Value, fields: &[&str], secrets: &mut Context<'_>) {
    for field in fields {
        if let Some(value) = value.get_mut(*field) {
            json_text(value, secrets);
        }
    }
}

fn json_payload(value: &mut Value, secrets: &mut Context<'_>) -> Result<()> {
    if let Some(error) = secrets.error {
        return Err(scrub_error(error));
    }
    let mut decoded: Payload = serde_json::from_value(std::mem::take(value)).map_err(internal)?;
    payload(&mut decoded, secrets)?;
    *value = serde_json::to_value(decoded).map_err(internal)?;
    Ok(())
}

fn json_sealable(value: &mut Value, secrets: &mut Context<'_>) -> Result<()> {
    if let Some(value) = value.get_mut("value") {
        json_payload(value, secrets)?;
    }
    Ok(())
}

fn sealable_field(value: &mut Value, field: &str, secrets: &mut Context<'_>) -> Result<()> {
    if let Some(value) = value.get_mut(field) {
        json_sealable(value, secrets)?;
    }
    Ok(())
}

fn json_message(value: &mut Value, secrets: &mut Context<'_>) -> Result<()> {
    text_fields(value, &["name", "content_type"], secrets);
    sealable_field(value, "body", secrets)
}

fn message_field(value: &mut Value, field: &str, secrets: &mut Context<'_>) -> Result<()> {
    if let Some(value) = value.get_mut(field) {
        json_message(value, secrets)?;
    }
    Ok(())
}

fn headers(value: &mut Value, secrets: &mut Context<'_>) -> Result<()> {
    if let Some(values) = value.get_mut("headers").and_then(Value::as_array_mut) {
        for value in values {
            text_fields(value, &["name"], secrets);
            sealable_field(value, "value", secrets)?;
        }
    }
    Ok(())
}

impl ScrubbedOutput for TurnJson {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        let turn = &mut self.0;

        if let Some(value) = turn.get_mut("input") {
            match value.get("type").and_then(Value::as_str) {
                Some("http") => {
                    text_fields(value, &["path", "query", "idempotency_key"], secrets);
                    if let Some(params) = value.get_mut("params").and_then(Value::as_array_mut) {
                        for param in params {
                            // param_values() emits (schema name, free value).
                            if let Some(value) = param.get_mut(1) {
                                json_text(value, secrets);
                            }
                        }
                    }
                    headers(value, secrets)?;
                    sealable_field(value, "body", secrets)?;
                }
                Some("message") => {
                    if let Some(Value::String(reason)) = value.get_mut("reason") {
                        persisted_reason(reason, secrets);
                    }
                    message_field(value, "msg", secrets)?;
                }
                Some("timer") => {
                    message_field(value, "msg", secrets)?;
                }
                // Migrate has only numeric schema versions; null has no data.
                _ => {}
            }
        }

        if let Some(value) = turn.get_mut("outcome") {
            text_fields(value, &["error_code", "message"], secrets);
        }
        if let Some(value) = turn.get_mut("output") {
            message_field(value, "reply", secrets)?;
            if let Some(http) = value.get_mut("http") {
                headers(http, secrets)?;
                sealable_field(http, "body", secrets)?;
            }
        }
        if let Some(values) = turn.get_mut("writes").and_then(Value::as_array_mut) {
            for value in values {
                text_fields(value, &["key"], secrets);
                sealable_field(value, "value", secrets)?;
            }
        }
        for field in ["messages", "compensations"] {
            if let Some(values) = turn.get_mut(field).and_then(Value::as_array_mut) {
                for value in values {
                    message_field(value, "msg", secrets)?;
                }
            }
        }
        if let Some(values) = turn.get_mut("sql_schema").and_then(Value::as_array_mut) {
            for value in values {
                json_text(value, secrets);
            }
        }
        if let Some(values) = turn.get_mut("effects").and_then(Value::as_array_mut) {
            for value in values {
                text_fields(value, &["target", "error", "hint", "request"], secrets);
            }
        }
        if let Some(values) = turn.get_mut("timers").and_then(Value::as_array_mut) {
            for value in values {
                text_fields(value, &["name"], secrets);
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for TurnJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use kronik_proto::log::v1 as pb;

    use super::*;

    fn plain(bytes: &[u8]) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
        })
    }

    fn decoded(value: &Value) -> Vec<u8> {
        STANDARD.decode(value["base64"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn inspect_scrubs_free_keys_and_bytes_once_but_keeps_actual_identity() {
        let secrets: Vec<(String, Vec<u8>)> = vec![
            ("token7".into(), b"7".to_vec()),
            ("yes".into(), b"true".to_vec()),
            ("no".into(), b"false".to_vec()),
            ("nil".into(), b"null".to_vec()),
            ("utf8".into(), "λ".as_bytes().to_vec()),
            ("binary".into(), vec![0xff]),
            ("word".into(), b"secret".to_vec()),
        ];
        let expected = "[secret:token7]|[secret:yes]|[secret:no]|[secret:nil]|\
             [secret:utf8]|[secret:binary]|[secret:word]";

        let mut value = InspectResponse {
            actor: Actor {
                kind: "counter".into(),
                key: "7".into(),
                schema_version: 7,
                turns: 7,
                last_turn_id: "main:7".into(),
                sql: true,
            },
            state: vec![StateEntry {
                key: "7".into(),
                value: Payload::from_bytes(b"7|true|false|null|\xce\xbb|\xff|secret"),
                subject: Some("subject7".into()),
                lsn: 7,
            }],
            sql: Some(SqlSummary {
                tables: vec![SqlTable {
                    name: "7".into(),
                    rows: 7,
                }],
            }),
        };
        value.scrub_free(&secrets).unwrap();

        assert_eq!(value.actor.key, "7");
        assert_eq!(value.actor.last_turn_id, "main:7");
        assert!(value.actor.sql);
        assert_eq!(value.state[0].key, "[secret:token7]");
        assert_eq!(value.state[0].subject.as_deref(), Some("subject7"));
        assert_eq!(
            value.state[0].value.to_bytes().unwrap(),
            expected.as_bytes()
        );
        assert_eq!(value.state[0].value.text.as_deref(), Some(expected));
        assert_eq!(
            value.sql.as_ref().unwrap().tables[0].name,
            "[secret:token7]"
        );
    }

    #[test]
    fn actual_turn_schema_keeps_positions_but_not_free_lookalikes() {
        let secrets: Vec<(String, Vec<u8>)> = vec![
            ("token7".into(), b"7".to_vec()),
            ("word".into(), b"secret".to_vec()),
        ];
        let record = pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "counter".into(),
                key: "7".into(),
            }),
            code_hash: vec![7; 32],
            engine_version: "engine7".into(),
            causal_key: Some(pb::CausalKey {
                root: "root7".into(),
                path: vec![],
            }),
            logical_time_ms: 7,
            config_epoch: 7,
            schema_version: 7,
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    method: "GET".into(),
                    path: "/counter/7".into(),
                    query: "v=7".into(),
                    route: "/counter/{key7}".into(),
                    params: vec![pb::Param {
                        name: "key7".into(),
                        value: "7".into(),
                        ..Default::default()
                    }],
                    headers: vec![pb::Header {
                        name: "x7".into(),
                        value: plain(b"7"),
                    }],
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(
                            plain(br#"{"lsn":"7","kind":"7"}"#).unwrap(),
                        )),
                    }),
                    idempotency_key: "7".into(),
                    ..Default::default()
                })),
            }),
            writes: vec![pb::StateWrite {
                op: pb::StateOp::Set as i32,
                key: "7".into(),
                value: plain(b"7"),
            }],
            timers: vec![pb::TimerOp {
                kind: pb::TimerOpKind::Schedule as i32,
                timer_id: 7,
                due_ms: 77,
                msg: Some(pb::Message {
                    name: "7".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                    status: 207,
                    headers: vec![pb::Header {
                        name: "x7".into(),
                        value: plain(b"7"),
                    }],
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(plain(b"7").unwrap())),
                    }),
                })),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut view = crate::turn_json("main", 7, &record);
        view.scrub_free(&secrets).unwrap();
        let value = serde_json::to_value(view).unwrap();

        assert_eq!(value["turn_id"], "main:7");
        assert_eq!(value["actor"], "counter/7");
        assert_eq!(value["engine_version"], "engine7");
        assert_eq!(value["causal_key"]["root"], "root7");
        assert_eq!(value["config_epoch"], 7);
        assert_eq!(value["input"]["type"], "http");
        assert_eq!(value["input"]["method"], "GET");
        assert_eq!(value["input"]["route"], "/counter/{key7}");
        assert_eq!(value["input"]["params"][0][0], "key7");
        assert_eq!(value["input"]["params"][0][1], "[secret:token7]");
        assert_eq!(value["input"]["idempotency_key"], "[secret:token7]");
        assert_eq!(value["input"]["headers"][0]["name"], "x[secret:token7]");
        assert_eq!(
            decoded(&value["input"]["body"]["value"]),
            br#"{"lsn":"[secret:token7]","kind":"[secret:token7]"}"#
        );
        assert_eq!(value["writes"][0]["op"], "set");
        assert_eq!(value["writes"][0]["key"], "[secret:token7]");
        assert_eq!(
            decoded(&value["writes"][0]["value"]["value"]),
            b"[secret:token7]"
        );
        assert_eq!(value["timers"][0]["id"], "7");
        assert_eq!(value["timers"][0]["name"], "[secret:token7]");
        assert_eq!(value["outcome"]["kind"], "committed");
        assert_eq!(value["output"]["http"]["status"], 207);
        assert_eq!(
            value["output"]["http"]["headers"][0]["name"],
            "x[secret:token7]"
        );
        assert_eq!(
            decoded(&value["output"]["http"]["body"]["value"]),
            b"[secret:token7]"
        );
    }

    #[test]
    fn fork_and_dead_letter_views_keep_labels_not_free_label_lookalikes() {
        let secrets: Vec<(String, Vec<u8>)> = vec![
            ("phase".into(), b"failed".to_vec()),
            ("digit".into(), b"7".to_vec()),
        ];
        let mut fork = ForkTurnResponse {
            fork: "fork7".into(),
            turn_id: "fork7:7".into(),
            outcome: Outcome {
                kind: "failed".into(),
                error_code: Some("TURN_FAILED".into()),
                message: Some("failed".into()),
            },
            reply: Some(Reply::inline(
                "failed".into(),
                "7".into(),
                Payload::from_bytes(b"7"),
                Vec::new(),
            )),
            effects: vec![EffectSummary {
                ordinal: 7,
                kind: "http.fetch".into(),
                target: "7".into(),
                status: "failed".into(),
                delivery: Some("replay-safe".into()),
                error: Some("failed".into()),
                hint: Some("7".into()),
                request: Some("7".into()),
                grounding: Some("exact".into()),
                simulator: None,
            }],
        };
        fork.scrub_free(&secrets).unwrap();
        assert_eq!(fork.turn_id, "fork7:7");
        assert_eq!(fork.outcome.kind, "failed");
        assert_eq!(fork.outcome.message.as_deref(), Some("[secret:phase]"));
        assert_eq!(fork.reply.as_ref().unwrap().name, "[secret:phase]");
        assert_eq!(
            fork.reply.as_ref().unwrap().body.to_bytes().unwrap(),
            b"[secret:digit]"
        );
        assert_eq!(fork.effects[0].ordinal, 7);
        assert_eq!(fork.effects[0].status, "failed");
        assert_eq!(fork.effects[0].error.as_deref(), Some("[secret:phase]"));
        assert_eq!(fork.effects[0].target, "[secret:digit]");

        let mut dead = DeadLettersResponse {
            dead_letters: vec![DeadLetter {
                id: "main:7".into(),
                actor: "counter/7".into(),
                input: InputSummary {
                    kind: "message".into(),
                    summary: "7".into(),
                },
                error_code: "TURN_FAILED".into(),
                message: "failed".into(),
                resent_as: Some("main:77".into()),
            }],
        };
        dead.scrub_free(&secrets).unwrap();
        let value = &dead.dead_letters[0];
        assert_eq!(value.id, "main:7");
        assert_eq!(value.actor, "counter/7");
        assert_eq!(value.error_code, "TURN_FAILED");
        assert_eq!(value.resent_as.as_deref(), Some("main:77"));
        assert_eq!(value.input.kind, "message");
        assert_eq!(value.input.summary, "[secret:digit]");
        assert_eq!(value.message, "[secret:phase]");
    }

    #[test]
    fn sibling_payload_twins_and_json_escaping_share_remaining_budget() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("x".into(), b"x".to_vec())];
        let mut context = Context::new(&inventory, 60);
        let mut first = Payload::from_bytes(b"x");
        payload(&mut first, &mut context).unwrap();
        assert_eq!(first.to_bytes().unwrap(), b"[secret:x]");
        let mut second = Payload::from_bytes(b"x");
        assert!(payload(&mut second, &mut context).is_err());
        let mut escaped = String::from("\"\"");
        let mut context = Context::new(&inventory, 5);
        text(&mut escaped, &mut context);
        assert!(matches!(context.error, Some(ScrubError::OutputLimit)));
    }

    #[test]
    fn bounded_writer_rejects_before_extending() {
        let mut output = writer(3, true);
        output.write_all(b"ab").unwrap();
        assert!(output.write_all(b"cd").is_err());
        assert_eq!(output.bytes, b"ab");
    }

    #[test]
    fn partial_utf8_matches_withhold_free_text() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("partial".into(), vec![0xbb])];
        let mut context = Context::new(&inventory, 100);
        let mut value = "λ".to_owned();
        text(&mut value, &mut context);
        assert!(matches!(context.error, Some(ScrubError::InvalidText)));
    }

    #[test]
    fn trace_descendants_share_the_ancestor_budget() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("x".into(), b"x".to_vec())];
        let mut context = Context::new(&inventory, 20);
        let node = |children| TraceNode {
            turn_id: "main:1".into(),
            actor: "counter/key".into(),
            input: InputSummary {
                kind: "message".into(),
                summary: "x".into(),
            },
            outcome: Outcome {
                kind: "committed".into(),
                error_code: None,
                message: None,
            },
            children,
        };
        let mut tree = node(vec![node(Vec::new())]);
        trace_node(&mut tree, &mut context);
        assert!(matches!(context.error, Some(ScrubError::OutputLimit)));
        assert_eq!(tree.turn_id, "main:1");
        assert_eq!(tree.input.kind, "message");
    }

    #[test]
    fn empty_values_count_existing_payload_twins_without_regenerating() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("empty".into(), Vec::new())];
        let mut value = Payload::from_bytes(b"unchanged");
        let original = value.clone();
        let size = encoded_len(&value, 100).unwrap();
        let mut context = Context::new(&inventory, size);
        payload(&mut value, &mut context).unwrap();
        assert_eq!(value, original);
        assert_eq!(context.remaining, 0);
        assert!(payload(&mut value, &mut context).is_err());

        let mut view = serde_json::to_value(&original).unwrap();
        let before = view.clone();
        let mut context = Context::new(&inventory, size);
        json_payload(&mut view, &mut context).unwrap();
        assert_eq!(view, before);
        assert_eq!(context.remaining, 0);
        let error = encoded_len(&value, size - 1).unwrap_err();
        assert_eq!(error.code.http_status(), 413);
    }

    #[test]
    fn one_projection_plan_uses_original_longest_matches_across_free_fields() {
        let inventory: Vec<(String, Vec<u8>)> = vec![
            ("long".into(), b"abc".to_vec()),
            ("short".into(), b"ab".to_vec()),
            ("duplicate".into(), b"abc".to_vec()),
            ("marker".into(), b"secret".to_vec()),
        ];
        let mut context = Context::new(&inventory, 256);
        let mut key = "abc|ab|secret".to_owned();
        text(&mut key, &mut context);
        let mut body = Payload::from_bytes(b"abc|ab|secret");
        payload(&mut body, &mut context).unwrap();
        assert!(context.error.is_none());
        let expected = "[secret:long]|[secret:short]|[secret:marker]";
        assert_eq!(key, expected);
        assert_eq!(body.to_bytes().unwrap(), expected.as_bytes());
        assert_eq!(body.text.as_deref(), Some(expected));
    }

    #[test]
    fn nonmatching_payload_keeps_original_encoding_shape() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("other".into(), b"absent".to_vec())];
        let mut value = Payload {
            text: Some("ordinary".into()),
            base64: None,
        };
        let size = encoded_len(&value, 100).unwrap();
        let mut context = Context::new(&inventory, size);
        payload(&mut value, &mut context).unwrap();
        assert_eq!(value.text.as_deref(), Some("ordinary"));
        assert!(value.base64.is_none());
        assert_eq!(context.remaining, 0);
    }

    #[test]
    fn turn_projection_borrows_shared_zeroizing_inventory_values() {
        let inventory = vec![(
            "retained".to_owned(),
            std::sync::Arc::new(zeroize::Zeroizing::new(b"x".to_vec())),
        )];
        let index: Vec<(&str, &[u8])> = inventory
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let record = pb::TurnRecord {
            writes: vec![pb::StateWrite {
                op: pb::StateOp::Set as i32,
                key: "x".into(),
                value: plain(b"x"),
            }],
            ..Default::default()
        };
        let mut output = crate::turn_json("main", 1, &record);
        output.scrub_free(&index).unwrap();
        assert_eq!(output["turn_id"], "main:1");
        assert_eq!(output["lsn"], 1);
        assert_eq!(output["writes"][0]["op"], "set");
        assert_eq!(output["writes"][0]["key"], "[secret:retained]");
        assert_eq!(
            decoded(&output["writes"][0]["value"]["value"]),
            b"[secret:retained]"
        );
        assert_eq!(inventory[0].1.as_slice(), b"x");
    }

    #[test]
    fn reply_projection_scrubs_inline_data_without_fabricating_bytes_for_blob_identities() {
        let inventory: Vec<(String, Vec<u8>)> = vec![("digit".into(), b"1".to_vec())];
        let identity = BlobReference {
            hash: format!("b3:{}", "11".repeat(32)),
            size: 31,
        };
        let mut blob = Reply::blob("1".into(), "1".into(), identity.clone());
        reply(&mut blob, &mut Context::new(&inventory, 4096)).unwrap();
        let json = serde_json::to_value(&blob).unwrap();
        assert!(!json["name"].as_str().unwrap().contains('1'));
        assert!(!json["content_type"].as_str().unwrap().contains('1'));
        assert!(json.get("text").is_none());
        assert!(json.get("base64").is_none());
        assert_eq!(blob.blob, Some(identity.clone()));

        let mut inline = Reply::inline(
            "reply".into(),
            "text/plain".into(),
            Payload::from_bytes(b"1"),
            vec![identity.clone()],
        );
        reply(&mut inline, &mut Context::new(&inventory, 4096)).unwrap();
        let projected = inline.body.to_bytes().unwrap();
        assert!(!projected.is_empty());
        assert!(!projected.contains(&b'1'));
        assert_eq!(inline.blobs, vec![identity]);
        assert!(inline.blob.is_none());
    }
    #[test]
    fn completed_approval_reasons_use_the_shared_persisted_reason_boundary() {
        for (reason, needle) in [
            ("stored [secret:older] approval reason", "[secret:older]"),
            (
                "a later secret equals the complete approval reason",
                "a later secret equals the complete approval reason",
            ),
        ] {
            let diff_hash = format!("b3:{}", "a".repeat(64));
            let token_id = format!("oidc:{}", "b".repeat(64));
            let mut response: ProposalInfo = serde_json::from_value(serde_json::json!({
                "id": "p-reason-projection", "fork": "reason-projection", "status": "approved",
                "fork_lsn": 1, "verified_through_lsn": 21, "diff_hash": diff_hash,
                "policy": null, "summary": null, "kinds": [],
                "approvals": [{"lsn": 22, "verified_through_lsn": 21, "diff_hash": diff_hash,
                    "token_id": token_id, "reason": reason, "wall_time_ms": 23,
                    "verified_identity": {"state": "VERIFIED", "issuer": "https://issuer.example", "subject": "verified-subject"}}]
            })).unwrap();
            response
                .scrub_free(&[("later", needle.as_bytes())])
                .unwrap();
            let approval = &response.approvals[0];
            assert!(!approval.reason.contains(needle));
            assert_ne!(approval.reason, reason);
            assert_eq!(approval.token_id, token_id);
            assert_eq!(approval.diff_hash, diff_hash);
            assert_eq!(approval.verified_through_lsn, 21);
            assert_eq!(
                approval.verified_identity,
                Some(VerifiedApprovalIdentity::Verified {
                    issuer: "https://issuer.example".into(),
                    subject: "verified-subject".into(),
                })
            );
        }
    }
}

impl ScrubbedOutput for DeploymentsResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for deployment in &mut self.deployments {
            persisted_reason(&mut deployment.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for GrantsResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for grant in &mut self.grants {
            persisted_reason(&mut grant.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for SecretHistoryResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for version in &mut self.versions {
            persisted_reason(&mut version.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for TokenView {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        persisted_reason(&mut self.reason, secrets);
        if let Some(reason) = &mut self.revoke_reason {
            persisted_reason(reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for TokensResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for token in &mut self.tokens {
            token.scrub_fields(secrets)?;
        }
        Ok(())
    }
}

impl ScrubbedOutput for ProposalInfo {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for request in &mut self.approval_requests {
            persisted_reason(&mut request.reason, secrets);
        }
        for approval in &mut self.approvals {
            persisted_reason(&mut approval.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for ProposalsResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for proposal in &mut self.proposals {
            proposal.scrub_fields(secrets)?;
        }
        Ok(())
    }
}

impl ScrubbedOutput for WatchInfo {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        persisted_reason(&mut self.reason, secrets);
        if let Some(stopped) = &mut self.stopped {
            persisted_reason(&mut stopped.reason, secrets);
        }
        for triggered in &mut self.triggered {
            text(&mut triggered.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for WatchesResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for watch in &mut self.watches {
            watch.scrub_fields(secrets)?;
        }
        Ok(())
    }
}

impl ScrubbedOutput for crate::events::WebhookStatus {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        optional_text(&mut self.last_error, secrets);
        Ok(())
    }
}

impl ScrubbedOutput for crate::events::WebhooksResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for webhook in &mut self.webhooks {
            webhook.scrub_fields(secrets)?;
        }
        Ok(())
    }
}

impl ScrubbedOutput for crate::m7::ForeignListResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for foreign in &mut self.foreign {
            persisted_reason(&mut foreign.reason, secrets);
        }
        optional_text(&mut self.unavailable, secrets);
        Ok(())
    }
}

impl ScrubbedOutput for crate::m7::ForeignShowResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        persisted_reason(&mut self.foreign.reason, secrets);
        Ok(())
    }
}

impl ScrubbedOutput for crate::m12::SimulatorsResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        for target in &mut self.targets {
            persisted_reason(&mut target.reason, secrets);
        }
        Ok(())
    }
}

impl ScrubbedOutput for GrantResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        persisted_reason(&mut self.grant.reason, secrets);
        Ok(())
    }
}

impl ScrubbedOutput for TokenCreateResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        self.token.scrub_fields(secrets)
    }
}

impl ScrubbedOutput for TokenRevokeResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        self.token.scrub_fields(secrets)
    }
}

impl ScrubbedOutput for ProposeResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        self.proposal.scrub_fields(secrets)
    }
}

impl ScrubbedOutput for WatchResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        self.watch.scrub_fields(secrets)
    }
}

impl ScrubbedOutput for crate::m7::ForeignAddResponse {
    fn scrub_fields(&mut self, secrets: &mut Context<'_>) -> Result<()> {
        persisted_reason(&mut self.foreign.reason, secrets);
        for warning in &mut self.warnings {
            text(warning, secrets);
        }
        Ok(())
    }
}
