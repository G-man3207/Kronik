//! Secret scrubbing (I8): every exact occurrence of a secret value the turn
//! used or revealed becomes `[secret:<name>]` before anything is written.
//!
//! Scrubbing works on structured fields, never on encoded protobuf bytes: a
//! replacement of another length inside an encoded message breaks its
//! length prefixes. New effect producers prepare their payloads exactly once;
//! recorded facts and admitted cleanup intents are never rescanned at turn
//! finalization. Opaque encrypted values are not plaintext matcher input.
//! Production turns and fork turns use the same functions.

use kronik_effects::http::{CompiledScrubber, ScrubError, ScrubLimits, Target, scrub};
use kronik_proto::log::v1 as pb;
use prost::Message as _;
use zeroize::Zeroize as _;

/// Metadata-only borrowed names and protected value slices.
pub type Secrets<'a> = [(&'a str, &'a [u8])];

/// Aggregate bound for ordinary JSON/control views, not streamed bodies.
pub const MAX_JSON_OUTPUT_BYTES: usize = kronik_log::MAX_RECORD as usize;
/// Bound for the shared matcher's secret values and names.
pub const MAX_SECRET_PATTERN_BYTES: usize = crate::secrets::MAX_INVENTORY_BYTES;

/// Public log positions of the two audit actions whose semantics use them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditPositions {
    Restore { through_lsn: u64 },
    Gap { from: u64, to: u64 },
    MetadataGap { from_index: u64, through_index: u64 },
}

impl AuditPositions {
    /// Validates the action's required positions, never arbitrary free-text keys.
    pub fn parse(
        action: &str,
        details: &std::collections::BTreeMap<String, String>,
    ) -> Result<Option<Self>, &'static str> {
        let position = |field: &str| -> Option<u64> {
            let value = details.get(field)?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            value.parse().ok()
        };
        match action {
            "restore" => position("through_lsn")
                .map(|through_lsn| Some(Self::Restore { through_lsn }))
                .ok_or("restore requires a valid decimal through_lsn"),
            "audit.gap" if details.contains_key("namespace") => {
                let (_, from_index, through_index) =
                    kronik_proto::control::metadata_audit_gap_details(details)
                        .map_err(|_| "audit.gap requires the closed metadata index range")?;
                Ok(Some(Self::MetadataGap {
                    from_index,
                    through_index,
                }))
            }
            "audit.gap" => match (position("from"), position("to")) {
                (Some(from), Some(to)) if from > 0 && from <= to => {
                    Ok(Some(Self::Gap { from, to }))
                }
                _ => Err("audit.gap requires a valid nonempty decimal range"),
            },
            _ => Ok(None),
        }
    }

    /// The validated numeric value of a field in this action's schema.
    pub fn value(self, field: &str) -> Option<u64> {
        match (self, field) {
            (Self::Restore { through_lsn }, "through_lsn") => Some(through_lsn),
            (Self::Gap { from, .. }, "from") => Some(from),
            (Self::Gap { to, .. }, "to") => Some(to),
            (Self::MetadataGap { from_index, .. }, "from_index") => Some(from_index),
            (Self::MetadataGap { through_index, .. }, "through_index") => Some(through_index),
            _ => None,
        }
    }
}

/// The existing record and inventory bounds, also used by the ordinary
/// control views. A caller with a smaller body budget passes that budget.
pub fn limits(output_bytes: usize) -> ScrubLimits {
    ScrubLimits {
        output_bytes,
        pattern_bytes: MAX_SECRET_PATTERN_BYTES,
    }
}

/// The closed HTTP method vocabulary is protocol, not user free text.
pub fn protocol_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
    )
}

fn charge(remaining: &mut usize, bytes: usize) -> Result<(), ScrubError> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or(ScrubError::OutputLimit)?;
    Ok(())
}

fn plain(
    s: &mut pb::Sealable,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    if let Some(pb::sealable::Value::Plain(bytes)) = &mut s.value {
        if let Some(redacted) = matcher.scrub_if_matched(bytes, *remaining)? {
            charge(remaining, redacted.len())?;
            bytes.zeroize();
            *bytes = redacted;
        } else {
            charge(remaining, bytes.len())?;
        }
    } else {
        // Protected ciphertext and opaque controls are not plaintext.
        // Their real key/source validation belongs to the data boundary.
        charge(remaining, s.encoded_len())?;
    }
    Ok(())
}

fn sealable_budget(
    s: &mut Option<pb::Sealable>,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    if let Some(s) = s {
        plain(s, matcher, remaining)?;
    }
    Ok(())
}

/// Raw guest bytes, before sealing.
pub fn sealable<N: AsRef<str>, V: AsRef<[u8]>>(
    s: &mut Option<pb::Sealable>,
    secrets: &[(N, V)],
) -> Result<(), ScrubError> {
    let matcher = CompiledScrubber::new(secrets, MAX_SECRET_PATTERN_BYTES)?;
    let mut remaining = MAX_JSON_OUTPUT_BYTES;
    sealable_budget(s, &matcher, &mut remaining)
}

fn message_fields(
    message: &mut pb::Message,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    text_budget(&mut message.name, matcher, remaining)?;
    text_budget(&mut message.content_type, matcher, remaining)?;
    sealable_budget(&mut message.body, matcher, remaining)
}

fn message_budget(
    m: &mut Option<pb::Message>,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    if let Some(m) = m {
        message_fields(m, matcher, remaining)?;
    }
    Ok(())
}

pub fn message<N: AsRef<str>, V: AsRef<[u8]>>(
    m: &mut Option<pb::Message>,
    secrets: &[(N, V)],
) -> Result<(), ScrubError> {
    let matcher = CompiledScrubber::new(secrets, MAX_SECRET_PATTERN_BYTES)?;
    let mut remaining = MAX_JSON_OUTPUT_BYTES;
    message_budget(m, &matcher, &mut remaining)
}

fn text_budget(
    text: &mut String,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    // A typed host trap has no free message. No occurrence can exist in
    // empty text; do not rebuild a failed pattern plan just to close it.
    if text.is_empty() {
        return Ok(());
    }
    if let Some(redacted) = matcher.scrub_if_matched(text.as_bytes(), *remaining)? {
        let redacted = String::from_utf8(redacted).map_err(|error| {
            let _bytes = zeroize::Zeroizing::new(error.into_bytes());
            ScrubError::InvalidText
        })?;
        charge(remaining, redacted.len())?;
        text.zeroize();
        *text = redacted;
    } else {
        charge(remaining, text.len())?;
    }
    Ok(())
}

/// One free text field using its operation's already compiled policy.
pub fn text(
    value: &mut String,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<(), ScrubError> {
    let mut remaining = output_bytes;
    text_budget(value, matcher, &mut remaining)
}

/// Unjournaled final guest data uses the final set of revealed values.
/// Recorded effects and their prepared compensation intents do not pass
/// through this function: their original admitted inputs are immutable.
pub fn output(
    out: &mut kronik_runtime::TurnOutput,
    matcher: &CompiledScrubber<'_>,
) -> Result<(), ScrubError> {
    // Trap is produced by the runtime's host classifier, never a guest
    // HandlerError. A parseable string alone is not host provenance.
    let host_trap_code = out.outcome.kind == pb::OutcomeKind::Trap as i32
        && kronik_core::error::ErrorCode::parse(&out.outcome.error_code).is_some();
    if out.writes.is_empty()
        && out.messages.is_empty()
        && out.timers.is_empty()
        && out.outcome.message.is_empty()
        && out.outcome.output.is_none()
        && (out.outcome.error_code.is_empty() || host_trap_code)
    {
        return Ok(());
    }
    let mut budget = MAX_JSON_OUTPUT_BYTES;
    let remaining = &mut budget;
    for w in &mut out.writes {
        sealable_budget(&mut w.value, matcher, remaining)?;
    }
    for m in &mut out.messages {
        message_budget(&mut m.msg, matcher, remaining)?;
    }
    for t in &mut out.timers {
        message_budget(&mut t.msg, matcher, remaining)?;
    }
    charge(remaining, out.outcome.error_code.len())?;
    // Guest Rejected/Failed codes remain free text even if they happen to
    // spell an existing Core code. Do not silently change routing symbols.
    if !host_trap_code && matcher.is_match(out.outcome.error_code.as_bytes()) {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    text_budget(&mut out.outcome.message, matcher, remaining)?;
    outcome_budget(&mut out.outcome.output, matcher, remaining)
}

fn outcome_budget(
    o: &mut Option<pb::outcome::Output>,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(), ScrubError> {
    match o {
        Some(pb::outcome::Output::Reply(m)) => message_fields(m, matcher, remaining)?,
        Some(pb::outcome::Output::Http(h)) => {
            for hd in &mut h.headers {
                text_budget(&mut hd.name, matcher, remaining)?;
                if !header_name_valid(&hd.name) {
                    return Err(ScrubError::InvalidText);
                }
                sealable_budget(&mut hd.value, matcher, remaining)?;
            }
            if let Some(pb::Body {
                value: Some(pb::body::Value::Inline(s)),
            }) = &mut h.body
            {
                plain(s, matcher, remaining)?;
            }
        }
        None => {}
    }
    Ok(())
}

pub fn outcome_output<N: AsRef<str>, V: AsRef<[u8]>>(
    o: &mut Option<pb::outcome::Output>,
    secrets: &[(N, V)],
) -> Result<(), ScrubError> {
    if o.is_none() {
        return Ok(());
    }
    let matcher = CompiledScrubber::new(secrets, MAX_SECRET_PATTERN_BYTES)?;
    let mut remaining = MAX_JSON_OUTPUT_BYTES;
    outcome_budget(o, &matcher, &mut remaining)
}

/// Prepare original guest log fields once with the canonical output policy.
/// On failure the caller must withhold the entire event batch.
pub fn logs<N: AsRef<str>, V: AsRef<[u8]>>(
    logs: &mut [kronik_runtime::LogEvent],
    secrets: &[(N, V)],
) -> Result<(), ScrubError> {
    if logs.is_empty() {
        return Ok(());
    }
    let matcher = CompiledScrubber::new_output(secrets, MAX_SECRET_PATTERN_BYTES)?;
    let mut remaining = MAX_JSON_OUTPUT_BYTES;
    for event in logs {
        charge(
            &mut remaining,
            event
                .fields
                .len()
                .checked_mul(2)
                .ok_or(ScrubError::OutputLimit)?,
        )?;
        text_budget(&mut event.message, &matcher, &mut remaining)?;
        for (name, value) in &mut event.fields {
            text_budget(name, &matcher, &mut remaining)?;
            text_budget(value, &matcher, &mut remaining)?;
        }
    }
    Ok(())
}

/// A policy denial is not a matcher/resource failure or a callee outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRequestError {
    UnsafeCompensation,
    UnsafeMessage,
    Redaction(ScrubError),
}

impl From<ScrubError> for CallRequestError {
    fn from(error: ScrubError) -> Self {
        Self::Redaction(error)
    }
}

pub(crate) fn scope_identity(reference: &pb::SecretRef) -> Result<(&str, u64, &[u8]), ScrubError> {
    if !reference.template.is_empty()
        || reference.version_hash.len() != 16
        || !kronik_privacy::valid_name(&reference.name)
    {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    let version = reference
        .resolved_version()
        .map_err(|_| ScrubError::SourceScopeUnavailable)?;
    Ok((&reference.name, version, &reference.version_hash))
}

/// None means UNKNOWN, never a proved empty scope. Both lists must be
/// genuine identity-only metadata of the exact preparation, not inventory
/// names, future turn references, or a scope guessed from an engine string.
pub fn secret_scope_is_subset(
    current: Option<&[pb::SecretRef]>,
    original: Option<&[pb::SecretRef]>,
) -> Result<bool, ScrubError> {
    let (Some(current), Some(original)) = (current, original) else {
        return Ok(false);
    };
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(original.len())
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    for reference in original {
        identities.push(scope_identity(reference)?);
    }
    identities.sort_unstable();
    for reference in current {
        if identities
            .binary_search(&scope_identity(reference)?)
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Inspect PREPARED data, never replace or rescan generated markers. A
/// complete strict source scope proves existing normalization; otherwise
/// any match is ambiguous and cannot authorize disclosure. The caller must
/// supply every free field and separately qualify opaque body references.
pub fn prepared_fields_safe<'a>(
    current: Option<&[pb::SecretRef]>,
    original: Option<&[pb::SecretRef]>,
    matcher: &CompiledScrubber<'_>,
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), ScrubError> {
    if secret_scope_is_subset(current, original)? {
        return Ok(());
    }
    let mut remaining = MAX_JSON_OUTPUT_BYTES;
    for bytes in fields {
        charge(&mut remaining, bytes.len())?;
        if matcher.is_match(bytes) {
            return Err(ScrubError::SourceScopeUnavailable);
        }
    }
    Ok(())
}

/// The one payload decoder for original secret-use identities. Payloads
/// must already be opened by their real key/source path. This does not
/// authorize operational use, fetch a provider, or invent an empty proof.
/// Historical version-0 identities remain inventory, not prepared-byte proof.
pub fn effect_secret_references(
    kind: &str,
    status: i32,
    bytes: &[u8],
) -> Result<Vec<pb::SecretRef>, ScrubError> {
    decode_secret_references(kind, status, bytes, false)
}

fn decode_secret_references(
    kind: &str,
    status: i32,
    bytes: &[u8],
    prepared_http: bool,
) -> Result<Vec<pb::SecretRef>, ScrubError> {
    let mut references: Vec<pb::SecretRef> = match kind {
        "http.fetch" | "foreign.http" => {
            let mut request = pb::HttpEffectRequest::default();
            let decoded = (|| {
                request
                    .merge(bytes)
                    .map_err(|_| ScrubError::SourceScopeUnavailable)?;
                if !matches!(request.fingerprint_version, 0 | 2)
                    || (prepared_http && request.fingerprint_version != 2)
                {
                    return Err(ScrubError::SourceScopeUnavailable);
                }
                let mut references = Vec::new();
                for header in &mut request.headers {
                    match header.value.take() {
                        Some(pb::http_effect_header::Value::Secret(mut reference)) => {
                            reference.template.zeroize();
                            reference.template.clear();
                            references.push(reference);
                        }
                        Some(pb::http_effect_header::Value::Text(mut text)) => text.zeroize(),
                        None => return Err(ScrubError::SourceScopeUnavailable),
                    }
                }
                Ok(references)
            })();
            // A failed merge may have populated only part of the message.
            // Wipe that owned partial input as well as the successful decode.
            request.method.zeroize();
            request.body.zeroize();
            request.url.zeroize();
            for header in &mut request.headers {
                header.name.zeroize();
                match &mut header.value {
                    Some(pb::http_effect_header::Value::Text(text)) => text.zeroize(),
                    Some(pb::http_effect_header::Value::Secret(reference)) => {
                        reference.template.zeroize()
                    }
                    None => {}
                }
            }
            decoded?
        }
        "crypto.hmac-sha256" | "crypto.sign-ed25519" => {
            let mut request = pb::CryptoEffectRequest::default();
            let decoded = request
                .merge(bytes)
                .map_err(|_| ScrubError::SourceScopeUnavailable);
            if let Some(reference) = &mut request.secret {
                reference.template.zeroize();
            }
            request.algorithm.zeroize();
            request.data_hash.zeroize();
            decoded?;
            if status == pb::EffectStatus::Ok as i32 && request.secret.is_none() {
                return Err(ScrubError::SourceScopeUnavailable);
            }
            request.secret.into_iter().collect()
        }
        "secret.reveal" => {
            let mut request = pb::RevealEffectRequest::default();
            let decoded = request
                .merge(bytes)
                .map_err(|_| ScrubError::SourceScopeUnavailable);
            if let Some(reference) = &mut request.secret {
                reference.template.zeroize();
            }
            decoded?;
            if status == pb::EffectStatus::Ok as i32 && request.secret.is_none() {
                return Err(ScrubError::SourceScopeUnavailable);
            }
            request.secret.into_iter().collect()
        }
        _ => Vec::new(),
    };
    references
        .retain(|reference| !(status != pb::EffectStatus::Ok as i32 && reference.is_unresolved()));
    for reference in &mut references {
        reference.template.zeroize();
        reference.template.clear();
        scope_identity(reference)?;
    }
    Ok(references)
}

/// Only the exact opened source prefix can certify already-prepared bytes.
/// This is the shared native/replay/model implementation; no current inventory
/// or future receipt can manufacture the original producer's identity scope.
pub fn original_secret_prefix(
    input: &pb::Input,
    effects: &[pb::EffectRecord],
    ordinal: u32,
) -> Option<std::sync::Arc<[pb::SecretRef]>> {
    if input.kind.as_ref().is_some_and(|kind| matches!(kind,
        pb::input::Kind::Message(input)
            if input.msg.as_ref().is_some_and(|message| message.retained_compensation_source.is_some())))
    {
        // A resolved cleanup can add a scrub-only seed absent from its effects.
        return None;
    }
    if input.kind.is_none() {
        return None;
    }
    let mut prefix = Vec::new();
    for effect in effects.iter().filter(|effect| effect.ordinal <= ordinal) {
        prefix.try_reserve(1).ok()?;
        prefix.push(effect);
    }
    prefix.sort_unstable_by_key(|effect| effect.ordinal);
    if prefix.last().is_none_or(|effect| effect.ordinal != ordinal)
        || prefix
            .windows(2)
            .any(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return None;
    }
    let mut references = Vec::new();
    for effect in prefix {
        if !matches!(
            effect.kind.as_str(),
            "http.fetch"
                | "foreign.http"
                | "crypto.hmac-sha256"
                | "crypto.sign-ed25519"
                | "secret.reveal"
        ) {
            continue;
        }
        let bytes = match effect
            .request
            .as_ref()
            .and_then(|value| value.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(bytes)) => bytes,
            _ => return None,
        };
        // Policy qualification and identity extraction share ONE decode; a
        // separate HTTP pre-decode would copy the whole inline body twice.
        let found = decode_secret_references(&effect.kind, effect.status, bytes, true).ok()?;
        references.try_reserve(found.len()).ok()?;
        references.extend(found);
    }
    Some(std::sync::Arc::from(references))
}

/// Original free message data only. Encrypted payloads and typed reference
/// coordinates are not plaintext; their source/key validation is separate.
pub fn message_contains_sensitive(message: &pb::Message, matcher: &CompiledScrubber<'_>) -> bool {
    matcher.is_match(message.name.as_bytes())
        || matcher.is_match(message.content_type.as_bytes())
        || message
            .body
            .as_ref()
            .is_some_and(|value| match &value.value {
                Some(pb::sealable::Value::Plain(bytes)) => matcher.is_match(bytes),
                _ => false,
            })
}

pub(crate) fn wipe_message(message: &mut pb::Message) {
    message.name.zeroize();
    message.content_type.zeroize();
    if let Some(pb::Sealable {
        value: Some(pb::sealable::Value::Plain(bytes)),
        ..
    }) = &mut message.body
    {
        bytes.zeroize();
    }
}

/// Validate a fresh call without changing either admitted intent. Known
/// plaintext credentials in a call or its compensation cannot enter the
/// callee journal, and replacing them would change the requested action.
pub fn call_request(
    r: &mut pb::CallEffectRequest,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<(), CallRequestError> {
    if r.encoded_len() > output_bytes {
        return Err(ScrubError::OutputLimit.into());
    }
    if [&r.msg, &r.compensate]
        .into_iter()
        .flatten()
        .any(|message| message.retained_compensation_source.is_some())
    {
        return Err(ScrubError::InvalidText.into());
    }
    if r.msg
        .as_ref()
        .is_some_and(|message| message_contains_sensitive(message, matcher))
    {
        return Err(CallRequestError::UnsafeMessage);
    }
    if r.compensate
        .as_ref()
        .is_some_and(|compensation| message_contains_sensitive(compensation, matcher))
    {
        return Err(CallRequestError::UnsafeCompensation);
    }
    r.fingerprint_version = 2;
    if r.encoded_len() > output_bytes {
        return Err(ScrubError::OutputLimit.into());
    }
    Ok(())
}

pub fn call_response(
    r: &mut pb::CallEffectResponse,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<(), ScrubError> {
    let mut remaining = output_bytes;
    message_budget(&mut r.reply, matcher, &mut remaining)
}

fn unescape_component(input: &str, result: &mut Vec<u8>) -> Result<(), ScrubError> {
    result.as_mut_slice().zeroize();
    result.clear();
    result
        .try_reserve(input.len())
        .map_err(|_| ScrubError::OutputLimit)?;
    let bytes = input.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let digit = |b: u8| (b as char).to_digit(16).map(|v| v as u8);
            let high = bytes
                .get(at + 1)
                .copied()
                .and_then(digit)
                .ok_or(ScrubError::InvalidText)?;
            let low = bytes
                .get(at + 2)
                .copied()
                .and_then(digit)
                .ok_or(ScrubError::InvalidText)?;
            result.push(high * 16 + low);
            at += 3;
        } else {
            result.push(bytes[at]);
            at += 1;
        }
    }
    Ok(())
}

/// Tests only original URL data components, never scheme/port/delimiters.
/// The callback uses the SAME compiled matcher as the surrounding operation.
/// Original URLs supply their validated raw host span; prepared targets supply
/// their already-encoded host. Canonical lowercasing cannot prove no raw match.
pub fn http_url_contains(
    target: &Target,
    host_span: &str,
    contains: &dyn Fn(&[u8]) -> bool,
) -> Result<bool, ScrubError> {
    let part = |value: &str| -> Result<bool, ScrubError> {
        if value.is_empty() {
            return Ok(false);
        }
        if value.as_bytes().contains(&b'%') {
            let mut decoded = zeroize::Zeroizing::new(Vec::new());
            unescape_component(value, &mut decoded)?;
            Ok(contains(&decoded))
        } else {
            Ok(contains(value.as_bytes()))
        }
    };
    let host = host_span
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host_span);
    let canonical_host = target
        .host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&target.host);
    let mut canonical_parts = canonical_host.split(['.', ':']);
    for value in host.split(['.', ':']) {
        let canonical = canonical_parts.next().ok_or(ScrubError::InvalidText)?;
        if part(value)? || (value != canonical && part(canonical)?) {
            return Ok(true);
        }
    }
    if canonical_parts.next().is_some() {
        return Err(ScrubError::InvalidText);
    }
    for value in target.path.split('/') {
        if part(value)? {
            return Ok(true);
        }
    }
    for query in target.query.split('&') {
        if let Some((key, value)) = query.split_once('=') {
            if part(key)? || part(value)? {
                return Ok(true);
            }
        } else if part(query)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A component contains data only; grammar separators are copied separately
/// from the original parsed URL. Markers can therefore never become syntax.
fn url_component(
    input: &str,
    canonical: &str,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(String, bool), ScrubError> {
    let mut decoded = zeroize::Zeroizing::new(Vec::new());
    unescape_component(input, &mut decoded)?;
    let mut redacted = matcher
        .scrub_if_matched(&decoded, *remaining)?
        .map(zeroize::Zeroizing::new);
    if redacted.is_none() && input != canonical {
        // Preserve the existing v2 canonical-host normalization only after
        // the ORIGINAL raw component proved no match. Never scan a marker.
        unescape_component(canonical, &mut decoded)?;
        redacted = matcher
            .scrub_if_matched(&decoded, *remaining)?
            .map(zeroize::Zeroizing::new);
    }
    let matched = redacted.is_some();
    let bytes = redacted
        .as_ref()
        .map_or(decoded.as_slice(), |value| value.as_slice());
    let literal = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'~');
    let len = bytes.iter().try_fold(0usize, |len, &b| {
        len.checked_add(if literal(b) { 1 } else { 3 })
            .ok_or(ScrubError::OutputLimit)
    })?;
    charge(remaining, len)?;
    let mut out = String::with_capacity(len);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        if literal(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    Ok((out, matched))
}

fn url_parts(
    input: &str,
    canonical: &str,
    separator: char,
    matcher: &CompiledScrubber<'_>,
    remaining: &mut usize,
) -> Result<(String, bool), ScrubError> {
    let mut result = String::new();
    let mut matched = false;
    let mut canonical_parts = canonical.split(separator);
    for (i, part) in input.split(separator).enumerate() {
        if i > 0 {
            charge(remaining, separator.len_utf8())?;
            result.push(separator);
        }
        let canonical = canonical_parts.next().ok_or(ScrubError::InvalidText)?;
        let (part, part_matched) = url_component(part, canonical, matcher, remaining)?;
        result.push_str(&part);
        matched |= part_matched;
    }
    if canonical_parts.next().is_some() {
        return Err(ScrubError::InvalidText);
    }
    Ok((result, matched))
}

/// Prepares a NEW request for fingerprint version 2. The caller supplies the
/// target it already parsed from the original wire URL. The returned target
/// contains encoded, redacted data components and original grammar only;
/// fingerprint_v2 consumes it directly, without reparsing generated markers.
/// The original request used on the wire is a separate caller-owned value.
/// `raw_host` is borrowed from that original URL's single validated parse,
/// before canonical host lowercasing; it is never a newly parsed locator.
pub fn http_request(
    r: &mut pb::HttpEffectRequest,
    original: &Target,
    raw_host: &str,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<Target, ScrubError> {
    let mut remaining = output_bytes;
    if protocol_method(&r.method) {
        charge(&mut remaining, r.method.len())?;
    } else {
        text_budget(&mut r.method, matcher, &mut remaining)?;
    }
    charge(&mut remaining, original.scheme.len() + 3)?;
    let ipv6 = raw_host.starts_with('[') && raw_host.ends_with(']');
    let host = if ipv6 {
        let original_inner = &raw_host[1..raw_host.len() - 1];
        let canonical_inner = original
            .host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .ok_or(ScrubError::InvalidText)?;
        let mut canonical_groups = canonical_inner.split(':');
        let mut inner = String::new();
        let mut matched = false;
        for (i, group) in original_inner.split(':').enumerate() {
            if i > 0 {
                charge(&mut remaining, 1)?;
                inner.push(':');
            }
            // Dots in an embedded IPv4 address are original IP grammar too.
            let canonical = canonical_groups.next().ok_or(ScrubError::InvalidText)?;
            let (group, group_matched) = url_parts(group, canonical, '.', matcher, &mut remaining)?;
            inner.push_str(&group);
            matched |= group_matched;
        }
        if canonical_groups.next().is_some() {
            return Err(ScrubError::InvalidText);
        }
        if !matched {
            charge(&mut remaining, 2)?;
            format!("[{inner}]")
        } else {
            // A marker is not a hexadecimal IP group. Render the now-opaque
            // host as an escaped reg-name, never invalid text inside IPv6 [].
            let colons = inner.bytes().filter(|&b| b == b':').count();
            charge(
                &mut remaining,
                colons.checked_mul(2).ok_or(ScrubError::OutputLimit)?,
            )?;
            inner.replace(':', "%3a")
        }
    } else {
        url_parts(raw_host, &original.host, '.', matcher, &mut remaining)?.0
    };
    let port = original
        .port
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    charge(&mut remaining, port.len())?;
    let path = url_parts(&original.path, &original.path, '/', matcher, &mut remaining)?.0;
    let mut query = String::new();
    if !original.query.is_empty() {
        charge(&mut remaining, 1)?;
        for (i, item) in original.query.split('&').enumerate() {
            if i > 0 {
                charge(&mut remaining, 1)?;
                query.push('&');
            }
            if let Some((key, value)) = item.split_once('=') {
                query.push_str(&url_component(key, key, matcher, &mut remaining)?.0);
                charge(&mut remaining, 1)?;
                query.push('=');
                query.push_str(&url_component(value, value, matcher, &mut remaining)?.0);
            } else {
                query.push_str(&url_component(item, item, matcher, &mut remaining)?.0);
            }
        }
    }
    let target = Target {
        scheme: original.scheme.clone(),
        host,
        port: original.port,
        path,
        query,
    };
    let query_prefix = if original.query.is_empty() { "" } else { "?" };
    let url = format!(
        "{}://{}{}{}{}{}",
        target.scheme, target.host, port, target.path, query_prefix, target.query
    );
    r.url.zeroize();
    r.url = url;
    for h in &mut r.headers {
        text_budget(&mut h.name, matcher, &mut remaining)?;
        match &mut h.value {
            Some(pb::http_effect_header::Value::Text(text)) => {
                text_budget(text, matcher, &mut remaining)?
            }
            Some(pb::http_effect_header::Value::Secret(reference)) => {
                // The placeholder is protocol syntax. Only its original free
                // literal segments are matched; the wire template is untouched.
                let mut template = String::new();
                for (i, part) in reference.template.split("{}").enumerate() {
                    if i > 0 {
                        charge(&mut remaining, 2)?;
                        template.push_str("{}");
                    }
                    if let Some(part) = matcher.scrub_if_matched(part.as_bytes(), remaining)? {
                        let part = String::from_utf8(part).map_err(|error| {
                            let _bytes = zeroize::Zeroizing::new(error.into_bytes());
                            ScrubError::InvalidText
                        })?;
                        charge(&mut remaining, part.len())?;
                        template.push_str(&part);
                    } else {
                        charge(&mut remaining, part.len())?;
                        template.push_str(part);
                    }
                }
                reference.template.zeroize();
                reference.template = template;
            }
            None => {}
        }
    }
    if let Some(redacted) = matcher.scrub_if_matched(&r.body, remaining)? {
        charge(&mut remaining, redacted.len())?;
        r.body.zeroize();
        r.body = redacted;
    } else {
        charge(&mut remaining, r.body.len())?;
    }
    r.fingerprint_version = 2;
    Ok(target)
}

fn header_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Response headers and raw body share ONE actual response budget.
pub fn http_response(
    r: &mut pb::HttpEffectResponse,
    matcher: &CompiledScrubber<'_>,
    output_bytes: usize,
) -> Result<(), ScrubError> {
    let mut budget = output_bytes;
    let remaining = &mut budget;
    for h in &mut r.headers {
        text_budget(&mut h.name, matcher, remaining)?;
        // Actual HTTP response headers must remain representable by every
        // guest HTTP frontend. A redacted arbitrary name can cease to be a
        // token: the producer then records the truthful status and WITHHELD
        // result, and terminates with the typed host-redaction failure.
        if !header_name_valid(&h.name) {
            return Err(ScrubError::InvalidText);
        }
        text_budget(&mut h.value, matcher, remaining)?;
    }
    if let Some(redacted) = matcher.scrub_if_matched(&r.body, *remaining)? {
        charge(remaining, redacted.len())?;
        r.body.zeroize();
        r.body = redacted;
    } else {
        charge(remaining, r.body.len())?;
    }
    Ok(())
}

/// Operator text is matched once against BOTH original token bytes and
/// original secret values. Generated markers never become another input.
pub fn for_log(text: &str, secrets: Option<&Secrets<'_>>) -> String {
    let Some(secrets) = secrets else {
        return WITHHELD.to_owned();
    };
    original_text(text, secrets).unwrap_or_else(|_| WITHHELD.to_owned())
}

/// Project an already-persisted audit reason, never mutable operator input.
/// Without proved marker provenance a current match withholds the WHOLE field;
/// generated markers must not become input to another replacement pass.
/// Reuse the caller's compiled OUTPUT plan. Inventory/certificate failures
/// remain the caller's errors; a withheld field never certifies completeness.
pub fn persisted_audit_reason<'a>(
    mut reason: std::borrow::Cow<'a, str>,
    matcher: Option<&CompiledScrubber<'_>>,
) -> std::borrow::Cow<'a, str> {
    if matcher.is_none_or(|matcher| matcher.is_match(reason.as_bytes())) {
        if let std::borrow::Cow::Owned(text) = &mut reason {
            text.zeroize();
        }
        std::borrow::Cow::Borrowed(WITHHELD)
    } else {
        reason
    }
}
pub fn for_target(text: &str, secrets: Option<&Secrets<'_>>) -> String {
    match secrets {
        Some(secrets) => for_log(text, Some(secrets)),
        None => original_text(text, &[]).unwrap_or_else(|_| WITHHELD.to_owned()),
    }
}

pub const WITHHELD: &str = "[withheld: secrets could not be loaded]";

fn original_text(text: &str, secrets: &Secrets<'_>) -> Result<String, ScrubError> {
    let matcher = CompiledScrubber::new_output(secrets, MAX_SECRET_PATTERN_BYTES)?;
    match matcher.scrub_if_matched(text.as_bytes(), MAX_JSON_OUTPUT_BYTES)? {
        Some(bytes) => String::from_utf8(bytes).map_err(|error| {
            let _bytes = zeroize::Zeroizing::new(error.into_bytes());
            ScrubError::InvalidText
        }),
        None if text.len() <= MAX_JSON_OUTPUT_BYTES => Ok(text.to_owned()),
        None => Err(ScrubError::OutputLimit),
    }
}

fn legacy_bytes<N: AsRef<str>, V: AsRef<[u8]>>(
    input: &[u8],
    secrets: &[(N, V)],
) -> Result<Vec<u8>, ScrubError> {
    let old: Vec<(&str, &[u8])> = secrets
        .iter()
        .filter(|(_, value)| {
            let value = value.as_ref();
            value.len() >= 4
                && value.len() <= input.len()
                && !matches!(value, b"true" | b"false" | b"null")
        })
        .map(|(name, value)| (name.as_ref(), value.as_ref()))
        .collect();
    scrub(input, &old, limits(MAX_JSON_OUTPUT_BYTES))
}

/// Digest-only verification of a saved v1 request. NEVER use this on a new
/// writer path or publish its temporary normalized fields. The historical
/// filter/order/lossy text conversion are deliberately confined here.
///
/// The mutable borrow avoids copying the original request values: originals
/// move onto the stack, temporary normalized fields are wiped, and all
/// originals are restored even when verification fails.
pub fn legacy_verification_fingerprint<N: AsRef<str>, V: AsRef<[u8]>>(
    request: &mut pb::HttpEffectRequest,
    source: &pb::HttpEffectRequest,
    secrets: &[(N, V)],
) -> Result<Vec<u8>, ScrubError> {
    if source.fingerprint_version != 0 || !matches!(request.fingerprint_version, 0 | 2) {
        return Err(ScrubError::InvalidText);
    }
    fn text<N: AsRef<str>, V: AsRef<[u8]>>(
        input: &str,
        secrets: &[(N, V)],
    ) -> Result<String, ScrubError> {
        match String::from_utf8(legacy_bytes(input.as_bytes(), secrets)?) {
            Ok(text) => Ok(text),
            Err(error) => {
                // Exact legacy verification ONLY, never a log/read/guest
                // rendering fallback.
                let bytes = zeroize::Zeroizing::new(error.into_bytes());
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }
    let original_version = std::mem::replace(&mut request.fingerprint_version, 0);
    let original_url = std::mem::take(&mut request.url);
    let original_body = std::mem::take(&mut request.body);
    let mut originals = Vec::new();
    let result = (|| {
        request.url = text(&original_url, secrets)?;
        request.body = legacy_bytes(&original_body, secrets)?;
        for (index, header) in request.headers.iter_mut().enumerate() {
            if let Some(pb::http_effect_header::Value::Text(value)) = &mut header.value {
                originals.push((index, std::mem::take(value)));
                *value = text(&originals.last().expect("just pushed").1, secrets)?;
            }
        }
        kronik_effects::http::fingerprint(request).map_err(|_| ScrubError::InvalidText)
    })();
    request.url.zeroize();
    request.url = original_url;
    request.body.zeroize();
    request.body = original_body;
    for (index, original) in originals {
        if let Some(pb::http_effect_header::Value::Text(value)) = &mut request.headers[index].value
        {
            value.zeroize();
            *value = original;
        }
    }
    request.fingerprint_version = original_version;
    result
}

/// The EXISTING v0 digest of the stored legacy call, already normalized by
/// its historical writer. Never normalize this source again or use it for a
/// new writer. Applying its original subject's existing fingerprint key is
/// the caller's separate, existing Sealer::effect_fingerprint operation.
pub fn legacy_call_source_fingerprint(
    source: &pb::CallEffectRequest,
) -> Result<Vec<u8>, ScrubError> {
    if source.fingerprint_version != 0
        || [&source.msg, &source.compensate]
            .into_iter()
            .flatten()
            .any(|message| message.retained_compensation_source.is_some())
    {
        return Err(ScrubError::InvalidText);
    }
    let encoded = zeroize::Zeroizing::new(source.encode_to_vec());
    Ok(blake3::hash(&encoded).as_bytes().to_vec())
}

/// Exact private verification of a saved legacy call. Only its two Plain
/// bodies used the historical filter; names, subject tags, and metadata
/// remain byte-exact. Temporary legacy-normalized bodies never escape.
pub fn legacy_call_verification_fingerprint<N: AsRef<str>, V: AsRef<[u8]>>(
    request: &mut pb::CallEffectRequest,
    source: &pb::CallEffectRequest,
    secrets: &[(N, V)],
) -> Result<Vec<u8>, ScrubError> {
    if source.fingerprint_version != 0 || !matches!(request.fingerprint_version, 0 | 2) {
        return Err(ScrubError::InvalidText);
    }
    let original_version = std::mem::replace(&mut request.fingerprint_version, 0);
    let mut originals = [None, None];
    let result = (|| {
        for (index, message) in [&mut request.msg, &mut request.compensate]
            .into_iter()
            .enumerate()
        {
            if let Some(pb::Message {
                body:
                    Some(pb::Sealable {
                        value: Some(pb::sealable::Value::Plain(bytes)),
                        ..
                    }),
                ..
            }) = message
            {
                originals[index] = Some(std::mem::take(bytes));
                *bytes = legacy_bytes(originals[index].as_deref().expect("just moved"), secrets)?;
            }
        }
        legacy_call_source_fingerprint(request)
    })();
    for (message, original) in [&mut request.msg, &mut request.compensate]
        .into_iter()
        .zip(originals)
    {
        if let Some(original) = original {
            if let Some(pb::Message {
                body:
                    Some(pb::Sealable {
                        value: Some(pb::sealable::Value::Plain(bytes)),
                        ..
                    }),
                ..
            }) = message
            {
                bytes.zeroize();
                *bytes = original;
            }
        }
    }
    request.fingerprint_version = original_version;
    result
}

#[cfg(test)]
mod tests;
