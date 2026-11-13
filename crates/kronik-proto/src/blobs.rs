//! Every blob reference of a record, in one place (M25/M26, ADR 0118 §3):
//! validation, the blob index, shipping and history walk records through
//! these functions, so a new field that carries a `BlobRef` only has to be
//! added here.
//!
//! A reference is complete wherever the host writes it: `b3:` + 64 lowercase
//! hex characters with no subject and key version 0, or `b3s:` + 64 lowercase
//! hex characters with a valid subject and a key version of at least 1. The
//! references inside sealed effect payloads (`HttpEffectRequest.body_blob`,
//! `HttpEffectResponse.body_blob`) are also listed, in the clear, in
//! `EffectRecord.blobs`, which this module walks; [`check_http_payload_blob`]
//! checks a payload's reference against that list where the payload is
//! decoded.

use std::collections::BTreeMap;

use crate::log::v1 as pb;
use crate::{DecodeError, Record, invalid};

/// The identity prefix of a blob without a subject: BLAKE3 of the content.
pub const PLAIN_PREFIX: &str = "b3:";
/// The identity prefix of a subject's blob: BLAKE3 keyed per subject.
pub const KEYED_PREFIX: &str = "b3s:";
/// The longest subject, in bytes (the keystore's limit).
pub const MAX_SUBJECT_BYTES: usize = 256;

/// Whether `subject` can be a subject: 1 to [`MAX_SUBJECT_BYTES`] bytes of
/// printable ASCII without spaces, such as `user:123`. The one rule the log
/// format and the keystore share.
pub fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_SUBJECT_BYTES
        && subject.bytes().all(|b| b.is_ascii_graphic())
}

/// The 32-byte digest an identity names and whether it is keyed, or why the
/// text is not an identity.
pub fn parse_hash(hash: &str) -> Result<(bool, [u8; 32]), String> {
    let (keyed, hex) = if let Some(hex) = hash.strip_prefix(KEYED_PREFIX) {
        (true, hex)
    } else if let Some(hex) = hash.strip_prefix(PLAIN_PREFIX) {
        (false, hex)
    } else {
        return Err("not b3: or b3s:".into());
    };
    if hex.len() != 64 {
        return Err(format!("{} hex characters, not 64", hex.len()));
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut digest = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        match (nibble(pair[0]), nibble(pair[1])) {
            (Some(high), Some(low)) => digest[i] = high << 4 | low,
            _ => return Err("not lowercase hex".into()),
        }
    }
    Ok((keyed, digest))
}

/// Checks one reference: its identity and whether its subject and key
/// version match its kind.
pub fn validate_ref(r: &pb::BlobRef) -> Result<(), DecodeError> {
    let (keyed, _) = parse_hash(&r.hash).map_err(|why| invalid("BlobRef.hash", why))?;
    match (keyed, r.subject.as_deref(), r.key_version) {
        (false, None, 0) => Ok(()),
        (false, _, _) => Err(invalid(
            "BlobRef",
            "a b3: reference has no subject and key version 0",
        )),
        (true, Some(subject), version) if version >= 1 && valid_subject(subject) => Ok(()),
        (true, _, _) => Err(invalid(
            "BlobRef",
            "a b3s: reference needs a valid subject and a key version of at least 1",
        )),
    }
}

fn message<'a>(m: Option<&'a pb::Message>, out: &mut Vec<&'a pb::BlobRef>) {
    if let Some(m) = m {
        out.extend(&m.blobs);
    }
}

fn body<'a>(b: Option<&'a pb::Body>, out: &mut Vec<&'a pb::BlobRef>) {
    if let Some(pb::Body {
        value: Some(pb::body::Value::Blob(r)),
    }) = b
    {
        out.push(r);
    }
}

/// The references of an input: an HTTP body, a message's or timer's blobs,
/// or the body of a connection's opening request (M24; the gateway never
/// reads one, but a reference there is still a reference).
pub fn input<'a>(i: Option<&'a pb::Input>, out: &mut Vec<&'a pb::BlobRef>) {
    use pb::input::Kind;
    match i.and_then(|i| i.kind.as_ref()) {
        Some(Kind::Http(h)) => body(h.body.as_ref(), out),
        Some(Kind::Message(m)) => message(m.msg.as_ref(), out),
        Some(Kind::Timer(t)) => message(t.msg.as_ref(), out),
        Some(Kind::Connection(c)) => {
            if let Some(pb::connection_input::Event::Open(open)) = &c.event
                && let Some(request) = &open.request
            {
                body(request.body.as_ref(), out);
            }
        }
        Some(Kind::Migrate(_)) | None => {}
    }
}

/// The references of an outcome: a reply's blobs or an HTTP response body.
pub fn outcome<'a>(o: Option<&'a pb::Outcome>, out: &mut Vec<&'a pb::BlobRef>) {
    match o.and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Reply(m)) => message(Some(m), out),
        Some(pb::outcome::Output::Http(h)) => body(h.body.as_ref(), out),
        // A connection's accept decision holds headers only (M24).
        Some(pb::outcome::Output::Accept(_)) | None => {}
    }
}

/// The references a turn record carries: input, effects, messages,
/// compensations, timers, reference operations and outcome, in that order.
pub fn turn<'a>(t: &'a pb::TurnRecord, out: &mut Vec<&'a pb::BlobRef>) {
    input(t.input.as_ref(), out);
    for e in &t.effects {
        out.extend(&e.blobs);
    }
    for m in t.messages.iter().chain(&t.compensations) {
        message(m.msg.as_ref(), out);
    }
    for timer in &t.timers {
        message(timer.msg.as_ref(), out);
    }
    out.extend(t.blob_refs.iter().filter_map(|op| op.blob.as_ref()));
    outcome(t.outcome.as_ref(), out);
}

/// Every reference of `record` outside sealed payloads, in walk order.
pub fn refs(record: &Record) -> Vec<&pb::BlobRef> {
    let mut out = Vec::new();
    match record {
        Record::TurnBegin(b) => input(b.input.as_ref(), &mut out),
        Record::EffectResult(r) => {
            if let Some(e) = &r.effect {
                out.extend(&e.blobs);
            }
        }
        other => {
            if let Some(t) = other.turn() {
                turn(t, &mut out);
            }
        }
    }
    out
}

/// Calls `f` for every reference of `record` outside sealed payloads.
pub fn for_each(record: &Record, f: &mut dyn FnMut(&pb::BlobRef)) {
    refs(record).into_iter().for_each(f);
}

/// Validates every reference of `record`: each is well formed, every
/// reference operation names a blob, and one identity has one size, subject
/// and key version throughout the record.
pub fn validate(record: &Record) -> Result<(), DecodeError> {
    if let Some(t) = record.turn()
        && t.blob_refs.iter().any(|op| op.blob.is_none())
    {
        return Err(invalid("BlobRefOp.blob", "missing"));
    }
    let mut seen: BTreeMap<&str, &pb::BlobRef> = BTreeMap::new();
    for r in refs(record) {
        validate_ref(r)?;
        match seen.get(r.hash.as_str()) {
            Some(first) if *first != r => {
                return Err(invalid(
                    "BlobRef",
                    format!(
                        "{} appears with different size, subject or key version",
                        r.hash
                    ),
                ));
            }
            Some(_) => {}
            None => {
                seen.insert(&r.hash, r);
            }
        }
    }
    Ok(())
}

/// Checks the body of a decoded `HttpEffectRequest` or `HttpEffectResponse`
/// (`body` and `body_blob`) against its effect's `EffectRecord.blobs`: never
/// both an inline body and a blob, and a blob is listed. Callers run it where
/// they decode the payload, since the payload itself may be sealed.
pub fn check_http_payload_blob(
    inline: &[u8],
    body_blob: Option<&pb::BlobRef>,
    listed: &[pb::BlobRef],
) -> Result<(), DecodeError> {
    let Some(r) = body_blob else {
        return Ok(());
    };
    if !inline.is_empty() {
        return Err(invalid("HttpEffect body", "both an inline body and a blob"));
    }
    validate_ref(r)?;
    if !listed.contains(r) {
        return Err(invalid(
            "HttpEffect body_blob",
            "not listed in EffectRecord.blobs",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_ref(byte: u8, size: u64) -> pb::BlobRef {
        pb::BlobRef {
            hash: format!("{PLAIN_PREFIX}{}", format!("{byte:02x}").repeat(32)),
            size,
            subject: None,
            key_version: 0,
        }
    }

    fn keyed_ref(byte: u8, size: u64, subject: &str, version: u32) -> pb::BlobRef {
        pb::BlobRef {
            hash: format!("{KEYED_PREFIX}{}", format!("{byte:02x}").repeat(32)),
            size,
            subject: Some(subject.into()),
            key_version: version,
        }
    }

    #[test]
    fn identities_parse_only_in_their_canonical_form() {
        let r = plain_ref(0xab, 1);
        assert_eq!(parse_hash(&r.hash).unwrap(), (false, [0xab; 32]));
        let k = keyed_ref(0x01, 1, "user:1", 1);
        assert_eq!(parse_hash(&k.hash).unwrap(), (true, [0x01; 32]));
        for bad in [
            String::new(),
            "b3:".into(),
            "sha256:00".into(),
            format!("b3:{}", "AB".repeat(32)),
            format!("b3:{}", "ab".repeat(31)),
            format!("b3:{}", "ab".repeat(33)),
            format!("b3:{}g0", "ab".repeat(31)),
            format!("B3:{}", "ab".repeat(32)),
        ] {
            assert!(parse_hash(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn metadata_must_match_the_kind_of_identity() {
        assert!(validate_ref(&plain_ref(1, 10)).is_ok());
        assert!(validate_ref(&keyed_ref(1, 10, "user:1", 1)).is_ok());
        let mut with_subject = plain_ref(1, 10);
        with_subject.subject = Some("user:1".into());
        let mut with_version = plain_ref(1, 10);
        with_version.key_version = 1;
        let mut keyed_without_subject = keyed_ref(1, 10, "user:1", 1);
        keyed_without_subject.subject = None;
        for bad in [
            with_subject,
            with_version,
            keyed_without_subject,
            keyed_ref(1, 10, "user:1", 0),
            keyed_ref(1, 10, "user 1", 1),
            keyed_ref(1, 10, "", 1),
            keyed_ref(1, 10, &"x".repeat(257), 1),
        ] {
            assert!(validate_ref(&bad).is_err(), "{bad:?}");
        }
    }

    fn message_with(blobs: Vec<pb::BlobRef>) -> pb::Message {
        pb::Message {
            name: "m".into(),
            body: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(vec![])),
            }),
            blobs,
            ..Default::default()
        }
    }

    fn turn_with_every_reference() -> pb::TurnRecord {
        pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Blob(plain_ref(1, 1))),
                    }),
                    ..Default::default()
                })),
            }),
            effects: vec![pb::EffectRecord {
                blobs: vec![plain_ref(2, 2)],
                ..Default::default()
            }],
            messages: vec![pb::OutboundMessage {
                msg: Some(message_with(vec![plain_ref(3, 3)])),
                ..Default::default()
            }],
            compensations: vec![pb::OutboundMessage {
                msg: Some(message_with(vec![plain_ref(4, 4)])),
                ..Default::default()
            }],
            timers: vec![pb::TimerOp {
                msg: Some(message_with(vec![plain_ref(5, 5)])),
                ..Default::default()
            }],
            blob_refs: vec![pb::BlobRefOp {
                kind: pb::blob_ref_op::Kind::Retain as i32,
                blob: Some(keyed_ref(6, 6, "user:1", 2)),
            }],
            outcome: Some(pb::Outcome {
                output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Blob(plain_ref(7, 7))),
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn every_place_a_turn_carries_a_reference_is_walked() {
        let record = Record::TurnRecord(turn_with_every_reference());
        let sizes: Vec<u64> = refs(&record).iter().map(|r| r.size).collect();
        assert_eq!(sizes, [1, 2, 3, 4, 5, 6, 7]);
        let mut visited = Vec::new();
        for_each(&record, &mut |r| visited.push(r.size));
        assert_eq!(visited, sizes);

        // A rebased turn carries the same references.
        let rebased = Record::StateRebase(pb::StateRebase {
            rebase_id: "r-1".into(),
            part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
                fork_lsn: 9,
                record: Some(turn_with_every_reference()),
            })),
        });
        assert_eq!(refs(&rebased).len(), 7);

        let begin = Record::TurnBegin(pb::TurnBegin {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Timer(pb::TimerInput {
                    msg: Some(message_with(vec![plain_ref(8, 8)])),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        });
        assert_eq!(refs(&begin).len(), 1);
        let result = Record::EffectResult(pb::EffectResult {
            execution_id: "e".into(),
            effect: Some(pb::EffectRecord {
                blobs: vec![plain_ref(9, 9), plain_ref(10, 10)],
                ..Default::default()
            }),
        });
        assert_eq!(refs(&result).len(), 2);
    }

    #[test]
    fn a_record_names_one_identity_one_way() {
        let mut t = turn_with_every_reference();
        assert!(validate(&Record::TurnRecord(t.clone())).is_ok());
        // The same blob twice, consistently: fine.
        t.messages[0]
            .msg
            .as_mut()
            .unwrap()
            .blobs
            .push(plain_ref(1, 1));
        assert!(validate(&Record::TurnRecord(t.clone())).is_ok());
        // The same identity with another size: corrupt.
        t.messages[0]
            .msg
            .as_mut()
            .unwrap()
            .blobs
            .push(plain_ref(1, 99));
        assert!(validate(&Record::TurnRecord(t)).is_err());

        let mut t = turn_with_every_reference();
        t.blob_refs[0].blob = None;
        assert!(validate(&Record::TurnRecord(t)).is_err());
    }

    #[test]
    fn a_payload_holds_an_inline_body_or_a_listed_blob() {
        let r = plain_ref(1, 3);
        assert!(check_http_payload_blob(b"abc", None, &[]).is_ok());
        assert!(check_http_payload_blob(b"", Some(&r), std::slice::from_ref(&r)).is_ok());
        assert!(check_http_payload_blob(b"abc", Some(&r), std::slice::from_ref(&r)).is_err());
        assert!(check_http_payload_blob(b"", Some(&r), &[]).is_err());
        let other = plain_ref(2, 3);
        assert!(check_http_payload_blob(b"", Some(&r), &[other]).is_err());
    }
}
