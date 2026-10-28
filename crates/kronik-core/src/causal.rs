//! Causal keys and the ids derived from them (docs/design/m1-core.md §3).
//!
//! A causal key is the root input's id plus the path of (producing actor,
//! op ordinal) that led to a turn. It is recorded in every turn, so replay
//! and forks derive the same `causal-id`, message ids and idempotency keys.

use kronik_proto::log::v1 as pb;

use crate::ids::{ActorRef, hex};

/// The step ordinal that marks the migrate turn run before an input.
pub const MIGRATE_ORDINAL: u32 = u32::MAX;

/// The step ordinal that marks a compensation (docs/design/m2-effects.md §5).
pub const COMPENSATION_ORDINAL: u32 = u32::MAX - 1;

/// The causal key of a root input.
pub fn root(root_id: String) -> pb::CausalKey {
    pb::CausalKey {
        root: root_id,
        path: Vec::new(),
    }
}

/// The key of a turn produced by `parent`'s turn on `actor` with `ordinal`.
pub fn child(parent: &pb::CausalKey, actor: &ActorRef, ordinal: u32) -> pb::CausalKey {
    let mut key = parent.clone();
    key.path.push(pb::CausalStep {
        actor: Some(actor.to_pb()),
        ordinal,
    });
    key
}

/// The key of the migrate turn that runs on `actor` before the input whose
/// key is `input`.
pub fn migrate(input: &pb::CausalKey, actor: &ActorRef) -> pb::CausalKey {
    child(input, actor, MIGRATE_ORDINAL)
}

/// The key of the compensation for the call made by `caller`'s turn `key`
/// with `ordinal` to `callee`: the callee's call turn key plus a
/// compensation step.
pub fn compensation(
    key: &pb::CausalKey,
    caller: &ActorRef,
    ordinal: u32,
    callee: &ActorRef,
) -> pb::CausalKey {
    child(&child(key, caller, ordinal), callee, COMPENSATION_ORDINAL)
}

/// Canonical byte encoding: `"kronik.causal.v1\0" + root + for each step:
/// kind + "\0" + key + "\0" + u32_le(ordinal)`.
pub fn encode(key: &pb::CausalKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + key.path.len() * 32);
    out.extend_from_slice(b"kronik.causal.v1\0");
    out.extend_from_slice(key.root.as_bytes());
    for step in &key.path {
        let (kind, k) = step
            .actor
            .as_ref()
            .map_or(("", ""), |a| (a.kind.as_str(), a.key.as_str()));
        out.extend_from_slice(kind.as_bytes());
        out.push(0);
        out.extend_from_slice(k.as_bytes());
        out.push(0);
        out.extend_from_slice(&step.ordinal.to_le_bytes());
    }
    out
}

/// The guest-visible `causal-id`: 32 hex characters of BLAKE3(encoding).
pub fn causal_id(key: &pb::CausalKey) -> String {
    hex(&blake3::hash(&encode(key)).as_bytes()[..16])
}

fn with_ordinal(key: &pb::CausalKey, ordinal: u32) -> blake3::Hash {
    let mut bytes = encode(key);
    bytes.extend_from_slice(&ordinal.to_le_bytes());
    blake3::hash(&bytes)
}

/// The id of the message produced by the turn `key` with `ordinal`
/// (32 hex characters). The receiver dedups on it.
pub fn message_id(key: &pb::CausalKey, ordinal: u32) -> String {
    hex(&with_ordinal(key, ordinal).as_bytes()[..16])
}

/// `hex(blake3(causal key + effect ordinal))`, sent as `Idempotency-Key`.
pub fn idempotency_key(key: &pb::CausalKey, ordinal: u32) -> String {
    hex(with_ordinal(key, ordinal).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_ids_are_stable_and_distinct() {
        let a = ActorRef::parse("counter/a").unwrap();
        let r = root("00112233445566778899aabbccddeeff".into());
        let c0 = child(&r, &a, 0);
        let c1 = child(&r, &a, 1);
        assert_ne!(causal_id(&r), causal_id(&c0));
        assert_ne!(causal_id(&c0), causal_id(&c1));
        assert_eq!(causal_id(&c0), causal_id(&child(&r, &a, 0)));
        assert_eq!(causal_id(&r).len(), 32);
        assert_eq!(idempotency_key(&r, 0).len(), 64);
        assert_ne!(idempotency_key(&r, 0), idempotency_key(&r, 1));
        assert!(idempotency_key(&r, 7).starts_with(&message_id(&r, 7)));
        // Golden value: changing the encoding breaks replay identity.
        assert_eq!(
            causal_id(&r),
            hex(
                &blake3::hash(b"kronik.causal.v1\x0000112233445566778899aabbccddeeff").as_bytes()
                    [..16]
            )
        );
    }
}
