//! Deterministic stratified sampling of root inputs (docs/design/m3-fork.md
//! §6).

use std::collections::BTreeMap;

use crate::index::RootInput;

/// The root inputs to replay in isolated mode for `fraction` in (0, 1]:
/// per stratum (kind and input), the first `ceil(fraction × n)` (at least
/// one) ordered by `blake3(seed + root id)`. Returned in LSN order.
pub fn sample(roots: &[RootInput], seed: &str, fraction: f64) -> Vec<RootInput> {
    if fraction >= 1.0 {
        return roots.to_vec();
    }
    let mut strata: BTreeMap<&str, Vec<(blake3::Hash, &RootInput)>> = BTreeMap::new();
    for r in roots {
        let mut h = blake3::Hasher::new();
        h.update(seed.as_bytes());
        h.update(r.causal_key.root.as_bytes());
        strata
            .entry(&r.stratum)
            .or_default()
            .push((h.finalize(), r));
    }
    let mut out: Vec<RootInput> = Vec::new();
    for (_, mut members) in strata {
        members.sort_by(|a, b| {
            a.0.as_bytes()
                .cmp(b.0.as_bytes())
                .then(a.1.lsn.cmp(&b.1.lsn))
        });
        let take = ((fraction * members.len() as f64).ceil() as usize).clamp(1, members.len());
        out.extend(members.into_iter().take(take).map(|(_, r)| r.clone()));
    }
    out.sort_by_key(|r| r.lsn);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kronik_core::ids::ActorRef;
    use kronik_proto::log::v1 as pb;

    fn root(lsn: u64, stratum: &str) -> RootInput {
        RootInput {
            lsn,
            start_lsn: lsn,
            actor: ActorRef::from_pb(&pb::ActorRef {
                kind: "counter".into(),
                key: "a".into(),
            }),
            causal_key: pb::CausalKey {
                root: format!("{lsn:032x}"),
                path: Vec::new(),
            },
            input: pb::Input::default(),
            logical_time_ms: lsn,
            stratum: stratum.into(),
            subject: None,
        }
    }

    #[test]
    fn stratified_deterministic_and_at_least_one_per_stratum() {
        let mut roots: Vec<RootInput> = (1..=100).map(|l| root(l, "counter POST /x")).collect();
        roots.push(root(101, "counter GET /y"));
        let a = sample(&roots, "p-1", 0.1);
        let b = sample(&roots, "p-1", 0.1);
        let lsns = |v: &[RootInput]| v.iter().map(|r| r.lsn).collect::<Vec<_>>();
        assert_eq!(lsns(&a), lsns(&b));
        assert_eq!(a.len(), 11);
        assert!(a.iter().any(|r| r.lsn == 101));
        assert!(a.windows(2).all(|w| w[0].lsn < w[1].lsn));
        assert_ne!(lsns(&a), lsns(&sample(&roots, "p-2", 0.1)));
        assert_eq!(sample(&roots, "p-1", 1.0).len(), 101);
    }
}
