//! Effect simulators (brief, "Simulator-trait"): where an effect's result
//! comes from when it is not performed live. Crash re-runs and forks ask a
//! simulator first; v0.1 has `RecordedMatch` and `FailClosed` (`StubRules`
//! arrives with forks in M3).

use kronik_proto::log::v1 as pb;

/// An effect as seen by a simulator.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectRequest {
    pub ordinal: u32,
    pub kind: String,
    pub target: String,
    pub fingerprint: Vec<u8>,
}

/// A simulated result: the record to hand to the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectResponse {
    pub record: pb::EffectRecord,
}

/// What the simulator may look at: the recorded effects of the matching
/// turn.
pub struct ReplayContext<'a> {
    pub recorded: &'a [pb::EffectRecord],
}

/// The answer when a recorded effect exists at the ordinal but its
/// fingerprint differs: the replay diverged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diverged {
    pub ordinal: u32,
}

pub trait EffectSimulator: Send + Sync {
    fn respond(&self, req: &EffectRequest, ctx: &ReplayContext<'_>) -> Option<EffectResponse>;
}

/// Answers with the recorded result for the same ordinal and fingerprint,
/// marked with `grounding` (`LIVE` for crash re-runs of the same execution,
/// `EXACT` in forks).
pub struct RecordedMatch {
    pub grounding: pb::Grounding,
}

impl RecordedMatch {
    /// Like `respond`, but tells a fingerprint mismatch apart from a missing
    /// record.
    pub fn lookup(
        &self,
        req: &EffectRequest,
        ctx: &ReplayContext<'_>,
    ) -> Result<Option<EffectResponse>, Diverged> {
        let Some(rec) = ctx.recorded.iter().find(|r| r.ordinal == req.ordinal) else {
            return Ok(None);
        };
        if rec.kind != req.kind || rec.fingerprint != req.fingerprint {
            return Err(Diverged {
                ordinal: req.ordinal,
            });
        }
        let mut record = rec.clone();
        record.grounding = self.grounding as i32;
        Ok(Some(EffectResponse { record }))
    }
}

impl EffectSimulator for RecordedMatch {
    fn respond(&self, req: &EffectRequest, ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        self.lookup(req, ctx).ok().flatten()
    }
}

/// Never answers: an effect without a recording is denied (forks, I7).
pub struct FailClosed;

impl EffectSimulator for FailClosed {
    fn respond(&self, _req: &EffectRequest, _ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_match_by_ordinal_and_fingerprint() {
        let rec = pb::EffectRecord {
            ordinal: 2,
            kind: "http.fetch".into(),
            fingerprint: vec![1],
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        };
        let ctx = ReplayContext {
            recorded: std::slice::from_ref(&rec),
        };
        let m = RecordedMatch {
            grounding: pb::Grounding::Exact,
        };
        let req = |ordinal, fp: u8| EffectRequest {
            ordinal,
            kind: "http.fetch".into(),
            target: "http:x".into(),
            fingerprint: vec![fp],
        };
        let hit = m.lookup(&req(2, 1), &ctx).unwrap().unwrap();
        assert_eq!(hit.record.grounding, pb::Grounding::Exact as i32);
        assert!(m.lookup(&req(3, 1), &ctx).unwrap().is_none());
        assert_eq!(m.lookup(&req(2, 9), &ctx), Err(Diverged { ordinal: 2 }));
        assert!(FailClosed.respond(&req(2, 1), &ctx).is_none());
    }
}
