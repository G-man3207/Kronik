//! Offline checks over a durable log image: rebuilding state from the log
//! alone (I4), and identity replay of every committed turn through the Wasm
//! code with recorded time, seed and effect results (I1).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use super::ActorState;
use super::log::{EffectOutcome, Record, scan};
use super::state::StateDb;
use crate::env::{BoxFuture, HttpRequest};
use crate::wasm::{Code, EffectGate, TurnSpec};

fn fresh_db() -> Result<StateDb, String> {
    let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
    StateDb::open(conn, None).map_err(|e| e.to_string())
}

/// State built from the log alone, starting from an empty `state.db`.
pub fn rebuild(image: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let s = scan(image).map_err(|c| c.0)?;
    let mut db = fresh_db()?;
    for (lsn, rec) in &s.records {
        db.apply(*lsn, rec)
            .map_err(|e| format!("apply {lsn}: {e}"))?;
    }
    db.dump().map_err(|e| e.to_string())
}

struct RecordedGate(BTreeMap<u32, EffectOutcome>);

impl EffectGate for RecordedGate {
    fn fetch(
        &self,
        ordinal: u32,
        _req: HttpRequest,
    ) -> BoxFuture<'static, Result<EffectOutcome, String>> {
        let r = self
            .0
            .get(&ordinal)
            .cloned()
            .ok_or_else(|| format!("replay: no recording for effect {ordinal}"));
        Box::pin(async move { r })
    }
}

pub struct ReplayReport {
    pub turns: usize,
    pub mismatches: Vec<String>,
    pub state: BTreeMap<String, String>,
}

/// Re-executes every `TurnRecord` in LSN order against state rebuilt up to
/// that point and requires identical outcome, writes, effects and fuel.
pub fn identity_replay(code: &Code, image: &[u8]) -> Result<ReplayReport, String> {
    let s = scan(image).map_err(|c| c.0)?;
    let db = Arc::new(Mutex::new(fresh_db()?));
    let mut turns = 0;
    let mut mismatches = Vec::new();
    for (lsn, rec) in &s.records {
        if let Record::TurnRecord(t) = rec {
            turns += 1;
            let (kind, key) = t.begin.actor.split_once('/').unwrap_or(("counter", ""));
            let spec = TurnSpec {
                kind: kind.into(),
                key: key.into(),
                causal_key: t.begin.causal_key.clone(),
                time_ms: t.begin.time_ms,
                seed: t.begin.seed,
                input: t.begin.input.clone(),
            };
            let reads = Arc::new(ActorState {
                state: db.clone(),
                actor: t.begin.actor.clone(),
            });
            let gate = Arc::new(RecordedGate(t.effects.iter().cloned().collect()));
            let out = futures::executor::block_on(code.run(&spec, reads, gate))?;
            if out.outcome != t.outcome
                || out.writes != t.writes
                || out.effects != t.effects
                || out.fuel != t.fuel
            {
                mismatches.push(format!(
                    "lsn {lsn} {}: recorded {:?}/{:?} fuel {}, replayed {:?}/{:?} fuel {}",
                    t.begin.actor, t.outcome, t.writes, t.fuel, out.outcome, out.writes, out.fuel
                ));
            }
        }
        db.lock()
            .unwrap_or_else(|e| e.into_inner())
            .apply(*lsn, rec)
            .map_err(|e| format!("apply {lsn}: {e}"))?;
    }
    let state = db
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .dump()
        .map_err(|e| e.to_string())?;
    Ok(ReplayReport {
        turns,
        mismatches,
        state,
    })
}
