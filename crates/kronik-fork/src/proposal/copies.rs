//! A fork's copies of `fork_mode = "sandbox"` foreign actors
//! (docs/design/m14-foreign-forks.md §4, ADR 0019): started from the
//! nearest checkpoint, brought to the fork point with main's recorded
//! calls, stopped with the fork's live state.

use kronik_core::env::Env;
use kronik_effects::foreign::{CopySpec, ForeignCopy};

use super::*;
use crate::diff::ForeignFork;
use crate::replay::ForkCopies;

/// The copies a fork's live replay state holds; stopped when dropped.
pub(super) struct Copies {
    env: Env,
    copies: BTreeMap<String, Arc<dyn ForeignCopy>>,
}

impl Copies {
    pub(super) fn fork(&self) -> ForkCopies {
        ForkCopies {
            env: self.env.clone(),
            copies: self.copies.clone(),
        }
    }

    /// Stops every copy now (the fork's directory is deleted next).
    pub(super) async fn stop(mut self) {
        for (_, c) in std::mem::take(&mut self.copies) {
            c.stop().await;
        }
    }
}

impl Drop for Copies {
    fn drop(&mut self) {
        for (_, c) in std::mem::take(&mut self.copies) {
            self.env
                .spawn("fork-copy-stop", async move { c.stop().await });
        }
    }
}

/// Why a replay starts no copies (`options.foreign[].why`).
pub(super) const DRY_RUN: &str = "a dry run starts no copies";
pub(super) const PREVIEW: &str = "a preview starts no copies";
pub(super) const REBASE: &str = "a rollback via replay answers from production's recordings only";
const NO_PII: &str = "a fork without personal data gets no copies";

/// Stops the copies of a fork's live state, if any, and waits for it: a
/// new replay's copies must not start while old ones are being stopped.
pub(super) async fn retire(live: Option<Live>) {
    if let Some(c) = live.and_then(|mut l| l.copies.take()) {
        c.stop().await;
    }
}

impl Proposals {
    /// Starts the copies of the fork `id` for its continuous replay: every
    /// `sandbox` actor of the fork's configuration with a checkpoint at or
    /// before `fork_lsn`. Returns them and what the diff says about each.
    /// `skip`: why this replay starts none (a dry run, a rebase); a fork
    /// without personal data starts none either.
    pub(super) async fn start_copies(
        &self,
        id: &str,
        index: &ProductionIndex,
        fork_lsn: Lsn,
        no_pii: bool,
        skip: Option<&str>,
    ) -> Result<(Option<Copies>, Vec<ForeignFork>), ApiError> {
        let config = crate::config_at(index, fork_lsn);
        let sandboxed: Vec<String> = config
            .foreign_actors()
            .filter(|f| f.fork_mode == "sandbox")
            .map(|f| f.name.clone())
            .collect();
        if sandboxed.is_empty() {
            return Ok((None, Vec::new()));
        }
        let skip = skip.or(no_pii.then_some(NO_PII));
        let host = self.node.foreign_host();
        // The fork re-runs these roots: their calls must not reach the copy
        // twice.
        let roots: BTreeSet<&str> = index
            .roots
            .iter()
            .map(|r| r.causal_key.root.as_str())
            .collect();
        // Every started copy is in here at once, so a replay cancelled
        // while copies start stops them (review M14 M3).
        let mut copies = Copies {
            env: self.node.env().clone(),
            copies: BTreeMap::new(),
        };
        let mut info = Vec::new();
        for name in sandboxed {
            let recorded = |why: String| ForeignFork {
                name: name.clone(),
                mode: "recorded".into(),
                checkpoint_lsn: None,
                replayed_calls: 0,
                why,
            };
            if let Some(why) = skip {
                info.push(recorded(why.into()));
                continue;
            }
            let Some(host) = &host else {
                info.push(recorded("this daemon runs no foreign actors".into()));
                continue;
            };
            let Some(ck) = host
                .checkpoints(&name)
                .into_iter()
                .rfind(|c| c.lsn <= fork_lsn)
            else {
                info.push(recorded(format!(
                    "no checkpoint at or before the fork point {fork_lsn}"
                )));
                continue;
            };
            // The copy's disk is a copy of the checkpoint's data: not when it
            // would not fit above `[log] disk_reserve`.
            if let Some(room) = self.node.disk_budget()
                && ck.bytes > room
            {
                info.push(recorded(format!(
                    "the copy needs {} bytes, more than the {room} bytes free above [log] disk_reserve",
                    ck.bytes
                )));
                continue;
            }
            let spec = CopySpec {
                fork: id.to_owned(),
                name: name.clone(),
                checkpoint: ck.clone(),
                dir: self.dir(id).join("foreign").join(&name),
            };
            let copy = match host.start_copy(spec).await {
                Ok(c) => c,
                Err(e) => {
                    info.push(recorded(e));
                    continue;
                }
            };
            copies.copies.insert(name.clone(), copy.clone());
            match self.bring_to(&*copy, &name, ck.lsn, fork_lsn, &roots).await {
                Ok(n) => {
                    info.push(ForeignFork {
                        name: name.clone(),
                        mode: "sandbox".into(),
                        checkpoint_lsn: Some(ck.lsn),
                        replayed_calls: n,
                        why: String::new(),
                    });
                }
                Err(e) => {
                    copies.stop().await;
                    return Err(e);
                }
            }
        }
        Ok(((!copies.copies.is_empty()).then_some(copies), info))
    }

    /// Sends main's recorded calls to `name` in `(from, to]` to the copy, in
    /// log order; answers are dropped. Calls of turns under `roots` (which
    /// the fork re-runs) and calls denied before they left are skipped;
    /// secret headers are not in the log and are not sent.
    async fn bring_to(
        &self,
        copy: &dyn ForeignCopy,
        name: &str,
        from: Lsn,
        to: Lsn,
        roots: &BTreeSet<&str>,
    ) -> Result<u64, ApiError> {
        let mut calls = Vec::new();
        if to > from {
            let target = format!("foreign:{name}");
            // A turn writes its `TurnBegin` before its first external effect.
            let mut rerun = BTreeSet::new();
            self.node
                .reader()
                .read(from + 1, to, |c| {
                    match c.record {
                        Record::TurnBegin(b)
                            if b.causal_key
                                .as_ref()
                                .is_some_and(|k| roots.contains(k.root.as_str())) =>
                        {
                            rerun.insert(b.execution_id);
                        }
                        Record::EffectResult(r) if !rerun.contains(&r.execution_id) => {
                            if let Some(e) = r.effect
                                && e.kind == "foreign.http"
                                && e.target == target
                                && e.status != pb::EffectStatus::Denied as i32
                            {
                                calls.push(e);
                            }
                        }
                        _ => {}
                    }
                    Ok(())
                })
                .await
                .map_err(internal)?;
        }
        let privacy = self.privacy(false);
        let mut sent = 0;
        for mut e in calls {
            privacy.reveal_effect(&mut e);
            let Some(req) = recorded_request(&e) else {
                continue;
            };
            // Answers do not matter: the copy only has to do what
            // production's actor did.
            let _ = self
                .node
                .env()
                .timeout(std::time::Duration::from_secs(30), copy.http(req))
                .await;
            sent += 1;
        }
        Ok(sent)
    }
}

/// The wire request of a recorded `foreign.http` effect, without secret
/// headers (their values are never in the log).
pub(crate) fn recorded_request(e: &pb::EffectRecord) -> Option<kronik_core::env::HttpRequest> {
    let bytes = match e.request.as_ref()?.value.as_ref()? {
        pb::sealable::Value::Plain(b) => b,
        pb::sealable::Value::Sealed(_) => return None,
    };
    let r = pb::HttpEffectRequest::decode(bytes.as_slice()).ok()?;
    Some(kronik_core::env::HttpRequest {
        method: r.method,
        url: r.url,
        headers: r
            .headers
            .into_iter()
            .filter_map(|h| match h.value {
                Some(pb::http_effect_header::Value::Text(t)) => Some((h.name, t)),
                _ => None,
            })
            .collect(),
        body: r.body.into(),
        max_response_bytes: 10 << 20,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_requests_keep_text_headers_only() {
        let req = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "foreign://pg/sql".into(),
            headers: vec![
                pb::HttpEffectHeader {
                    name: "content-type".into(),
                    value: Some(pb::http_effect_header::Value::Text("text/plain".into())),
                },
                pb::HttpEffectHeader {
                    name: "authorization".into(),
                    value: Some(pb::http_effect_header::Value::Secret(pb::SecretRef {
                        name: "pg-token".into(),
                        ..Default::default()
                    })),
                },
            ],
            body: b"SELECT 1".to_vec(),
        };
        let e = pb::EffectRecord {
            kind: "foreign.http".into(),
            request: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(req.encode_to_vec())),
            }),
            ..Default::default()
        };
        let wire = recorded_request(&e).expect("a request");
        assert_eq!(
            (wire.method.as_str(), wire.url.as_str()),
            ("POST", "foreign://pg/sql")
        );
        assert_eq!(
            wire.headers,
            [("content-type".to_owned(), "text/plain".to_owned())]
        );
        assert_eq!(&wire.body[..], b"SELECT 1");
        // A sealed request (an erased subject, or --no-pii) is not sent.
        let mut sealed = e.clone();
        sealed.request = Some(pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed::default())),
        });
        assert!(recorded_request(&sealed).is_none());
    }
}
