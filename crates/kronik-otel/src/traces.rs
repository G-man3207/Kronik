//! The trace exporter (m28-otel §3.6): a [`Sink`] that maps the turn
//! records of a batch to spans and POSTs them to `<endpoint>/v1/traces` as
//! OTLP/HTTP protobuf. Its cursor state is the open-turn set.

use std::sync::Arc;

use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use prost::Message as _;

use crate::follow::{Delivery, Sink};
use crate::keys::KeyHasher;
use crate::otlp::collector::trace::v1::ExportTraceServiceResponse;
use crate::spans::{self, ActorKeys, OpenTurns, Resource, SpanRef, Turn};

/// `[otel] actor_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    Hashed,
    Plain,
    Omit,
}

/// Where and how spans are sent.
#[derive(Clone)]
pub struct Settings {
    /// `[otel] endpoint`, without a trailing `/`.
    pub endpoint: String,
    /// From `[otel] headers_env`.
    pub headers: Vec<(String, String)>,
    pub service_name: String,
    pub keys: KeyMode,
}

pub struct TraceSink {
    node: Arc<Node>,
    settings: Settings,
    hasher: KeyHasher,
    open: OpenTurns,
    /// Whether the open-turn cap was hit since the last warning.
    capped: bool,
}

impl TraceSink {
    /// `state` is the cursor's saved open-turn set.
    pub fn new(
        node: Arc<Node>,
        settings: Settings,
        hasher: KeyHasher,
        state: &serde_json::Value,
    ) -> TraceSink {
        TraceSink {
            node,
            settings,
            open: OpenTurns::from_json(state, hasher.id_key()),
            hasher,
            capped: false,
        }
    }

    /// The span of the dead-lettered turn a resend names (`main:<lsn>`),
    /// read from the log; none once retention deleted it.
    async fn resend_of(&self, input: Option<&pb::Input>) -> Option<SpanRef> {
        let Some(pb::input::Kind::Message(m)) = input.and_then(|i| i.kind.as_ref()) else {
            return None;
        };
        let (branch, lsn) = m.resend_of.split_once(':')?;
        let lsn: Lsn = lsn.parse().ok()?;
        if branch != self.node.branch() {
            return None;
        }
        let mut found = None;
        let read = self
            .node
            .reader()
            .read(lsn, lsn, |c| {
                if let Record::TurnRecord(r) = c.record {
                    found = Some(r);
                }
                Ok(())
            })
            .await;
        if let Err(e) = read {
            tracing::debug!(error = %e, lsn, "otel: reading a resent turn failed");
        }
        found.map(|r| spans::turn_ref(&r, &self.open))
    }

    /// The record with a sealed `traceparent` opened with the node's
    /// sealer; left sealed (no link) once its subject is erased.
    fn unseal_traceparent(&self, r: &pb::TurnRecord) -> Option<pb::TurnRecord> {
        let Some(pb::input::Kind::Http(h)) = r.input.as_ref().and_then(|i| i.kind.as_ref()) else {
            return None;
        };
        let sealed = |h: &pb::Header| {
            h.name.eq_ignore_ascii_case("traceparent")
                && matches!(
                    h.value.as_ref().and_then(|v| v.value.as_ref()),
                    Some(pb::sealable::Value::Sealed(_))
                )
        };
        if !h.headers.iter().any(sealed) {
            return None;
        }
        let mut r = r.clone();
        if let Some(pb::input::Kind::Http(h)) = r.input.as_mut().and_then(|i| i.kind.as_mut()) {
            for header in h.headers.iter_mut().filter(|h| sealed(h)) {
                if let Some(v) = header.value.as_mut() {
                    let _ = self.node.sealer().unseal_value(v);
                }
            }
        }
        Some(r)
    }
}

impl Sink for TraceSink {
    /// The encoded request, or none when the batch had no turn records.
    type Batch = Option<Vec<u8>>;

    async fn prepare(&mut self, records: Vec<Committed>) -> Self::Batch {
        let mut out = Vec::new();
        for c in records {
            match c.record {
                Record::TurnBegin(b) => {
                    let Some(key) = &b.causal_key else { continue };
                    if !self.open.begin(key, b.input.as_ref()) && !self.capped {
                        self.capped = true;
                        tracing::warn!(
                            cap = OpenTurns::CAP,
                            "otel: too many open turns to track; their callees start traces of their own"
                        );
                    }
                }
                Record::TurnRecord(r) => {
                    let resend_of = self.resend_of(r.input.as_ref()).await;
                    let unsealed = self.unseal_traceparent(&r);
                    let record = unsealed.as_ref().unwrap_or(&r);
                    let hash = |kind: &str, key: &str| self.hasher.label(kind, key);
                    let keys = match self.settings.keys {
                        KeyMode::Hashed => ActorKeys::Hashed(&hash),
                        KeyMode::Plain => ActorKeys::Plain,
                        KeyMode::Omit => ActorKeys::Omit,
                    };
                    let turn = Turn {
                        record,
                        lsn: c.lsn,
                        branch: self.node.branch(),
                        open: &self.open,
                        resend_of,
                    };
                    out.extend(spans::spans(&turn, &keys));
                    self.open.commit(&r);
                }
                _ => {}
            }
        }
        if self.open.len() < OpenTurns::CAP {
            self.capped = false;
        }
        if out.is_empty() {
            return None;
        }
        // Callees commit first, so a caller in the same batch clamps them.
        spans::clamp(&mut out);
        let resource = Resource {
            service_name: &self.settings.service_name,
            service_version: kronik_runtime::KRONIK_VERSION,
            node: self.node.branch(),
            engine: kronik_runtime::ENGINE_VERSION,
        };
        Some(spans::request(&resource, out).encode_to_vec())
    }

    async fn deliver(&mut self, batch: &Self::Batch) -> Delivery {
        let Some(body) = batch else {
            return Delivery::Delivered;
        };
        let env = self.node.env().clone();
        let url = format!("{}/v1/traces", self.settings.endpoint);
        let headers = self.settings.headers.clone();
        otlp_delivery(
            crate::http::post(&env, url, headers, "application/x-protobuf", body.clone()).await,
            |body| {
                ExportTraceServiceResponse::decode(body)
                    .ok()
                    .and_then(|r| r.partial_success)
                    .map(|p| p.rejected_spans)
            },
        )
    }

    fn state(&self) -> serde_json::Value {
        self.open.to_json()
    }

    /// Rebuilds the open-turn set as it was after `to` (review M8): from
    /// an empty set at the first retained record, through the records'
    /// beginnings and commits, so that a re-export sends the same spans.
    /// The rebuilt set is what an exporter that always ran holds, also for
    /// turns open before the stream's first start.
    ///
    /// shortcut: a turn begun before the first retained record and still
    /// open or kept after `to` is not known, so what names it falls back as
    /// past the cap; keep set snapshots with the cursor if rewinds past
    /// retention ever matter. Reads the retained log up to `to` once.
    async fn rewind(&mut self, to: Lsn) {
        let mut open = OpenTurns::new(*self.open.ids());
        let read = self
            .node
            .reader()
            .read(1, to, |c| {
                match &c.record {
                    Record::TurnBegin(b) => {
                        if let Some(key) = &b.causal_key {
                            open.begin(key, b.input.as_ref());
                        }
                    }
                    Record::TurnRecord(r) => open.commit(r),
                    _ => {}
                }
                Ok(())
            })
            .await;
        if let Err(e) = read {
            tracing::warn!(error = %e, to, "otel: rebuilding the open turns for a rewind failed; links may name other traces");
        }
        self.open = open;
    }
}

/// OTLP/HTTP's answers (§3.6): 2xx delivered (a partial success is
/// logged), 400 dropped, anything else retried, honouring `Retry-After`.
pub(crate) fn otlp_delivery(
    resp: Result<kronik_core::env::HttpResponse, &'static str>,
    rejected: impl Fn(&[u8]) -> Option<i64>,
) -> Delivery {
    let resp = match resp {
        Ok(r) => r,
        Err(code) => {
            return Delivery::Retry {
                code: code.into(),
                after: None,
            };
        }
    };
    match resp.status {
        200..=299 => {
            if let Some(n) = rejected(&resp.body).filter(|n| *n > 0) {
                tracing::warn!(rejected = n, "otel: the collector rejected part of a batch");
            }
            Delivery::Delivered
        }
        400 => Delivery::Dropped {
            code: "http_400".into(),
        },
        status => Delivery::Retry {
            code: format!("http_{status}"),
            after: crate::http::retry_after(&resp),
        },
    }
}
