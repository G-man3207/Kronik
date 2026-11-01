//! The trace exporter (m28-otel §3.6): a [`Sink`] that maps the turn
//! records of a batch to spans and POSTs them to `<endpoint>/v1/traces` as
//! OTLP/HTTP protobuf. Its cursor state is the open-turn set.

use std::io;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use kronik_core::authority::AuthLease;
use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use kronik_sched::secrets::CertifiedSecretSnapshot;
use prost::Message as _;

use crate::cursor::Generation;
use crate::follow::{Delivery, Sink};
use crate::keys::KeyHasher;
use crate::otlp::collector::trace::v1::ExportTraceServiceResponse;
use crate::spans::{self, ActorKeys, OpenTurns, Resource, SpanRef, Turn};
use crate::trace_state::{self, TraceState};

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
    checkpoints: TraceState,
    /// Whether the open-turn cap was hit since the last warning.
    capped: bool,
}

impl TraceSink {
    /// `state` is the cursor's saved open-turn set.
    pub async fn open(
        node: Arc<Node>,
        settings: Settings,
        hasher: KeyHasher,
        data_dir: &Path,
        state: &serde_json::Value,
        lsn: Lsn,
    ) -> io::Result<TraceSink> {
        let reader = if state.is_null() {
            Some(node.capture_system_export_reader().await.map_err(|error| io::Error::other(error.code.as_str()))?)
        } else { None };
        let (checkpoints, open) =
            trace_state::load(node.env().clone(), data_dir, state, lsn, hasher.id_key()).await?;
        let mut sink = TraceSink {
            node,
            settings,
            open,
            checkpoints,
            hasher,
            capped: false,
        };
        if let Some(reader) = reader {
            sink.rewind(lsn, [0; 16], &reader).await.map_err(io::Error::other)?;
        }
        Ok(sink)
    }

    /// The span of the dead-lettered turn a resend names (`main:<lsn>`),
    /// read from the log; none once retention deleted it.
    async fn resend_of(&self, input: Option<&pb::Input>, source: &pb::ActorSource,
        reader: &kronik_sched::ShardReader) -> Result<Option<SpanRef>, String> {
        let Some(pb::input::Kind::Message(message)) = input.and_then(|input| input.kind.as_ref()) else { return Ok(None) };
        let Some(id) = kronik_core::ids::TurnId::parse(&message.resend_of) else { return Ok(None) };
        if id.branch != source.branch || id.shard != source.shard { return Ok(None); }
        let kronik_core::ids::SourcePos::Actor { shard, lsn: through } = reader.point().source else {
            return Err("STORAGE_CORRUPT".into());
        };
        if id.shard != shard || id.lsn < reader.point().retained_from.max(1) || id.lsn > through { return Ok(None); }
        let page = reader.local_export_page(id.lsn - 1, 1, crate::follow::BATCH_BYTES).await
            .map_err(|error| error.code.as_str().to_owned())?;
        if page.retention_gap.is_some() { return Ok(None); }
        let Some((actual, committed)) = page.records.first() else { return Ok(None) };
        if committed.lsn != id.lsn || actual.lsn != id.lsn || actual.shard != id.shard || actual.branch != id.branch {
            return Ok(None);
        }
        Ok(match &committed.record {
            Record::TurnRecord(record) => Some(spans::turn_ref(record, &self.open)),
            _ => None,
        })
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
    type Batch = Option<Bytes>;

    async fn prepare(
        &mut self,
        records: &[(pb::ActorSource, Committed)],
        _generation: Generation,
        reader: &kronik_sched::ShardReader,
        snapshot: &CertifiedSecretSnapshot,
        original: AuthLease,
    ) -> Result<Self::Batch, String> {
        original.check().map_err(|e| e.code.as_str().to_owned())?;
        let secrets = kronik_sched::effects::secret_patterns(&snapshot.values);
        let mut out = Vec::new();
        for (source, c) in records {
            source.validate().map_err(|_| "STORAGE_CORRUPT".to_owned())?;
            if source.lsn != c.lsn || source.shard.is_some() { return Err("STORAGE_CORRUPT".into()); }
            match &c.record {
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
                    let resend_of = self.resend_of(r.input.as_ref(), source, reader).await?;
                    let unsealed = self.unseal_traceparent(r);
                    let record = unsealed.as_ref().unwrap_or(r);
                    let hash = |kind: &str, key: &str| self.hasher.label(kind, key);
                    let keys = match self.settings.keys {
                        KeyMode::Hashed => ActorKeys::Hashed(&hash),
                        KeyMode::Plain => ActorKeys::Plain,
                        KeyMode::Omit => ActorKeys::Omit,
                    };
                    let turn = Turn {
                        record,
                        lsn: c.lsn,
                        branch: &source.branch,
                        open: &self.open,
                        resend_of,
                        secrets: &secrets,
                    };
                    out.extend(spans::spans(&turn, &keys));
                    self.open.commit(r);
                }
                _ => {}
            }
        }
        if self.open.len() < OpenTurns::CAP {
            self.capped = false;
        }
        if out.is_empty() {
            return Ok(None);
        }
        // Callees commit first, so a caller in the same batch clamps them.
        spans::clamp(&mut out);
        let resource = Resource {
            service_name: &self.settings.service_name,
            service_version: kronik_runtime::KRONIK_VERSION,
            node: self.node.branch(),
            engine: kronik_runtime::ENGINE_VERSION,
        };
        Ok(Some(spans::request(&resource, out).encode_to_vec().into()))
    }

    async fn deliver(&mut self, batch: &Self::Batch, original: AuthLease) -> Delivery {
        let Some(body) = batch else {
            return Delivery::Delivered;
        };
        let url = format!("{}/v1/traces", self.settings.endpoint);
        let headers = self.settings.headers.clone();
        otlp_delivery(
            crate::http::post(&self.node, url, headers, "application/x-protobuf", body.clone(), original).await,
            |body| {
                ExportTraceServiceResponse::decode(body)
                    .ok()
                    .and_then(|r| r.partial_success)
                    .map(|p| p.rejected_spans)
            },
        )
    }

    async fn checkpoint(&mut self, lsn: Lsn) -> Result<serde_json::Value, String> {
        self.checkpoints
            .checkpoint(&mut self.open, lsn)
            .await
            .map_err(|error| {
                trace_state::failure_code(&error)
                    .unwrap_or("state_io")
                    .to_owned()
            })
    }

    fn committed(&mut self, _lsn: Lsn, _generation: Generation, _rewind_pending: bool) {
        self.checkpoints.committed(&mut self.open);
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
    async fn rewind(&mut self, to: Lsn, _generation: Generation, reader: &kronik_sched::ShardReader) -> Result<(), String> {
        reader.check().map_err(|error| error.code.as_str().to_owned())?;
        let kronik_core::ids::SourcePos::Actor { shard: None, lsn: through } = reader.point().source else {
            return Err("STORAGE_CORRUPT".into());
        };
        if to > through { return Err("BAD_REQUEST".into()); }
        let mut open = OpenTurns::new(*self.open.ids());
        open.tracking = false;
        let mut after = reader.point().retained_from.max(1) - 1;
        while after < to {
            let count = usize::try_from(to - after).unwrap_or(usize::MAX).min(256);
            let page = reader.local_export_page(after, count, crate::follow::BATCH_BYTES).await
                .map_err(|error| error.code.as_str().to_owned())?;
            if page.retention_gap.is_some() || page.records.is_empty() || page.scanned_through > to {
                return Err("state_read".into());
            }
            for (_, committed) in &page.records {
                match &committed.record {
                    Record::TurnBegin(begin) => if let Some(key) = &begin.causal_key { open.begin(key, begin.input.as_ref()); },
                    Record::TurnRecord(record) => open.commit(record),
                    _ => {}
                }
            }
            after = page.scanned_through;
        }
        reader.check().map_err(|error| error.code.as_str().to_owned())?;
        open.tracking = true;
        self.open = open;
        self.checkpoints.reset();
        Ok(())
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
