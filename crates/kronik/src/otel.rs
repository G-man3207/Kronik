//! `[otel]` and `[audit]` in `kronik serve` (m28-otel §3.6, §3.7, §4): the
//! trace exporter, which follows the log from the `traces` cursor, the
//! metrics push and the audit export. All are `env.spawn` tasks off the
//! turn path.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use kronik_otel::audit::{Keys, Mapper};
use kronik_otel::cursor::{Cursors, Entry};
use kronik_otel::follow::{Options, Stream, supervise};
use kronik_otel::keys::KeyHasher;
use kronik_otel::traces::{KeyMode, Settings, TraceSink};
use kronik_sched::Node;

use crate::config::{ActorKeys, AuditFrom, Config};

/// The cursor and metrics name of the trace stream.
pub const TRACES: &str = "traces";

/// Starts what `[otel]` turns on and returns the trace stream for the
/// export status (disabled without an endpoint or with `traces = false`).
pub fn start(
    config: &Config,
    node: &Arc<Node>,
    cursors: &Arc<Cursors>,
    data_dir: &Path,
) -> anyhow::Result<Arc<Stream>> {
    let otel = &config.otel;
    let endpoint = otel.endpoint();
    let saved = cursors.get(TRACES);
    let on = endpoint.is_some() && otel.traces;
    // A first start exports from now: a node's history is not replayed
    // into a backend that was just connected.
    let cursor = match &saved {
        Some(e) => e.lsn,
        None if on => node.applied_lsn(),
        None => 0,
    };
    let sink_name = endpoint
        .map(kronik_otel::http::scheme_host)
        .unwrap_or_default();
    let stream = Stream::new(TRACES, on, sink_name, cursor);
    let Some(endpoint) = endpoint else {
        return Ok(stream);
    };
    let headers =
        kronik_otel::http::env_headers(otel.headers_env.as_deref()).map_err(anyhow::Error::msg)?;
    let env = node.env().clone();
    if on {
        let random = || env.random_bytes();
        let hasher = KeyHasher::open(node.sealer().clone(), data_dir, random)?;
        let settings = Settings {
            endpoint: endpoint.to_owned(),
            headers: headers.clone(),
            service_name: otel.service_name.clone(),
            keys: match otel.actor_keys {
                ActorKeys::Hashed => KeyMode::Hashed,
                ActorKeys::Plain => KeyMode::Plain,
                ActorKeys::Omit => KeyMode::Omit,
            },
        };
        let options = Options {
            batch: otel.batch_spans,
            interval: otel.interval.0,
        };
        tracing::info!(endpoint = %stream.sink, cursor, "exporting spans over OTLP");
        let (node, cursors, stream) = (node.clone(), cursors.clone(), stream.clone());
        drop(env.spawn("otel-traces", async move {
            // A first start's cursor is saved before its first batch: a
            // refused batch and a restart then resend it (review Low).
            if saved.is_none() {
                let entry = Entry {
                    lsn: cursor,
                    state: serde_json::Value::Null,
                };
                if let Err(e) = cursors.save(TRACES, entry).await {
                    tracing::warn!(error = %e, "otel: saving the first trace cursor failed");
                }
            }
            let make = |state: &serde_json::Value| {
                TraceSink::new(node.clone(), settings.clone(), hasher.clone(), state)
            };
            supervise(node.clone(), cursors, stream, options, make).await;
        }));
    }
    if otel.metrics {
        let gauges = node.clone();
        tracing::info!(endpoint = %kronik_otel::http::scheme_host(endpoint), "pushing metrics over OTLP");
        drop(env.spawn(
            "otel-metrics",
            kronik_otel::metrics::push_loop(
                env.clone(),
                endpoint.to_owned(),
                headers,
                otel.service_name.clone(),
                node.branch().to_owned(),
                otel.metrics_interval.0,
                move || crate::admin::set_scrape_gauges(&gauges),
            ),
        ));
    }
    Ok(stream)
}

/// The `export.json` entry holding the hash of the `[audit]` and `[otel]`
/// settings last recorded in an `audit.config` event.
const AUDIT_CONFIG: &str = "audit_config";

/// The audit export: the line mapper, which `GET /v1/audit` shares, and the
/// stream (disabled without a sink). Then records an `audit.config` event
/// when `[audit]` or `[otel]` differ from the last recorded ones (review
/// L2), after the stream's start cursor so that `from = "now"` exports it
/// too; a node that never had either on records none.
pub async fn start_audit(
    config: &Config,
    node: &Arc<Node>,
    cursors: &Arc<Cursors>,
    data_dir: &Path,
) -> anyhow::Result<(Arc<Mapper>, Arc<Stream>)> {
    let env = node.env().clone();
    let keys = match config.otel.actor_keys {
        ActorKeys::Hashed => {
            Keys::Hashed(KeyHasher::open(node.sealer().clone(), data_dir, || {
                env.random_bytes()
            })?)
        }
        ActorKeys::Plain => Keys::Plain,
        ActorKeys::Omit => Keys::Omit,
    };
    let mapper = Arc::new(Mapper {
        keys,
        sealer: node.sealer().clone(),
        branch: node.branch().to_owned(),
    });
    let sink = config.audit.parsed_sink().map_err(anyhow::Error::msg)?;
    // The overrides are part of what is in force; the hash, not the
    // settings (a webhook URL can hold a credential), leaves the node.
    let settings = format!(
        "{:?}{:?}{:?}{:?}",
        config.audit,
        config.otel,
        config.audit.sink(),
        config.otel.endpoint()
    );
    let hash = format!("b3:{}", blake3::hash(settings.as_bytes()).to_hex());
    let stream = match sink {
        None => Stream::new(kronik_otel::sink::STREAM, false, String::new(), 0),
        Some(sink) => {
            let a = &config.audit;
            let settings = kronik_otel::sink::Settings {
                sink,
                batch_records: a.batch_records as u64,
                interval: a.interval.0,
                file_max_bytes: a.file_max_bytes.0,
                headers_env: a.headers_env.clone(),
                from_now: a.from == AuditFrom::Now,
                max_hold: a.max_hold.0,
                hold_release: a.hold_release_bytes(config.log.disk_reserve.0),
            };
            kronik_otel::sink::start(node.clone(), cursors.clone(), settings, mapper.clone())
                .await
                .map_err(anyhow::Error::msg)?
        }
    };
    let saved = cursors.get(AUDIT_CONFIG).map(|e| e.state);
    let on = stream.enabled || config.otel.endpoint().is_some();
    if saved.as_ref().and_then(|s| s.as_str()) != Some(hash.as_str()) && (on || saved.is_some()) {
        let audit = kronik_proto::log::v1::Audit {
            token_id: "system".into(),
            reason: "the [audit] or [otel] settings changed".into(),
            wall_time_ms: env.clock.wall_ms(),
        };
        let details = [
            ("hash".to_owned(), hash.clone()),
            ("sink".to_owned(), stream.sink.clone()),
        ]
        .into();
        node.record_audit_event("audit.config", "", details, audit)
            .await
            .map_err(|e| anyhow::anyhow!("recording the audit settings: {}", e.message))?;
        let entry = kronik_otel::cursor::Entry {
            lsn: node.applied_lsn(),
            state: hash.into(),
        };
        cursors
            .save(AUDIT_CONFIG, entry)
            .await
            .context("saving the export cursors")?;
    }
    Ok((mapper, stream))
}
