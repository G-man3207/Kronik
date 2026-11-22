//! Process-wide metrics, exported at `/metrics` in the Prometheus text
//! format (M6) and pushed over OTLP (M28, [`snapshot`]). [`METRICS`] is the
//! catalog: a name, its help text and its type. Recording never reads a
//! clock: daemon code measures durations with `Env::clock` and passes them
//! in (ADR 0004). Only the exporters read the values back, so they cannot
//! change behavior, in production or in the simulator. Recording a label
//! set the registry already holds allocates nothing and locks only its
//! own metric, so the paths that record on every turn, frame and request
//! do not queue behind one another.

use std::collections::hash_map::DefaultHasher;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Counter,
    Gauge,
    Histogram,
}

/// One exported metric.
#[derive(Debug, PartialEq)]
pub struct Def {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: Type,
}

/// Every metric Kronik exports.
pub const METRICS: &[Def] = &[
    Def {
        name: "kronik_build_info",
        help: "Always 1; the labels name the Kronik version and the engine.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_applied_lsn",
        help: "The last log sequence number applied to the materialized state.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_disk_free_bytes",
        help: "Free bytes on the log's file system (when [log] disk_reserve is set).",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_disk_below_reserve",
        help: "1 while the log's file system is below [log] disk_reserve: new inputs and changes are refused.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_key_source_up",
        help: "1 when the daemon loaded its master key through its key source ([keys] source); 0 without a secret store.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_secret_recovery_stalled",
        help: "Re-runs of open turns waiting for a recorded secret value or for an unavailable prerequisite.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_retention_open_turn_segments",
        help: "Closed log segments that the last retention pass kept only for an open turn, by source (live: open in the running state; snapshot: held open by a kept snapshot).",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_secret_fetch_total",
        help: "Requests to external secret backends, by backend and result (ok, unavailable, denied, not_found, version_gone, invalid, cancelled).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_secret_fetch_seconds",
        help: "Time an external secret backend took to answer, or until the request gave up, by backend.",
        kind: Type::Histogram,
    },
    Def {
        name: "kronik_secret_stale",
        help: "1 while effects use a secret's cached value past [secrets] refresh because its backend does not answer, by secret name.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_secret_versions_total",
        help: "Secret versions this node recorded, by backend (file for the built-in store).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_turns_total",
        help: "Turns recorded, by actor kind and outcome.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_turn_duration_seconds",
        help: "Time from the start of a turn to its record, by actor kind.",
        kind: Type::Histogram,
    },
    Def {
        name: "kronik_log_records_appended_total",
        help: "Records written to the log.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_log_fsync_duration_seconds",
        help: "Time to fsync a group commit of the log.",
        kind: Type::Histogram,
    },
    Def {
        name: "kronik_effects_total",
        help: "Effect results recorded, by effect kind and status.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_written_bytes_total",
        help: "Bytes of new blobs, by source (guest, upload, effect).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_read_bytes_total",
        help: "Blob bytes read, by reader (guest, effect, gateway, ship, api).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_store_below_reserve",
        help: "1 while the blob store is below [blobs] disk_reserve: no new blobs are written.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_blob_turn_retries_total",
        help: "Runs of turns again because their blob writes met [blobs] disk_reserve.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_missing_total",
        help: "Reads of a committed blob whose bytes are not in the blob store (BLOB_MISSING).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_objects",
        help: "Blob files in main's blob store, as of the collector's last pass.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_blob_bytes",
        help: "Bytes of the blob files in main's blob store, as of the collector's last pass.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_blob_gc_runs_total",
        help: "Passes of the blob collector.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_gc_deleted_total",
        help: "Blob files the collector deleted because nothing kept them.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_gc_freed_bytes_total",
        help: "Bytes of the blob files the collector deleted.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_blob_gc_duration_seconds",
        help: "Time a pass of the blob collector took.",
        kind: Type::Histogram,
    },
    Def {
        name: "kronik_blob_gc_candidates",
        help: "Blob files without a root that the collector's next pass deletes if they still have none.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_blob_ship_pending",
        help: "Blobs the index keeps that the shipper has not uploaded, as of its last round.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_blob_leases",
        help: "Leases on blobs held in this daemon's memory (turns, uploads, streams, replays), as of the collector's last pass.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_gateway_requests_total",
        help: "HTTP requests answered by the gateway, by status code.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_gateway_request_duration_seconds",
        help: "Time to answer an HTTP request at the gateway, by status code.",
        kind: Type::Histogram,
    },
    Def {
        name: "kronik_replay_runs_total",
        help: "Replays run for forks and proposals, by mode.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_fork_crypto_computations_total",
        help: "Unmatched crypto effects a fork computed on the host, by algorithm. The key is not a label.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_guard_triggered_total",
        help: "Guards of `kronik watch` that fired, by action and outcome.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_export_records_total",
        help: "Log records an export stream delivered (or skipped), by stream.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_export_lag_records",
        help: "Committed records an export stream has not delivered yet, by stream.",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_export_errors_total",
        help: "Failed export attempts (retried), by stream.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_export_dropped_total",
        help: "Records in batches the sink refused for good and the export skipped, by stream.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_export_gaps_total",
        help: "Log ranges retention deleted before an export stream read them, by stream.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connections_open",
        help: "Long-lived connections open on this node, by actor kind and protocol (websocket, sse).",
        kind: Type::Gauge,
    },
    Def {
        name: "kronik_connections_opened_total",
        help: "Connection opens, by actor kind, protocol and result (accepted, refused, failed, limit).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connections_closed_total",
        help: "Connections closed, by actor kind, protocol and cause (client, actor, or the host's reason).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connection_frames_total",
        help: "Frames, by actor kind, protocol and direction (in, out).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connection_frame_bytes_total",
        help: "Frame payload bytes, by actor kind, protocol and direction (in, out).",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connection_frames_dropped_total",
        help: "Outgoing frames never written: their connection was closed, closing or not live, by actor kind and protocol.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connection_send_now_total",
        help: "connection.send-now effects by actor kind and result: ok, closed, timeout, denied or outcome_unknown.",
        kind: Type::Counter,
    },
    Def {
        name: "kronik_connection_queued_bytes",
        help: "Bytes all outgoing connection queues hold.",
        kind: Type::Gauge,
    },
];

/// Histogram bucket bounds, in seconds.
pub const BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Clone)]
enum Value {
    Counter(u64),
    Gauge(f64),
    Histogram {
        buckets: [u64; BUCKETS.len()],
        sum: f64,
        count: u64,
    },
}

/// One recorded series: a catalog entry with one label set.
#[derive(Debug, Clone)]
struct Series {
    /// [`label_set_hash`] of `labels`: a metric's series are sorted by it.
    hash: u64,
    /// Sorted by name.
    labels: Vec<(&'static str, String)>,
    value: Value,
}

/// A catalog entry's series, behind a lock of their own and on a cache
/// line of their own: the hot paths record different metrics (turns,
/// frames, log writes, requests) and do not queue behind one another.
#[repr(align(64))]
struct Shard(Mutex<Vec<Series>>);

/// The recorded series of each catalog entry, in [`METRICS`] order.
static REGISTRY: [Shard; METRICS.len()] = [const { Shard(Mutex::new(Vec::new())) }; METRICS.len()];

/// A hash of a label set that does not depend on the order of its labels:
/// the caller's labels are the key as they are, without a sorted copy.
fn label_set_hash(labels: &[(&'static str, &str)]) -> u64 {
    labels.iter().fold(0, |hash, label| {
        let mut one = DefaultHasher::new();
        label.hash(&mut one);
        hash.wrapping_add(one.finish())
    })
}

impl Series {
    /// Whether `labels`, in any order, is this series' label set.
    fn has(&self, labels: &[(&'static str, &str)]) -> bool {
        self.labels.len() == labels.len()
            && labels
                .iter()
                .all(|(k, v)| self.labels.iter().any(|(k2, v2)| k2 == k && v2 == v))
    }
}

fn update(
    name: &'static str,
    labels: &[(&'static str, &str)],
    f: impl FnOnce(&mut Value),
    new: Value,
) {
    let Some(metric) = METRICS.iter().position(|d| d.name == name) else {
        return;
    };
    let hash = label_set_hash(labels);
    if let Ok(mut series) = REGISTRY[metric].0.lock() {
        record(&mut series, hash, labels, f, new);
    }
}

/// Updates the series of `labels` among `series`, which are sorted by
/// hash, adding one that starts at `new` when the label set has none.
fn record(
    series: &mut Vec<Series>,
    hash: u64,
    labels: &[(&'static str, &str)],
    f: impl FnOnce(&mut Value),
    new: Value,
) {
    let mut at = series.partition_point(|s| s.hash < hash);
    // Another label set with this hash (a collision) is passed over.
    while series
        .get(at)
        .is_some_and(|s| s.hash == hash && !s.has(labels))
    {
        at += 1;
    }
    if series.get(at).is_none_or(|s| s.hash != hash) {
        let mut labels: Vec<(&'static str, String)> =
            labels.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        labels.sort();
        series.insert(
            at,
            Series {
                hash,
                labels,
                value: new,
            },
        );
    }
    f(&mut series[at].value);
}

/// A Protobuf enum value's name as a label: `"OUTCOME_KIND_COMMITTED"`
/// with prefix `"OUTCOME_KIND_"` is `committed`.
pub fn enum_label(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// Adds `n` to a counter.
pub fn add(name: &'static str, labels: &[(&'static str, &str)], n: u64) {
    update(
        name,
        labels,
        |v| {
            if let Value::Counter(c) = v {
                *c += n;
            }
        },
        Value::Counter(0),
    );
}

/// Adds 1 to a counter.
pub fn inc(name: &'static str, labels: &[(&'static str, &str)]) {
    add(name, labels, 1);
}

/// Sets a gauge.
pub fn set(name: &'static str, labels: &[(&'static str, &str)], value: f64) {
    update(
        name,
        labels,
        |v| {
            if let Value::Gauge(g) = v {
                *g = value;
            }
        },
        Value::Gauge(0.0),
    );
}

/// Records a duration in a histogram.
pub fn observe(name: &'static str, labels: &[(&'static str, &str)], duration: Duration) {
    let seconds = duration.as_secs_f64();
    update(
        name,
        labels,
        |v| {
            if let Value::Histogram {
                buckets,
                sum,
                count,
            } = v
            {
                for (bucket, bound) in buckets.iter_mut().zip(BUCKETS) {
                    if seconds <= bound {
                        *bucket += 1;
                    }
                }
                *sum += seconds;
                *count += 1;
            }
        },
        Value::Histogram {
            buckets: [0; BUCKETS.len()],
            sum: 0.0,
            count: 0,
        },
    );
}

/// Records the time from its creation to its drop in a histogram, read from
/// `now` (a monotonic clock, such as `Env::clock`). It borrows its label's
/// value until it is dropped.
pub struct Timer<'a, F: Fn() -> Duration> {
    name: &'static str,
    label: (&'static str, &'a str),
    started: Duration,
    now: F,
}

/// A [`Timer`] for the histogram `name` with one label.
pub fn timer<'a, F: Fn() -> Duration>(
    name: &'static str,
    label: (&'static str, &'a str),
    now: F,
) -> Timer<'a, F> {
    Timer {
        name,
        label,
        started: now(),
        now,
    }
}

impl<F: Fn() -> Duration> Drop for Timer<'_, F> {
    fn drop(&mut self) {
        let elapsed = (self.now)().saturating_sub(self.started);
        observe(self.name, &[(self.label.0, self.label.1)], elapsed);
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn labels(pairs: &[(&'static str, String)], extra: Option<(&str, &str)>) -> String {
    let mut parts: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{v}\""));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

/// Every recorded series, in the order [`render`] writes them: catalog
/// order, then by labels.
fn recorded() -> Vec<(&'static Def, Vec<Series>)> {
    let mut out = Vec::with_capacity(METRICS.len());
    for (def, shard) in METRICS.iter().zip(REGISTRY.iter()) {
        let mut series = match shard.0.lock() {
            Ok(series) => series.clone(),
            Err(_) => return Vec::new(),
        };
        series.sort_by(|a, b| a.labels.cmp(&b.labels));
        out.push((def, series));
    }
    out
}

/// Every recorded series of the catalog, in the Prometheus text format
/// (version 0.0.4), in catalog order and then by labels.
pub fn render() -> String {
    let mut out = String::new();
    for (def, series) in recorded() {
        let kind = match def.kind {
            Type::Counter => "counter",
            Type::Gauge => "gauge",
            Type::Histogram => "histogram",
        };
        let _ = writeln!(
            out,
            "# HELP {} {}\n# TYPE {} {kind}",
            def.name, def.help, def.name
        );
        for s in &series {
            match &s.value {
                Value::Counter(c) => {
                    let _ = writeln!(out, "{}{} {c}", def.name, labels(&s.labels, None));
                }
                Value::Gauge(g) => {
                    let _ = writeln!(out, "{}{} {g}", def.name, labels(&s.labels, None));
                }
                Value::Histogram {
                    buckets,
                    sum,
                    count,
                } => {
                    for (n, bound) in buckets.iter().zip(BUCKETS) {
                        let le = bound.to_string();
                        let _ = writeln!(
                            out,
                            "{}_bucket{} {n}",
                            def.name,
                            labels(&s.labels, Some(("le", &le)))
                        );
                    }
                    let _ = writeln!(
                        out,
                        "{}_bucket{} {count}",
                        def.name,
                        labels(&s.labels, Some(("le", "+Inf")))
                    );
                    let _ = writeln!(out, "{}_sum{} {sum}", def.name, labels(&s.labels, None));
                    let _ = writeln!(out, "{}_count{} {count}", def.name, labels(&s.labels, None));
                }
            }
        }
    }
    out
}

/// A recorded series' value.
#[derive(Debug, Clone, PartialEq)]
pub enum SampleValue {
    Counter(u64),
    Gauge(f64),
    /// `buckets[i]` counts observations at most [`BUCKETS`]`[i]`
    /// (cumulative, as `le` in the text format).
    Histogram {
        buckets: [u64; BUCKETS.len()],
        sum: f64,
        count: u64,
    },
}

/// One recorded series.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub def: &'static Def,
    /// Sorted by name.
    pub labels: Vec<(&'static str, String)>,
    pub value: SampleValue,
}

/// Every recorded series of the catalog with its current value, in the
/// order [`render`] writes them.
pub fn snapshot() -> Vec<Sample> {
    recorded()
        .into_iter()
        .flat_map(|(def, series)| {
            series.into_iter().map(move |s| Sample {
                def,
                labels: s.labels,
                value: match s.value {
                    Value::Counter(c) => SampleValue::Counter(c),
                    Value::Gauge(g) => SampleValue::Gauge(g),
                    Value::Histogram {
                        buckets,
                        sum,
                        count,
                    } => SampleValue::Histogram {
                        buckets,
                        sum,
                        count,
                    },
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_gauges_and_histograms_in_the_text_format() {
        inc(
            "kronik_turns_total",
            &[("outcome", "committed"), ("kind", "counter")],
        );
        inc(
            "kronik_turns_total",
            &[("kind", "counter"), ("outcome", "committed")],
        );
        inc(
            "kronik_turns_total",
            &[("kind", "a\"b"), ("outcome", "failed")],
        );
        set("kronik_applied_lsn", &[], 42.0);
        observe(
            "kronik_log_fsync_duration_seconds",
            &[],
            Duration::from_millis(3),
        );
        let ticks = std::cell::Cell::new(0u64);
        drop(timer(
            "kronik_turn_duration_seconds",
            ("kind", "counter"),
            || {
                ticks.set(ticks.get() + 20);
                Duration::from_millis(ticks.get())
            },
        ));
        let text = render();
        assert!(
            text.contains("# TYPE kronik_turns_total counter\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_turns_total{kind=\"counter\",outcome=\"committed\"} 2\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_turns_total{kind=\"a\\\"b\",outcome=\"failed\"} 1\n"),
            "{text}"
        );
        assert!(text.contains("kronik_applied_lsn 42\n"), "{text}");
        assert!(
            text.contains("kronik_log_fsync_duration_seconds_bucket{le=\"0.0025\"} 0\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_log_fsync_duration_seconds_bucket{le=\"0.005\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_log_fsync_duration_seconds_bucket{le=\"+Inf\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_log_fsync_duration_seconds_count 1\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_turn_duration_seconds_bucket{kind=\"counter\",le=\"0.025\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("kronik_turn_duration_seconds_sum{kind=\"counter\"} 0.02\n"),
            "{text}"
        );
        // Every catalog entry is announced, in catalog order.
        let announced: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .map(|l| l.split(' ').next().unwrap_or_default())
            .collect();
        let catalog: Vec<&str> = METRICS.iter().map(|d| d.name).collect();
        assert_eq!(announced, catalog);
        // The read-back holds the same values.
        let samples = snapshot();
        let turns = samples
            .iter()
            .find(|s| {
                s.def.name == "kronik_turns_total"
                    && s.labels == [("kind", "counter".into()), ("outcome", "committed".into())]
            })
            .unwrap();
        assert_eq!(turns.value, SampleValue::Counter(2));
        assert_eq!(turns.def.kind, Type::Counter);
        let fsync = samples
            .iter()
            .find(|s| s.def.name == "kronik_log_fsync_duration_seconds")
            .unwrap();
        let SampleValue::Histogram { buckets, count, .. } = &fsync.value else {
            panic!("{fsync:?}")
        };
        assert_eq!((buckets[2], buckets[3], *count), (0, 1, 1));
    }

    #[test]
    fn a_label_set_is_its_labels_in_any_order_and_nothing_less() {
        let series = Series {
            hash: 0,
            labels: [("a", "1".into()), ("b", "2".into())].into(),
            value: Value::Counter(0),
        };
        assert!(series.has(&[("a", "1"), ("b", "2")]));
        assert!(series.has(&[("b", "2"), ("a", "1")]));
        assert!(!series.has(&[("a", "1"), ("b", "3")]));
        assert!(!series.has(&[("a", "1"), ("c", "2")]));
        assert!(!series.has(&[("a", "1")]));
        assert!(!series.has(&[]));
        assert_eq!(
            label_set_hash(&[("a", "1"), ("b", "2")]),
            label_set_hash(&[("b", "2"), ("a", "1")])
        );
        assert_ne!(
            label_set_hash(&[("a", "1"), ("b", "2")]),
            label_set_hash(&[("a", "2"), ("b", "1")])
        );
    }

    #[test]
    fn series_that_share_a_hash_are_told_apart_by_their_labels() {
        let series = |kind: &str| Series {
            hash: 7,
            labels: [("kind", kind.into())].into(),
            value: Value::Counter(0),
        };
        let mut all = vec![series("a"), series("c")];
        let bump = |v: &mut Value| {
            if let Value::Counter(c) = v {
                *c += 1;
            }
        };
        for kind in ["c", "b", "a", "c"] {
            record(&mut all, 7, &[("kind", kind)], bump, Value::Counter(0));
        }
        let counts: Vec<(String, u64)> = all
            .iter()
            .map(|s| match &s.value {
                Value::Counter(c) => (s.labels[0].1.clone(), *c),
                _ => panic!("{:?}", s.value),
            })
            .collect();
        // In the order they were added: a and c, then b after the run.
        assert_eq!(counts, [("a".into(), 1), ("c".into(), 2), ("b".into(), 1)]);
    }

    #[test]
    fn threads_recording_at_once_count_every_record() {
        const KINDS: [&str; 4] = ["a", "b", "c", "d"];
        std::thread::scope(|s| {
            for thread in 0..8 {
                s.spawn(move || {
                    for i in 0..10_000 {
                        inc(
                            "kronik_turns_total",
                            &[("kind", KINDS[thread % 4]), ("outcome", "ok")],
                        );
                        if thread % 2 == 0 {
                            let direction = if i % 2 == 0 { "in" } else { "out" };
                            add(
                                "kronik_connection_frames_total",
                                &[("direction", direction)],
                                1,
                            );
                        }
                    }
                });
            }
        });
        let count = |name: &'static str, label: (&'static str, &str)| {
            snapshot()
                .iter()
                .find(|s| {
                    s.def.name == name && s.labels.iter().any(|l| l.0 == label.0 && l.1 == label.1)
                })
                .map_or(0, |s| match &s.value {
                    SampleValue::Counter(c) => *c,
                    _ => 0,
                })
        };
        for kind in KINDS {
            assert_eq!(
                count("kronik_turns_total", ("kind", kind)),
                20_000,
                "{kind}"
            );
        }
        assert_eq!(
            count("kronik_connection_frames_total", ("direction", "in")),
            20_000
        );
        assert_eq!(
            count("kronik_connection_frames_total", ("direction", "out")),
            20_000
        );
    }
}
