//! Process-wide metrics, exported at `/metrics` in the Prometheus text
//! format (M6) and pushed over OTLP (M28, [`snapshot`]). [`METRICS`] is the
//! catalog: a name, its help text and its type. Recording never reads a
//! clock: daemon code measures durations with `Env::clock` and passes them
//! in (ADR 0004). Only the exporters read the values back, so they cannot
//! change behavior, in production or in the simulator.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{LazyLock, Mutex};
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
];

/// Histogram bucket bounds, in seconds.
pub const BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
}

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

static REGISTRY: LazyLock<Mutex<BTreeMap<Key, Value>>> = LazyLock::new(Mutex::default);

fn key(name: &'static str, labels: &[(&'static str, &str)]) -> Key {
    let mut labels: Vec<(&'static str, String)> =
        labels.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
    labels.sort();
    Key { name, labels }
}

fn update(
    name: &'static str,
    labels: &[(&'static str, &str)],
    f: impl FnOnce(&mut Value),
    new: Value,
) {
    if let Ok(mut registry) = REGISTRY.lock() {
        f(registry.entry(key(name, labels)).or_insert(new));
    }
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
/// `now` (a monotonic clock, such as `Env::clock`).
pub struct Timer<F: Fn() -> Duration> {
    name: &'static str,
    label: (&'static str, String),
    started: Duration,
    now: F,
}

/// A [`Timer`] for the histogram `name` with one label.
pub fn timer<F: Fn() -> Duration>(
    name: &'static str,
    label: (&'static str, &str),
    now: F,
) -> Timer<F> {
    Timer {
        name,
        label: (label.0, label.1.to_owned()),
        started: now(),
        now,
    }
}

impl<F: Fn() -> Duration> Drop for Timer<F> {
    fn drop(&mut self) {
        let elapsed = (self.now)().saturating_sub(self.started);
        observe(self.name, &[(self.label.0, &self.label.1)], elapsed);
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

/// Every recorded series of the catalog, in the Prometheus text format
/// (version 0.0.4), in catalog order and then by labels.
pub fn render() -> String {
    let registry = match REGISTRY.lock() {
        Ok(registry) => registry.clone(),
        Err(_) => return String::new(),
    };
    let mut out = String::new();
    for def in METRICS {
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
        for (key, value) in registry.iter().filter(|(k, _)| k.name == def.name) {
            match value {
                Value::Counter(c) => {
                    let _ = writeln!(out, "{}{} {c}", def.name, labels(&key.labels, None));
                }
                Value::Gauge(g) => {
                    let _ = writeln!(out, "{}{} {g}", def.name, labels(&key.labels, None));
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
                            labels(&key.labels, Some(("le", &le)))
                        );
                    }
                    let _ = writeln!(
                        out,
                        "{}_bucket{} {count}",
                        def.name,
                        labels(&key.labels, Some(("le", "+Inf")))
                    );
                    let _ = writeln!(out, "{}_sum{} {sum}", def.name, labels(&key.labels, None));
                    let _ = writeln!(
                        out,
                        "{}_count{} {count}",
                        def.name,
                        labels(&key.labels, None)
                    );
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
    let registry = match REGISTRY.lock() {
        Ok(registry) => registry.clone(),
        Err(_) => return Vec::new(),
    };
    METRICS
        .iter()
        .flat_map(|def| {
            registry
                .iter()
                .filter(move |(k, _)| k.name == def.name)
                .map(move |(k, v)| Sample {
                    def,
                    labels: k.labels.clone(),
                    value: match v {
                        Value::Counter(c) => SampleValue::Counter(*c),
                        Value::Gauge(g) => SampleValue::Gauge(*g),
                        Value::Histogram {
                            buckets,
                            sum,
                            count,
                        } => SampleValue::Histogram {
                            buckets: *buckets,
                            sum: *sum,
                            count: *count,
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
}
