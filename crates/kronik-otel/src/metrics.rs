//! Metrics over OTLP (m28-otel §3.7): every `[otel] metrics_interval`, the
//! `kronik-metrics` registry as one `ExportMetricsServiceRequest` to
//! `<endpoint>/v1/metrics`, cumulative since the daemon's start. Each push
//! replaces the last, so a failed one is only logged.

use std::time::Duration;

use kronik_core::env::Env;
use kronik_metrics::{BUCKETS, Sample, SampleValue, Type};
use prost::Message as _;

use crate::follow::Delivery;
use crate::otlp::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use crate::otlp::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use crate::otlp::metrics::v1::{
    AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
    ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
};
use crate::otlp::resource::v1::Resource as OtlpResource;
use crate::spans::Resource;

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
    }
}

/// The samples as OTLP metrics: counters as monotonic cumulative sums,
/// gauges as gauges, histograms as cumulative explicit-bound histograms.
/// One metric per catalog entry, one data point per label set.
pub fn request(
    resource: &Resource,
    samples: &[Sample],
    start_unix_nano: u64,
    now_unix_nano: u64,
) -> ExportMetricsServiceRequest {
    let mut metrics: Vec<Metric> = Vec::new();
    for s in samples {
        if metrics.last().is_none_or(|m| m.name != s.def.name) {
            let cumulative = AggregationTemporality::Cumulative as i32;
            metrics.push(Metric {
                name: s.def.name.into(),
                description: s.def.help.into(),
                unit: if s.def.kind == Type::Histogram {
                    "s".into()
                } else {
                    String::new()
                },
                data: Some(match s.def.kind {
                    Type::Counter => metric::Data::Sum(Sum {
                        data_points: Vec::new(),
                        aggregation_temporality: cumulative,
                        is_monotonic: true,
                    }),
                    Type::Gauge => metric::Data::Gauge(Gauge::default()),
                    Type::Histogram => metric::Data::Histogram(Histogram {
                        data_points: Vec::new(),
                        aggregation_temporality: cumulative,
                    }),
                }),
                ..Default::default()
            });
        }
        let attributes: Vec<KeyValue> = s.labels.iter().map(|(k, v)| kv(k, v)).collect();
        let number = |value| NumberDataPoint {
            attributes: attributes.clone(),
            start_time_unix_nano: start_unix_nano,
            time_unix_nano: now_unix_nano,
            value: Some(value),
            ..Default::default()
        };
        let Some(data) = metrics.last_mut().and_then(|m| m.data.as_mut()) else {
            continue;
        };
        match (data, &s.value) {
            (metric::Data::Sum(sum), SampleValue::Counter(c)) => sum.data_points.push(number(
                number_data_point::Value::AsInt(i64::try_from(*c).unwrap_or(i64::MAX)),
            )),
            (metric::Data::Gauge(g), SampleValue::Gauge(v)) => g
                .data_points
                .push(number(number_data_point::Value::AsDouble(*v))),
            (
                metric::Data::Histogram(h),
                SampleValue::Histogram {
                    buckets,
                    sum,
                    count,
                },
            ) => {
                // The registry's buckets are cumulative (`le`); OTLP's
                // count each bucket on its own, with one past the last bound.
                let mut counts = Vec::with_capacity(BUCKETS.len() + 1);
                let mut below = 0;
                for &b in buckets {
                    counts.push(b.saturating_sub(below));
                    below = b;
                }
                counts.push(count.saturating_sub(below));
                h.data_points.push(HistogramDataPoint {
                    attributes,
                    start_time_unix_nano: start_unix_nano,
                    time_unix_nano: now_unix_nano,
                    count: *count,
                    sum: Some(*sum),
                    bucket_counts: counts,
                    explicit_bounds: BUCKETS.to_vec(),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(OtlpResource {
                attributes: vec![
                    kv("service.name", resource.service_name),
                    kv("service.version", resource.service_version),
                    kv("kronik.node", resource.node),
                    kv("kronik.engine", resource.engine),
                ],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: "kronik".into(),
                    version: resource.service_version.into(),
                    ..Default::default()
                }),
                metrics,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

/// Pushes the registry every `interval`, forever. `before` sets the
/// scrape-time gauges first, as the admin endpoint does.
pub async fn push_loop(
    env: Env,
    endpoint: String,
    headers: Vec<(String, String)>,
    service_name: String,
    branch: String,
    interval: Duration,
    before: impl Fn() + Send,
) {
    let start = env.clock.wall_ms().saturating_mul(1_000_000);
    let url = format!("{endpoint}/v1/metrics");
    loop {
        env.clock.sleep(interval).await;
        before();
        let resource = Resource {
            service_name: &service_name,
            service_version: kronik_runtime::KRONIK_VERSION,
            node: &branch,
            engine: kronik_runtime::ENGINE_VERSION,
        };
        let now = env.clock.wall_ms().saturating_mul(1_000_000);
        let body = request(&resource, &kronik_metrics::snapshot(), start, now).encode_to_vec();
        let resp = crate::http::post(
            &env,
            url.clone(),
            headers.clone(),
            "application/x-protobuf",
            body,
        )
        .await;
        let delivery = crate::traces::otlp_delivery(resp, |b| {
            ExportMetricsServiceResponse::decode(b)
                .ok()
                .and_then(|r| r.partial_success)
                .map(|p| p.rejected_data_points)
        });
        if let Delivery::Dropped { code } | Delivery::Retry { code, .. } = delivery {
            tracing::warn!(
                code,
                "otel: pushing metrics failed; the next push replaces it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_gauges_and_histograms_map_to_otlp() {
        kronik_metrics::inc(
            "kronik_turns_total",
            &[("kind", "counter"), ("outcome", "committed")],
        );
        kronik_metrics::set("kronik_applied_lsn", &[], 12.0);
        kronik_metrics::observe(
            "kronik_log_fsync_duration_seconds",
            &[],
            Duration::from_millis(3),
        );
        kronik_metrics::observe(
            "kronik_log_fsync_duration_seconds",
            &[],
            Duration::from_secs(60),
        );
        let resource = Resource {
            service_name: "kronik",
            service_version: "v",
            node: "main",
            engine: "e",
        };
        let req = request(&resource, &kronik_metrics::snapshot(), 1, 2);
        let metrics = &req.resource_metrics[0].scope_metrics[0].metrics;
        let find = |n: &str| metrics.iter().find(|m| m.name == n).unwrap();
        let Some(metric::Data::Sum(sum)) = &find("kronik_turns_total").data else {
            panic!()
        };
        assert!(sum.is_monotonic);
        assert_eq!(
            sum.aggregation_temporality,
            AggregationTemporality::Cumulative as i32
        );
        let p = &sum.data_points[0];
        assert_eq!((p.start_time_unix_nano, p.time_unix_nano), (1, 2));
        assert_eq!(p.value, Some(number_data_point::Value::AsInt(1)));
        assert_eq!(p.attributes[0].key, "kind");
        let Some(metric::Data::Gauge(g)) = &find("kronik_applied_lsn").data else {
            panic!()
        };
        assert_eq!(
            g.data_points[0].value,
            Some(number_data_point::Value::AsDouble(12.0))
        );
        let Some(metric::Data::Histogram(h)) = &find("kronik_log_fsync_duration_seconds").data
        else {
            panic!()
        };
        let p = &h.data_points[0];
        assert_eq!(p.count, 2);
        assert_eq!(p.explicit_bounds.len() + 1, p.bucket_counts.len());
        // 3 ms falls in (2.5 ms, 5 ms]; 60 s past the last bound.
        assert_eq!(p.bucket_counts[3], 1);
        assert_eq!(*p.bucket_counts.last().unwrap(), 1);
        assert_eq!(p.bucket_counts.iter().sum::<u64>(), 2);
    }
}
