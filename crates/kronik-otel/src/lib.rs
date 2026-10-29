//! OpenTelemetry export (M28, docs/design/m28-otel.md).
//!
//! [`otlp`] holds the OTLP message types, generated from the vendored
//! `proto/opentelemetry/` files (ADR 0081). [`spans`] maps committed turn
//! records to OTLP spans as pure functions of the record (ADR 0080), with
//! only what may leave the node (ADR 0082). [`audit`] maps audited records
//! to `kronik.audit/v1` lines (ADR 0083).
//!
//! The exporters follow the committed log ([`follow`]) from a durable
//! cursor ([`cursor`]), as `env.spawn` tasks of `kronik serve`, off the turn
//! path.

pub mod audit;
pub mod cursor;
pub mod follow;
pub mod http;
pub mod keys;
pub mod metrics;
pub mod sink;
pub mod spans;
pub mod traces;

/// The OTLP 1.x messages (opentelemetry-proto v1.7.0). The module tree
/// mirrors the proto packages under `opentelemetry.proto`, which the
/// generated code's relative paths rely on.
#[allow(clippy::all, missing_docs, rustdoc::all)]
pub mod otlp {
    pub mod common {
        pub mod v1 {
            include!(concat!(
                env!("OUT_DIR"),
                "/opentelemetry.proto.common.v1.rs"
            ));
        }
    }
    pub mod resource {
        pub mod v1 {
            include!(concat!(
                env!("OUT_DIR"),
                "/opentelemetry.proto.resource.v1.rs"
            ));
        }
    }
    pub mod trace {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.trace.v1.rs"));
        }
    }
    pub mod metrics {
        pub mod v1 {
            include!(concat!(
                env!("OUT_DIR"),
                "/opentelemetry.proto.metrics.v1.rs"
            ));
        }
    }
    pub mod collector {
        pub mod trace {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.collector.trace.v1.rs"
                ));
            }
        }
        pub mod metrics {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.collector.metrics.v1.rs"
                ));
            }
        }
    }
}
