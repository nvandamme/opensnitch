//! Wire-format model for the Prometheus `io.prometheus.client` protobuf schema.
//!
//! Provides inline prost-derived types that match the canonical
//! `prometheus/client_model` proto2 definition, without requiring a hard
//! dependency on the `prometheus-client` crate.
//!
//! Used by:
//! - `platform/adapters/stats_exporters/http_push` — push-gateway proto push body
//!
//! Feature-gated: compiled when `metrics-http-serve-protobuf` or
//! `metrics-http-push-protobuf` is enabled
//! (prost is an optional dep).

/// A name/value label pair.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LabelPair {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

/// A gauge sample value.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Gauge {
    #[prost(double, optional, tag = "1")]
    pub value: Option<f64>,
}

/// A counter sample value.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Counter {
    #[prost(double, optional, tag = "1")]
    pub value: Option<f64>,
}

/// A single metric sample (labels + one value type).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Metric {
    #[prost(message, repeated, tag = "1")]
    pub label: Vec<LabelPair>,
    #[prost(message, optional, tag = "2")]
    pub gauge: Option<Gauge>,
    #[prost(message, optional, tag = "3")]
    pub counter: Option<Counter>,
    #[prost(int64, optional, tag = "7")]
    pub timestamp_ms: Option<i64>,
}

/// A metric family (one series of same-named metrics).
#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricFamily {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub help: Option<String>,
    /// Serialised as an `i32`; set with `MetricType as i32`.
    #[prost(enumeration = "MetricType", optional, tag = "3")]
    pub r#type: Option<i32>,
    #[prost(message, repeated, tag = "4")]
    pub metric: Vec<Metric>,
}

/// Metric type discriminant matching the canonical prometheus proto enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum MetricType {
    Counter = 0,
    Gauge = 1,
    Summary = 2,
    Untyped = 3,
    Histogram = 4,
}
