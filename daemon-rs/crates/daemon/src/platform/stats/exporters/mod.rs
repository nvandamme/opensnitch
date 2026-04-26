#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-serve-protobuf"
))]
pub mod http_serve;

#[cfg(any(
    feature = "metrics-http-serve-text",
    feature = "metrics-http-push-text"
))]
pub mod encoder_prometheus_text;

#[cfg(any(
    feature = "metrics-http-serve-openmetrics",
    feature = "metrics-http-push-openmetrics"
))]
pub mod encoder_prometheus_openmetrics;

#[cfg(any(
    feature = "metrics-http-serve-protobuf",
    feature = "metrics-http-push-protobuf"
))]
pub mod encoder_prometheus_protobuf;

#[cfg(any(
    feature = "metrics-http-push-text",
    feature = "metrics-http-push-protobuf",
    feature = "metrics-http-push-openmetrics"
))]
pub mod http_push;

#[cfg(feature = "metrics-http-push-influxdb")]
pub mod http_push_influxdb;

#[cfg(feature = "metrics-http-push-influxdb")]
pub mod encoder_influxdb;

#[cfg(feature = "metrics-syslog")]
pub mod syslog_push;

#[cfg(feature = "metrics-syslog")]
pub mod encoder_syslog;

pub mod multi;
