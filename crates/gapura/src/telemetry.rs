//! Prometheus metrics, request/trace identifiers, and log setup.

use std::io::Write;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    HistogramVec, IntCounter, IntCounterVec, IntGauge,
};
use rand::RngCore;
use serde::Serialize;

/// All metrics live in the default Prometheus registry; `/metrics` gathers it.
pub struct Metrics {
    /// labels: route (`ns/name` or `-`), code
    pub requests_total: IntCounterVec,
    /// labels: route
    pub request_duration_seconds: HistogramVec,
    /// labels: cluster, kind (`connect`, `timeout`, `read`, `other`)
    pub upstream_errors_total: IntCounterVec,
    /// labels: result (`success`, `failure`)
    pub config_reloads_total: IntCounterVec,
    pub config_last_reload_timestamp_seconds: IntGauge,
    /// labels: secret (`ns/name`)
    pub tls_cert_parse_errors_total: IntCounterVec,
    /// labels: port
    pub tls_sni_misses_total: IntCounterVec,
    pub handler_panics_total: IntCounter,
    /// labels: kind
    #[expect(dead_code, reason = "incremented by the Kubernetes source (Task 10)")]
    pub watch_disconnects_total: IntCounterVec,
    /// labels: result (`success`, `failure`)
    pub status_writes_total: IntCounterVec,
    /// 1 while this replica holds the leader Lease.
    #[expect(dead_code, reason = "set by the leader loop (Task 9)")]
    pub leader: IntGauge,
}

pub static METRICS: LazyLock<Metrics> = LazyLock::new(|| Metrics {
    requests_total: register_int_counter_vec!(
        "gapura_requests_total",
        "Requests by route and status code",
        &["route", "code"]
    )
    .expect("metric registered once"),
    request_duration_seconds: register_histogram_vec!(
        "gapura_request_duration_seconds",
        "Request duration in seconds by route",
        &["route"],
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("metric registered once"),
    upstream_errors_total: register_int_counter_vec!(
        "gapura_upstream_errors_total",
        "Upstream errors by cluster and kind",
        &["cluster", "kind"]
    )
    .expect("metric registered once"),
    config_reloads_total: register_int_counter_vec!(
        "gapura_config_reloads_total",
        "Config reloads by result",
        &["result"]
    )
    .expect("metric registered once"),
    config_last_reload_timestamp_seconds: register_int_gauge!(
        "gapura_config_last_reload_timestamp_seconds",
        "Unix time of the last successful reload"
    )
    .expect("metric registered once"),
    tls_cert_parse_errors_total: register_int_counter_vec!(
        "gapura_tls_cert_parse_errors_total",
        "TLS secrets that could not be parsed",
        &["secret"]
    )
    .expect("metric registered once"),
    tls_sni_misses_total: register_int_counter_vec!(
        "gapura_tls_sni_misses_total",
        "TLS handshakes with no matching certificate",
        &["port"]
    )
    .expect("metric registered once"),
    handler_panics_total: register_int_counter!(
        "gapura_handler_panics_total",
        "Panics caught in request handling"
    )
    .expect("metric registered once"),
    watch_disconnects_total: register_int_counter_vec!(
        "gapura_watch_disconnects_total",
        "Watch streams that failed and were restarted",
        &["kind"]
    )
    .expect("metric registered once"),
    status_writes_total: register_int_counter_vec!(
        "gapura_status_writes_total",
        "Status patches by result",
        &["result"]
    )
    .expect("metric registered once"),
    leader: register_int_gauge!(
        "gapura_leader",
        "1 while this replica holds the leader Lease"
    )
    .expect("metric registered once"),
});

/// Unix time in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix time in milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 lowercase hex characters, 128 random bits.
pub fn request_id() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    hex(&buf)
}

/// Keep a valid incoming W3C `traceparent` (version 00), otherwise start a new sampled trace.
pub fn traceparent(existing: Option<&str>) -> String {
    if let Some(tp) = existing {
        if is_valid_traceparent(tp) {
            return tp.to_string();
        }
    }
    let mut trace = [0u8; 16];
    let mut span = [0u8; 8];
    rand::rng().fill_bytes(&mut trace);
    rand::rng().fill_bytes(&mut span);
    format!("00-{}-{}-01", hex(&trace), hex(&span))
}

fn is_valid_traceparent(tp: &str) -> bool {
    let parts: Vec<&str> = tp.split('-').collect();
    let all_hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit());
    parts.len() == 4
        && parts[0] == "00"
        && parts[1].len() == 32
        && all_hex(parts[1])
        && parts[1] != "00000000000000000000000000000000"
        && parts[2].len() == 16
        && all_hex(parts[2])
        && parts[2] != "0000000000000000"
        && parts[3].len() == 2
        && all_hex(parts[3])
}

/// The 32-hex trace id inside a traceparent.
pub fn trace_id_of(traceparent: &str) -> &str {
    traceparent.split('-').nth(1).unwrap_or("")
}

/// One access log line. Written as JSON to stdout; app logs go to stderr.
#[derive(Debug, Serialize)]
pub struct AccessLog<'a> {
    pub ts_ms: u64,
    pub request_id: &'a str,
    pub trace_id: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes: usize,
    pub duration_ms: u64,
    pub listener: &'a str,
    pub route: &'a str,
    pub upstream: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub error: Option<String>,
}

pub fn write_access_log(entry: &AccessLog<'_>) {
    if let Ok(line) = serde_json::to_string(entry) {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        // A closed stdout must never take the gateway down.
        let _ = writeln!(lock, "{line}");
    }
}

/// App logs: JSON lines on stderr, filtered by `RUST_LOG`-style directives.
pub fn init_logging(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Count panics in request handling; Pingora keeps the process alive, we keep the number.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        METRICS.handler_panics_total.inc();
        default(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_32_hex() {
        let id = request_id();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(id, request_id());
    }

    #[test]
    fn traceparent_is_kept_when_valid_and_replaced_otherwise() {
        let valid = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(traceparent(Some(valid)), valid);
        assert_eq!(trace_id_of(valid), "0af7651916cd43dd8448eb211c80319c");
        for bad in [
            "",
            "garbage",
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
        ] {
            let tp = traceparent(Some(bad));
            assert!(is_valid_traceparent(&tp), "{tp}");
            assert!(tp.ends_with("-01"));
        }
        assert!(is_valid_traceparent(&traceparent(None)));
    }

    #[test]
    fn access_log_serializes_expected_keys() {
        let entry = AccessLog {
            ts_ms: 1,
            request_id: "r",
            trace_id: "t",
            method: "GET",
            host: "h",
            path: "/",
            status: 200,
            bytes: 3,
            duration_ms: 4,
            listener: "infra/main/http",
            route: "apps/echo",
            upstream: Some("10.0.0.1:8080"),
            client_ip: None,
            user_agent: None,
            error: None,
        };
        let v: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(v["route"], "apps/echo");
        assert!(v["client_ip"].is_null());
    }

    #[test]
    fn metrics_register_once() {
        METRICS
            .requests_total
            .with_label_values(&["apps/echo", "200"])
            .inc();
        assert!(
            METRICS
                .requests_total
                .with_label_values(&["apps/echo", "200"])
                .get()
                >= 1
        );
    }
}
